//! Global Page Allocator

use core::cmp::min;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::fs::disk::Swap;
use crate::mem::{utils::*, PTEFlags};
use crate::sbi::interrupt;
use crate::sync::{Intr, Lazy, Mutex};
use crate::thread::{current, Thread};
use crate::userproc::SwapTableEntry;

// BuddyAllocator allocates at most `1<<MAX_ORDER` pages at a time
const MAX_ORDER: usize = 8;
// How many pages are there in the user memory pool
pub(super) const USER_POOL_LIMIT: usize = 256;

/// Buddy Allocator. It allocates and deallocates memory page-wise.
#[derive(Debug)]
struct BuddyAllocator {
    /// The i-th free list is in charge of memory chunks of 2^i pages
    free_lists: [InMemList; MAX_ORDER + 1],
    /// How many memory does the buddy allocator control
    total: usize,
    /// The number of pages allocated
    allocated: usize,
}

impl BuddyAllocator {
    /// This struct can not be moved due to self reference.
    /// So, construct it and then call `init`.
    const fn empty() -> Self {
        Self {
            free_lists: [InMemList::new(); MAX_ORDER + 1],
            total: 0,
            allocated: 0,
        }
    }

    /// Take the memory segmant from `start` to `end` into page allocator's record
    unsafe fn insert_range(&mut self, start: usize, end: usize) {
        let start = round_up(start, PG_SIZE);
        let end = round_down(end, PG_SIZE);
        self.total += end - start;

        let mut current_start: usize = start;
        while current_start < end {
            // find the biggest alignment of `current_start`
            let size = min(
                1 << current_start.trailing_zeros(),
                prev_power_of_two(end - current_start),
            );
            let order = size.trailing_zeros() as usize - PG_SHIFT;
            // The order we found cannot exceed the preset maximun order
            let order = min(order, MAX_ORDER);
            self.free_lists[order].push(current_start as *mut usize);
            current_start += (1 << order) * PG_SIZE;
        }
    }

    /// Allocate n pages and returns the virtual address.
    unsafe fn alloc(&mut self, n: usize) -> *mut u8 {
        assert!(n <= 1 << MAX_ORDER, "request is too large");

        let order = n.next_power_of_two().trailing_zeros() as usize;
        for i in order..self.free_lists.len() {
            // Find the first non-empty list
            if !self.free_lists[i].is_empty() {
                // Split buffers (from large to small groups)
                for j in (order..i).rev() {
                    // Try to find a large block of group j+1 and then
                    // split it into two blocks of group j
                    if let Some(block) = self.free_lists[j + 1].pop() {
                        let half = (block as usize + (1 << j) * PG_SIZE) as *mut usize;
                        self.free_lists[j].push(half);
                        self.free_lists[j].push(block);
                    }
                }
                self.allocated += 1 << order;
                return self.free_lists[order].pop().unwrap().cast();
            }
        }

        unreachable!("memory is exhausted");
    }

    /// Deallocate a chunk of pages
    unsafe fn dealloc(&mut self, ptr: *mut u8, n: usize) {
        let order = n.next_power_of_two().trailing_zeros() as usize;
        self.free_lists[order].push(ptr.cast());

        // Merge free lists
        let mut curr_ptr = ptr as usize;
        let mut curr_order = order;

        while curr_order < MAX_ORDER {
            // Find the buddy block of the current block
            let buddy = curr_ptr ^ (1 << (curr_order + PG_SHIFT));
            // Try to find and merge blocks
            if let Some(blk) = self.free_lists[curr_order]
                .iter_mut()
                .find(|blk| blk.value() as usize == buddy)
            {
                blk.pop();
                // Merge two blocks into a bigger one
                self.free_lists[curr_order].pop();
                curr_ptr = min(curr_ptr, buddy);
                self.free_lists[curr_order + 1].push(curr_ptr as *mut _);
                // Attempt to form a even bigger block in the next iteration
                curr_order += 1;
            } else {
                break;
            }
        }

        self.allocated -= 1 << order;
    }
}

/// Wraps the buddy allocator
pub struct Palloc(Lazy<Mutex<BuddyAllocator, Intr>>);

unsafe impl Sync for Palloc {}

impl Palloc {
    /// Initialize the page-based allocator
    pub unsafe fn init(start: usize, end: usize) {
        Self::instance().lock().insert_range(start, end);
    }

    /// Allocate n pages of a consecutive memory segment
    pub unsafe fn alloc(n: usize) -> *mut u8 {
        Self::instance().lock().alloc(n)
    }

    /// Free n pages of memory starting at `ptr`
    pub unsafe fn dealloc(ptr: *mut u8, n: usize) {
        Self::instance().lock().dealloc(ptr, n)
    }

    fn instance() -> &'static Mutex<BuddyAllocator, Intr> {
        static PALLOC: Palloc = Palloc(Lazy::new(|| Mutex::new(BuddyAllocator::empty())));

        &PALLOC.0
    }
}

#[derive(Clone)]
struct PhysAddrEntry {
    va: usize,
    thread: Arc<Thread>,
}

struct PhysAddrTable(Lazy<Mutex<Vec<Option<PhysAddrEntry>>>>);

static TABLE: PhysAddrTable = PhysAddrTable(Lazy::new(|| Mutex::new(vec![None; USER_POOL_LIMIT])));

impl PhysAddrTable {
    fn instance() -> &'static PhysAddrTable {
        &TABLE
    }
}

pub struct UserPool(Lazy<Mutex<BuddyAllocator, Intr>>);

unsafe impl Sync for UserPool {}

const PHYS_START: usize = 532736;

static PAGE_POINTER: Lazy<Mutex<u8>> = Lazy::new(|| Mutex::new(0));

impl UserPool {
    /// Allocate 1 page
    pub unsafe fn alloc_page(va: usize, flags: PTEFlags, buf: &[u8; PG_SIZE]) {
        let old = interrupt::set(false);
        if Self::instance().lock().allocated == USER_POOL_LIMIT {
            let mut pat = PhysAddrTable::instance().0.lock();
            let entry = pat[*PAGE_POINTER.lock() as usize].as_mut().unwrap();
            kprintln!("name: {}", entry.thread.name());
            let old_va = entry.va;
            let old_pa = entry
                .thread
                .pagetable
                .as_ref()
                .unwrap()
                .lock()
                .get_pte(entry.va)
                .unwrap()
                .pa()
                .value();

            kprintln!("get old va/pa.");

            // swap condition: 1. not in mmap(writeback) 2. dirty or had been in swap space
            let mut wb = false;
            for mmap in entry
                .thread
                .userproc
                .as_ref()
                .unwrap()
                .mmap_table
                .lock()
                .values()
            {
                kprintln!("alloc check wb: {} {}", mmap.addr, mmap.length);
                if mmap.writeback && old_va >= mmap.addr && old_va < mmap.addr + mmap.length {
                    wb = true;
                    break;
                }
            }

            kprintln!("checked wb.");

            let dirty = entry
                .thread
                .pagetable
                .as_ref()
                .unwrap()
                .lock()
                .get_pte(old_va)
                .unwrap()
                .is_dirty();

            let had_been = entry
                .thread
                .userproc
                .as_ref()
                .unwrap()
                .swap_table
                .lock()
                .contains_key(&old_va);

            if !wb && (dirty || had_been) {
                // Add swap entry or change swap entry
                let mut flags = PTEFlags::V;
                if entry
                    .thread
                    .pagetable
                    .as_ref()
                    .unwrap()
                    .lock()
                    .get_pte(old_va)
                    .unwrap()
                    .is_readable()
                {
                    flags |= PTEFlags::R;
                }
                if entry
                    .thread
                    .pagetable
                    .as_ref()
                    .unwrap()
                    .lock()
                    .get_pte(old_va)
                    .unwrap()
                    .is_writable()
                {
                    flags |= PTEFlags::W;
                }
                if entry
                    .thread
                    .pagetable
                    .as_ref()
                    .unwrap()
                    .lock()
                    .get_pte(old_va)
                    .unwrap()
                    .is_executable()
                {
                    flags |= PTEFlags::X;
                }
                if entry
                    .thread
                    .pagetable
                    .as_ref()
                    .unwrap()
                    .lock()
                    .get_pte(old_va)
                    .unwrap()
                    .is_user()
                {
                    flags |= PTEFlags::U;
                }
                let mut st = entry.thread.userproc.as_ref().unwrap().swap_table.lock();
                let swap_entry = st.entry(old_va).or_insert(SwapTableEntry {
                    flags,
                    page: 0,
                    in_swap: false,
                });

                let page =
                    Swap::write(&*(PhysAddr::from_pa(old_pa).into_va() as *const [u8; PG_SIZE]));
                swap_entry.page = page;
                swap_entry.in_swap = true;
            }

            entry
                .thread
                .pagetable
                .as_ref()
                .unwrap()
                .lock()
                .get_mut_pte(old_va)
                .unwrap()
                .set_invalid();

            // Move buf to the freed physical page
            let va_ptr = PhysAddr::from_pa(old_pa).into_va() as *mut [u8; PG_SIZE];
            unsafe {
                (*va_ptr).copy_from_slice(buf);
            }

            current().pagetable.as_ref().unwrap().lock().map(
                PhysAddr::from_pa(old_pa),
                va,
                PG_SIZE,
                flags,
            );

            // Edit PhysAddrTable

            pat[*PAGE_POINTER.lock() as usize] = Some(PhysAddrEntry {
                va,
                thread: current(),
            });
            *PAGE_POINTER.lock() += 1;
        } else {
            let kva = Self::instance().lock().alloc(1);
            let pa = PhysAddr::from(kva);
            // Move buf to the allocated physical page
            let va_ptr = kva as *mut [u8; PG_SIZE];
            unsafe {
                (*va_ptr).copy_from_slice(buf);
            }
            current()
                .pagetable
                .as_ref()
                .unwrap()
                .lock()
                .map(pa, va, PG_SIZE, flags);

            // Edit PhysAddrTable
            kprintln!("{}", pa.value());
            PhysAddrTable::instance().0.lock()[pa.value() / PG_SIZE - PHYS_START] =
                Some(PhysAddrEntry {
                    va,
                    thread: current(),
                });
        }
        interrupt::set(old);
    }

    /// Free n pages of memory starting at `ptr`
    pub unsafe fn dealloc_pages(ptr: *mut u8, n: usize) {
        Self::instance().lock().dealloc(ptr, n);
        for i in 0..n {
            let pa = PhysAddr::from(ptr.add(i * PG_SIZE));
            PhysAddrTable::instance().0.lock()[pa.value() / PG_SIZE - PHYS_START] = None;
        }
    }

    /// Initialize the page-based allocator
    pub unsafe fn init(start: usize, end: usize) {
        kprintln!("start: {}, end: {}", start, end);
        Self::instance().lock().insert_range(start, end);
    }

    fn instance() -> &'static Mutex<BuddyAllocator, Intr> {
        static USERPOOL: UserPool = UserPool(Lazy::new(|| Mutex::new(BuddyAllocator::empty())));

        &USERPOOL.0
    }
}
