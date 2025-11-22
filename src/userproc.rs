//! User process.
//!

mod load;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::arch::asm;
use core::iter::zip;
use core::mem::{size_of, MaybeUninit};
use riscv::register::sstatus;

use crate::fs::disk::SwapBitmap;
use crate::fs::File;
use crate::io::{Seek, SeekFrom, Write};
use crate::mem::pagetable::KernelPgTable;
use crate::mem::{div_round_up, PTEFlags, PageAlign, PG_SIZE};
use crate::sbi::interrupt::set;
use crate::sync::Mutex;
use crate::sync::Semaphore;
use crate::thread::{self, current};
use crate::trap::{trap_exit_u, Frame};
use crate::userproc::load::init_user_stack;

pub static ZERO_PAGE: [u8; PG_SIZE] = [0u8; PG_SIZE];

pub static PT_SEMA: Semaphore = Semaphore::new(1);

pub struct MMapTableEntry {
    pub addr: usize,
    pub length: usize,
    pub pages: usize,
    pub fd: File,
    pub flags: PTEFlags,
    pub offset: usize,
    pub writeback: bool,
}

pub struct SwapTableEntry {
    pub flags: PTEFlags,
    pub page: usize,
    pub in_swap: bool,
}

pub struct UserProc {
    #[allow(dead_code)]
    bin: Mutex<File>,
    pub init_sp: usize,
    pub mmap_table: Mutex<BTreeMap<usize, MMapTableEntry>>,
    pub swap_table: Mutex<BTreeMap<usize, SwapTableEntry>>,
    status: Mutex<Option<isize>>,
    wait: Mutex<Option<(Arc<Semaphore>, Arc<Semaphore>)>>,
    pub fdlist: Mutex<Vec<Option<Mutex<File>>>>,
    pub exited: Mutex<bool>,
}

impl UserProc {
    pub fn new(file: File, init_sp: usize, mmap_table: BTreeMap<usize, MMapTableEntry>) -> Self {
        Self {
            bin: Mutex::new(file),
            init_sp,
            mmap_table: Mutex::new(mmap_table),
            swap_table: Mutex::new(BTreeMap::new()),
            status: Mutex::new(None),
            wait: Mutex::new(None),
            fdlist: Mutex::new(Vec::new()),
            exited: Mutex::new(false),
        }
    }
}

/// Map fd in memory addr.
pub fn add_mmap_entry(addr: usize, fd: File) -> Option<usize> {
    // kprintln!("add mmap at: {:#x}", addr);
    let length = fd.len().unwrap();
    if addr == 0
        || length == 0
        || !addr.is_aligned()
        || !current()
            .pagetable
            .as_ref()
            .unwrap()
            .lock()
            .check_available(addr, length)
    {
        return None;
    }
    // Check overlap between existing mappings
    for entry in current()
        .userproc
        .as_ref()
        .unwrap()
        .mmap_table
        .lock()
        .values()
    {
        let entry_start = entry.addr;
        let entry_end = entry.addr + entry.pages * PG_SIZE;
        let end = addr + length;
        if !(end <= entry_start || addr >= entry_end) {
            return None;
        }
    }
    let mut id = 0;
    while current()
        .userproc
        .as_ref()
        .unwrap()
        .mmap_table
        .lock()
        .contains_key(&id)
    {
        id += 1;
    }

    let entry = MMapTableEntry {
        addr,
        length,
        pages: div_round_up(length, PG_SIZE),
        fd,
        flags: PTEFlags::V | PTEFlags::R | PTEFlags::W | PTEFlags::U,
        offset: 0,
        writeback: true,
    };
    current()
        .userproc
        .as_ref()
        .unwrap()
        .mmap_table
        .lock()
        .insert(id, entry);
    Some(id)
}

pub fn remove_mmap_entry(id: usize) {
    let mut entry = current()
        .userproc
        .as_ref()
        .unwrap()
        .mmap_table
        .lock()
        .remove(&id)
        .unwrap();
    if !entry.writeback {
        return;
    }
    unsafe {
        let list = current()
            .pagetable
            .as_ref()
            .unwrap()
            .lock()
            .unmapping(&mut entry);
        for (addr, va, size) in list {
            // kprintln!("addr: {}, va: {}, size: {}", addr, va, size);
            let buf = va as *mut [u8; PG_SIZE];
            entry
                .fd
                .seek(SeekFrom::Start((entry.offset + addr - entry.addr) as usize))
                .unwrap();
            // kprintln!("Writing back mmap region: {}", (*buf)[0]);
            entry.fd.write(&((*buf)[..size])).unwrap();
            // kprintln!("Wrote back mmap region");
            // kprintln!("set invalid out");
        }
    }
}

pub fn remove_all_mmap_entries() {
    let entries: Vec<usize> = current()
        .userproc
        .as_ref()
        .unwrap()
        .mmap_table
        .lock()
        .keys()
        .cloned()
        .collect();
    for id in entries {
        remove_mmap_entry(id);
    }
}

/// Execute an object file with arguments.
///
/// ## Return
/// - `-1`: On error.
/// - `tid`: Tid of the newly spawned thread.
#[allow(unused_variables)]
pub fn execute(mut file: File, argv: Vec<String>) -> isize {
    #[cfg(feature = "debug")]
    kprintln!(
        "[PROCESS] Kernel thread {} prepare to execute a process with args {:?}",
        thread::current().name(),
        argv
    );

    // It only copies L2 pagetable. This approach allows the new thread
    // to access kernel code and data during syscall without the need to
    // switch pagetables.
    let mut pt = KernelPgTable::clone();

    let (exec_info, mmap_table) = match load::lazy_load_executable(&mut file, &mut pt) {
        Ok(x) => x,
        Err(_) => unsafe {
            pt.destroy();
            return -1;
        },
    };

    // Here the new process will be created.
    let userproc = UserProc::new(file, exec_info.init_sp, mmap_table);

    // Initialize frame, pass argument to user.
    let mut frame = unsafe { MaybeUninit::<Frame>::zeroed().assume_init() };
    frame.sepc = exec_info.entry_point;
    frame.x[2] = exec_info.init_sp;

    // TODO: (Lab2) Pass arguments to user program

    let mut str_size = 0;
    let mut arg_size = 2;
    for arg in argv.iter() {
        str_size += arg.len() + 1;
        arg_size += 1;
    }
    let align = size_of::<usize>();
    arg_size = arg_size * align + (str_size + align - 1) / align * align;
    if arg_size > PG_SIZE {
        kprintln!("Too many arguments!");
        unsafe {
            pt.destroy();
            return -1;
        }
    }

    let child = thread::Builder::new(move || start(argv, frame))
        .pagetable(pt)
        .userproc(userproc)
        .spawn();
    // kprintln!(
    //     "{} {}, {} {}",
    //     current().name(),
    //     current().id(),
    //     child.name(),
    //     child.id()
    // );
    let tid = child.id();
    current().child.lock().push(child);
    tid
}

/// Exits a process.
///
/// Panic if the current thread doesn't own a user process.
pub fn exit(_value: isize) -> ! {
    // TODO: Lab2.
    #[cfg(feature = "debug")]
    kprintln!("Into userproc::exit");
    set(false);
    assert!(
        current().userproc.is_some(),
        "Current thread doesn't own a user process."
    );

    current()
        .userproc
        .as_ref()
        .unwrap()
        .bin
        .lock()
        .allow_write();
    *current().userproc.as_ref().unwrap().status.lock() = Some(_value);

    // Wake waiting thread up.
    if let Some((psema, csema)) = current().userproc.as_ref().unwrap().wait.lock().as_ref() {
        #[cfg(feature = "debug")]
        kprintln!("exited!");
        psema.up();
        csema.down();
    } else {
        #[cfg(feature = "debug")]
        kprintln!(
            "no one is waiting. current thread {} {}",
            current().name(),
            current().id()
        );
    }
    #[cfg(feature = "debug")]
    kprintln!(
        "User thread {} {} exiting with value {}.",
        current().name(),
        current().id(),
        _value
    );
    // kprintln!("prod in");
    PT_SEMA.down();

    for entry in current()
        .userproc
        .as_ref()
        .unwrap()
        .swap_table
        .lock()
        .values()
    {
        // kprintln!("swapspace {:?} {} {}", current(), entry.page, entry.in_swap);
        if entry.in_swap {
            SwapBitmap::release(entry.page);
        }
    }
    remove_all_mmap_entries();
    if let Some(pt) = &current().pagetable {
        // kprintln!("{:?} remove pt", current());
        unsafe { pt.lock().destroy() };
    }
    PT_SEMA.up();
    // kprintln!("prod out");
    *current().userproc.as_ref().unwrap().exited.lock() = true;
    thread::exit();
}

/// Waits for a child thread, which must own a user process.
///
/// ## Return
/// - `Some(exit_value)`
/// - `None`: if tid was not created by the current thread.
pub fn wait(_tid: isize) -> Option<isize> {
    // TODO: Lab2.
    // kprintln!("start wait");

    let mut result = Some(-1);
    let mut index = None;
    for (thread, ind) in zip(current().child.lock().iter(), 0..) {
        if thread.id() == _tid {
            let old = set(false);
            #[cfg(feature = "debug")]
            kprintln!("Found child thread {} {}", thread.name(), _tid);
            // Find thread.
            assert!(
                thread.userproc.is_some(),
                "Child thread doesn't own a user process."
            );

            let lock = thread.userproc.as_ref().unwrap().status.lock();
            let status = lock.clone();
            #[cfg(feature = "debug")]
            kprintln!(
                "Checking status of child thread {} {}.",
                thread.name(),
                _tid
            );
            if let Some(val) = status {
                #[cfg(feature = "debug")]
                kprintln!("{:?}", lock.clone());
                #[cfg(feature = "debug")]
                kprint!("Child thread {} {} already exited.\n", thread.name(), _tid);
                result = Some(val);
                index = Some(ind);
                drop(lock);
                set(old);
                break;
            }
            #[cfg(feature = "debug")]
            kprintln!(
                "Child thread {} {} is still running. Waiting for exit.",
                thread.name(),
                _tid
            );

            // Wait for exit.
            let psema = Arc::new(Semaphore::new(0));
            let csema = Arc::new(Semaphore::new(0));
            *thread.userproc.as_ref().unwrap().wait.lock() =
                Some((Arc::clone(&psema), Arc::clone(&csema)));
            #[cfg(feature = "debug")]
            kprintln!(
                "Waiting for child thread {} {} to exit.",
                thread.name(),
                _tid
            );
            #[cfg(feature = "debug")]
            kprintln!("{:?}", lock.clone());
            drop(lock);
            set(old);
            psema.down();
            #[cfg(feature = "debug")]
            kprintln!("Child thread {} {} has exited.", thread.name(), _tid);
            assert!(
                thread.userproc.as_ref().unwrap().status.lock().is_some(),
                "Child thread doesn't exit properly."
            );
            result = Some(
                *thread
                    .userproc
                    .as_ref()
                    .unwrap()
                    .status
                    .lock()
                    .as_ref()
                    .unwrap(),
            );
            #[cfg(feature = "debug")]
            kprintln!("Releasing child thread {} {}", thread.name(), _tid);
            csema.up();
            index = Some(ind);
            break;
        }
    }
    if let Some(ind) = index {
        current().child.lock().remove(ind);
    }

    // kprintln!("Wait finish.");
    return result;
}

/// Initializes a user process in current thread.
///
/// This function won't return.
pub fn start(argv: Vec<String>, mut frame: Frame) -> ! {
    // Initialize user stack.
    // kprintln!("stack: {}", frame.x[2]);
    init_user_stack(frame.x[2]);

    let mut pnts = Vec::new();
    let mut user_sp = frame.x[2];

    for arg in argv {
        user_sp -= 1;
        unsafe {
            (user_sp as *mut u8).write(0);
        }
        for byte in arg.bytes().rev() {
            user_sp -= 1;
            unsafe {
                (user_sp as *mut u8).write(byte);
            }
        }
        pnts.push(user_sp);
    }
    let align = size_of::<usize>();
    user_sp -= user_sp % align;
    user_sp -= align;
    unsafe {
        (user_sp as *mut usize).write(0);
    }
    for ptr in pnts.iter().rev() {
        user_sp -= align;
        unsafe {
            (user_sp as *mut usize).write(*ptr);
        }
    }
    let argc = pnts.len();
    frame.x[2] = user_sp;
    frame.x[10] = argc;
    frame.x[11] = user_sp;

    unsafe { sstatus::set_spp(sstatus::SPP::User) };
    frame.sstatus = sstatus::read();

    // Set kernel stack pointer to intr frame and then jump to `trap_exit_u()`.
    let kernal_sp = (&frame as *const Frame) as usize;

    #[cfg(feature = "debug")]
    kprintln!("sp now: {:#x}", &kernal_sp as *const usize as usize);

    unsafe {
        asm!(
            "mv sp, t0",
            "jr t1",
            in("t0") kernal_sp,
            in("t1") trap_exit_u as *const u8
        );
    }

    unreachable!();
}
