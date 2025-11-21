use crate::io::SeekFrom;
use crate::mem::palloc::UserPool;
use crate::mem::userbuf::{
    __knrl_read_usr_byte_pc, __knrl_read_usr_exit, __knrl_write_usr_byte_pc, __knrl_write_usr_exit,
};
use crate::mem::{PTEFlags, PageAlign, PageTable, PhysAddr, MAX_USER_STACK, PG_SIZE};
use crate::thread::{self};
use crate::trap::Frame;
use crate::userproc::{self};
use crate::{OsError, Result};
use core::cmp::min;
use io::Read;
use io::Seek;

use riscv::register::scause::Exception::{self, *};
use riscv::register::sstatus::{self, SPP};

fn user_page_fault(frame: &mut Frame, addr: usize) -> Result<()> {
    if thread::current().userproc.is_none() {
        return Err(OsError::UserError);
    }
    let init_sp = thread::current().userproc.as_ref().unwrap().init_sp;
    if addr < init_sp && addr + MAX_USER_STACK >= init_sp && addr >= frame.x[2] {
        // Stack growth
        let va = unsafe { UserPool::alloc_pages(1) };
        let pa = PhysAddr::from(va);
        let entry_addr = PageAlign::floor(addr);
        let flags = PTEFlags::V | PTEFlags::R | PTEFlags::W | PTEFlags::U;

        thread::current()
            .pagetable
            .as_ref()
            .unwrap()
            .lock()
            .map(pa, entry_addr, PG_SIZE, flags);

        #[cfg(feature = "debug")]
        kprintln!(
            "[USERPROC] User Stack Grow: (k){:p} -> (u) {:#x}",
            stack_va,
            stack_page_begin
        );
    } else {
        for (_, mmap) in thread::current()
            .userproc
            .as_ref()
            .unwrap()
            .mmap_table
            .lock()
            .iter_mut()
        {
            kprintln!(
                "MMap region: addr={:#x}, length={:#x}, pages={:#x}",
                mmap.addr,
                mmap.length,
                mmap.pages
            );
            if addr >= mmap.addr && addr < mmap.addr + mmap.pages * PG_SIZE {
                // mmap region access
                let va = unsafe { UserPool::alloc_pages(1) };
                let pa = PhysAddr::from(va);
                let entry_addr = PageAlign::floor(addr);
                let flags = mmap.flags;
                thread::current()
                    .pagetable
                    .as_ref()
                    .unwrap()
                    .lock()
                    .map(pa, entry_addr, PG_SIZE, flags);

                unsafe {
                    let buf = va as *mut [u8; PG_SIZE];
                    (*buf).fill(0);
                    if entry_addr < mmap.addr + mmap.length {
                        let size = min(PG_SIZE, mmap.addr + mmap.length - entry_addr);
                        mmap.fd
                            .seek(SeekFrom::Start(
                                mmap.offset + (entry_addr - mmap.addr) as usize,
                            ))
                            .unwrap();
                        mmap.fd.read(&mut (*buf)[..size]).unwrap();
                    }
                }
                return Ok(());
            }
        }
        return Err(OsError::BadPtr);
    }
    Ok(())
}

pub fn handler(frame: &mut Frame, fault: Exception, addr: usize) {
    let privilege = frame.sstatus.spp();

    let present = {
        let table = unsafe { PageTable::effective_pagetable() };
        match table.get_pte(addr) {
            Some(entry) => entry.is_valid(),
            None => false,
        }
    };

    unsafe { sstatus::set_sie() };

    kprintln!(
        "Page fault at {:#x}: {} error {} page in {} context.",
        addr,
        if present { "rights" } else { "not present" },
        match fault {
            StorePageFault => "writing",
            LoadPageFault => "reading",
            InstructionPageFault => "fetching instruction",
            _ => panic!("Unknown Page Fault"),
        },
        match privilege {
            SPP::Supervisor => "kernel",
            SPP::User => "user",
        }
    );

    match privilege {
        SPP::Supervisor => {
            if frame.sepc == __knrl_read_usr_byte_pc as _ {
                if user_page_fault(frame, frame.x[10]).is_ok() {
                    if thread::current()
                        .pagetable
                        .as_ref()
                        .unwrap()
                        .lock()
                        .get_pte(frame.x[10])
                        .unwrap()
                        .is_user_readable()
                    {
                        return;
                    }
                }
                // Failed to read user byte from kernel space when trap in pagefault
                frame.x[11] = 1; // set a1 to non-zero
                frame.sepc = __knrl_read_usr_exit as _;
            } else if frame.sepc == __knrl_write_usr_byte_pc as _ {
                if user_page_fault(frame, frame.x[10]).is_ok() {
                    if thread::current()
                        .pagetable
                        .as_ref()
                        .unwrap()
                        .lock()
                        .get_pte(frame.x[10])
                        .unwrap()
                        .is_user_writable()
                    {
                        return;
                    }
                }
                // Failed to write user byte from kernel space when trap in pagefault
                frame.x[11] = 1; // set a1 to non-zero
                frame.sepc = __knrl_write_usr_exit as _;
            } else {
                panic!("Kernel page fault");
            }
        }
        SPP::User => match user_page_fault(frame, addr) {
            Ok(()) => {}
            Err(OsError::UserError) => {
                panic!("User page fault with no userproc");
            }
            Err(OsError::BadPtr) => {
                kprintln!("Invalid access at address {:#x}, exiting process.", addr);
                userproc::exit(-1);
            }
            _ => {
                panic!("Unexpected user page fault error");
            }
        },
    }
}
