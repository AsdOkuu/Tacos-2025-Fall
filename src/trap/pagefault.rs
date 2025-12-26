use crate::fs::disk::Swap;
use crate::io::SeekFrom;
use crate::mem::palloc::UserPool;
use crate::mem::userbuf::{
    __knrl_read_usr_byte_pc, __knrl_read_usr_exit, __knrl_write_usr_byte_pc, __knrl_write_usr_exit,
};
use crate::mem::{PTEFlags, PageAlign, PageTable, MAX_USER_STACK, PG_SIZE};
use crate::thread::{self, current};
use crate::trap::Frame;
use crate::userproc::{self};
use crate::userproc::{PT_SEMA, ZERO_PAGE};
use crate::{OsError, Result};
use core::cmp::min;
use io::Read;
use io::Seek;

use riscv::register::scause::Exception::{self};
use riscv::register::sstatus::{self, SPP};

fn user_page_fault(frame: &mut Frame, addr: usize) -> Result<()> {
    PT_SEMA.down();
    if thread::current().userproc.is_none() {
        PT_SEMA.up();
        return Err(OsError::UserError);
    }
    let entry_addr = PageAlign::floor(addr);
    let mut data = None;
    let mut kbuf = [0u8; PG_SIZE];
    if thread::current()
        .userproc
        .as_ref()
        .unwrap()
        .swap_table
        .lock()
        .contains_key(&entry_addr)
    {
        // 1. Move swap space out to local var 2. alloc a page
        assert!(
            thread::current()
                .userproc
                .as_ref()
                .unwrap()
                .swap_table
                .lock()[&entry_addr]
                .in_swap,
            "Page not in swap space"
        );
        let page = thread::current()
            .userproc
            .as_ref()
            .unwrap()
            .swap_table
            .lock()[&entry_addr]
            .page;
        data = Some(
            thread::current()
                .userproc
                .as_ref()
                .unwrap()
                .swap_table
                .lock()[&entry_addr]
                .flags,
        );
        Swap::read(page, &mut kbuf);
    }
    if let Some(flags) = data {
        unsafe {
            UserPool::alloc_page(entry_addr, flags, &kbuf);
        }
        PT_SEMA.up();
        return Ok(());
    }
    let init_sp = thread::current().userproc.as_ref().unwrap().init_sp;
    let sp = if frame.x[2] > init_sp || frame.x[2] + MAX_USER_STACK <= init_sp {
        frame.x[12]
    } else {
        frame.x[2]
    };
    // kprintln!("frame.x[2]: {:#x}, sp: {:#x}", sp, frame.x[2]);
    if addr < init_sp && addr + MAX_USER_STACK >= init_sp && addr >= sp {
        // Stack growth
        unsafe {
            UserPool::alloc_page(
                PageAlign::floor(addr),
                PTEFlags::V | PTEFlags::R | PTEFlags::W | PTEFlags::U,
                &ZERO_PAGE,
            );
        }

        #[cfg(feature = "debug")]
        kprintln!(
            "[USERPROC] User Stack Grow: (k){:p} -> (u) {:#x}",
            stack_va,
            stack_page_begin
        );
    } else {
        let entry_addr = PageAlign::floor(addr);
        let mut data = None;
        let mut kbuf = [0u8; PG_SIZE];
        // for (_, mmap) in thread::current()
        //     .userproc
        //     .as_ref()
        //     .unwrap()
        //     .mmap_table
        //     .lock()
        //     .iter_mut()
        // {
        //     kprintln!(
        //         "MMap region: addr={:#x}, length={:#x}, pages={:#x}",
        //         mmap.addr,
        //         mmap.length,
        //         mmap.pages
        //     );
        // }
        for (_, mmap) in thread::current()
            .userproc
            .as_ref()
            .unwrap()
            .mmap_table
            .lock()
            .iter_mut()
        {
            // kprintln!(
            //     "MMap region: addr={:#x}, length={:#x}, pages={:#x}",
            //     mmap.addr,
            //     mmap.length,
            //     mmap.pages
            // );
            if addr >= mmap.addr && addr < mmap.addr + mmap.pages * PG_SIZE {
                // mmap region access
                unsafe {
                    let buf = kbuf.as_mut_ptr() as *mut [u8; PG_SIZE];
                    (*buf).fill(0);
                    if entry_addr < mmap.addr + mmap.length {
                        let size = min(PG_SIZE, mmap.addr + mmap.length - entry_addr);
                        mmap.fd
                            .seek(SeekFrom::Start(
                                mmap.offset + (entry_addr - mmap.addr) as usize,
                            ))
                            .unwrap();
                        // kprintln!("read in: {}", size);
                        mmap.fd.read(&mut (*buf)[..size]).unwrap();
                        // kprintln!("read out");
                    }
                }

                data = Some(mmap.flags);
                break;
            }
        }
        if let Some(flags) = data {
            unsafe {
                UserPool::alloc_page(entry_addr, flags, &kbuf);
            }

            PT_SEMA.up();
            return Ok(());
        } else {
            PT_SEMA.up();
            return Err(OsError::BadPtr);
        }
    }
    PT_SEMA.up();
    Ok(())
}

pub fn handler(frame: &mut Frame, _fault: Exception, addr: usize) {
    let privilege = frame.sstatus.spp();

    let present = {
        let table = unsafe { PageTable::effective_pagetable() };
        match table.get_pte(addr) {
            Some(entry) => entry.is_valid(),
            None => false,
        }
    };

    unsafe { sstatus::set_sie() };

    // kprintln!("{} {}:", thread::current().name(), thread::current().id());

    #[cfg(feature = "Debug")]
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
                panic!(
                    "Kernel page fault. sepc: {:#x}, current: {} {}",
                    frame.sepc,
                    current().name(),
                    current().id()
                );
            }
        }
        SPP::User => {
            if present {
                userproc::exit(-1);
            }
            match user_page_fault(frame, addr) {
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
            }
        }
    }
}
