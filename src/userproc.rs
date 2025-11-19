//! User process.
//!

mod load;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::arch::asm;
use core::iter::zip;
use core::mem::{size_of, MaybeUninit};
use riscv::register::sstatus;

use crate::fs::File;
use crate::mem::pagetable::KernelPgTable;
use crate::mem::PG_SIZE;
use crate::sbi::interrupt::set;
use crate::sync::Mutex;
use crate::sync::Semaphore;
use crate::thread::{self, current};
use crate::trap::{trap_exit_u, Frame};

pub struct UserProc {
    #[allow(dead_code)]
    bin: File,
    pub init_sp: usize,
    status: Mutex<Option<isize>>,
    wait: Mutex<Option<(Arc<Semaphore>, Arc<Semaphore>)>>,
    pub fdlist: Mutex<Vec<Option<Mutex<File>>>>,
    pub exited: Mutex<bool>,
}

impl UserProc {
    pub fn new(file: File, init_sp: usize) -> Self {
        Self {
            bin: file,
            init_sp,
            status: Mutex::new(None),
            wait: Mutex::new(None),
            fdlist: Mutex::new(Vec::new()),
            exited: Mutex::new(false),
        }
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

    let exec_info = match load::load_executable(&mut file, &mut pt) {
        Ok(x) => x,
        Err(_) => unsafe {
            pt.destroy();
            return -1;
        },
    };

    // Here the new process will be created.
    let userproc = UserProc::new(file, exec_info.init_sp);

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

    return result;
}

/// Initializes a user process in current thread.
///
/// This function won't return.
pub fn start(argv: Vec<String>, mut frame: Frame) -> ! {
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
