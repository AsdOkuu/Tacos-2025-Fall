#![no_std]
#![no_main]

extern crate alloc;
extern crate bitflags;
extern crate elf_rs;
extern crate fdt;
extern crate riscv;

#[macro_use]
pub mod sbi;
pub mod boot;
pub mod device;
pub mod error;
pub mod fs;
pub mod io;
pub mod mem;
pub mod sync;
pub mod thread;
pub mod trace;
pub mod trap;
pub mod userproc;

#[cfg(feature = "test")]
#[path = "../test/mod.rs"]
mod test;

pub use error::OsError;

use core::{ptr, slice, str};
use fdt::{standard_nodes::MemoryRegion, Fdt};
use riscv::register;

use fs::{disk::DISKFS, FileSys};
use mem::PhysAddr;

use sync::Lazy;
use sync::Mutex;
use trace::DefaultTracer;
use trace::TraceLevel;
use trace::Tracepoint;

extern "C" {
    fn sbss();
    fn ebss();
    fn ekernel();
    fn bootstack();
}

pub type Result<T> = core::result::Result<T, OsError>;

static DEFAULT_TP: Lazy<Mutex<Tracepoint<DefaultTracer>>> =
    Lazy::new(|| Mutex::new(Tracepoint::new(TraceLevel::Debug)));

#[cfg(feature = "test-probe")]
#[allow(named_asm_labels)]
fn test_probe() {
    use core::arch::asm;
    unsafe {
        asm!("test_probe_flag:", "nop");
    }
    kprintln!("[TEST PROBE] Inside test_probe function.");
}

#[cfg(feature = "test-probe")]
extern "C" {
    fn test_probe_flag();
}

/// Initializes major components of our kernel
///
/// Note: `extern "C"` ensures this function adhere to the C calling convention.
/// (ref: https://doc.rust-lang.org/nomicon/ffi.html?highlight=calling%20convention#rust-side)
#[no_mangle]
pub extern "C" fn main(hart_id: usize, dtb: usize) -> ! {
    kprintln!("Hello, World!");

    // Flush BSS since they are not loaded and the corresponding memory may be random
    unsafe { ptr::write_bytes(sbss as *mut u8, 0, ebss as usize - sbss as usize) };

    // Parse the device tree.
    let devtree = unsafe { Fdt::from_ptr(dtb as *const u8).unwrap() };
    // Get the start point and length of physical memory
    let (pm_base, pm_len) = {
        let memory = devtree.memory();
        let mut regions = memory.regions();
        let MemoryRegion {
            starting_address,
            size,
        } = regions.next().expect("No memory info.");
        assert_eq!(regions.next(), None, "Unknown memory region");
        (
            starting_address as usize,
            size.expect("Unknown physical memory length"),
        )
    };
    assert_eq!(pm_base, mem::PM_BASE, "Error constant mem::PM_BASE.");
    // Get the boot arguments.
    let _bootargs: &'static str = unsafe {
        let (vm, len) = {
            let bootargs = devtree.chosen().bootargs().unwrap();
            let len = bootargs.len();
            (PhysAddr::from_pa(bootargs.as_ptr() as usize).into_va(), len)
        };
        str::from_utf8(slice::from_raw_parts(vm as *const u8, len)).unwrap()
    };

    // Initialize memory management.
    let ram_base = ekernel as usize;
    let ram_tail = dtb + mem::VM_OFFSET; // Current we do not reuse dtb area.
    mem::init(ram_base, ram_tail, pm_len);

    #[cfg(feature = "debug")]
    {
        kprintln!("RAM: 0x{:x} - 0x{:x}", ram_base, ram_tail);
        kprintln!("BOOTARGS: {:?}", _bootargs);
    }

    trap::set_strap_entry();

    unsafe {
        register::sstatus::set_sie();
        register::sstatus::set_sum();
    };

    device::plic::init(hart_id);
    #[cfg(feature = "debug")]
    kprintln!("Virtio inited.");

    // Init timer & external interrupt
    sbi::interrupt::init();

    #[cfg(feature = "test-probe")]
    {
        use alloc::sync::Arc;
        use trace::register_probe;
        use trace::Probe;

        use crate::trace::unregister_probe;

        let probe_addr = test_probe_flag as usize;
        let probe = Arc::new(Probe::new(probe_addr));
        probe.set_pre_handler(|frame| {
            kprintln!("[PROBE] Pre handler called.");
        });
        probe.set_post_handler(|frame| {
            kprintln!("[PROBE] Post handler called.");
        });
        register_probe(probe.clone());

        test_probe();

        kprintln!("[TEST PROBE] test_probe function returned.");

        unregister_probe(probe);

        test_probe();
    }
    #[cfg(feature = "test")]
    {
        use alloc::sync::Arc;
        let sema = Arc::new(sync::Semaphore::new(0));
        let sema2 = sema.clone();
        thread::spawn("test", move || crate::test::main(sema2, _bootargs));
        sema.down();
    }

    #[cfg(feature = "shell")]
    {
        // TODO: Lab 0
        const BSIZE: usize = 4096;
        'shell: loop {
            DEFAULT_TP.lock().trace(&DefaultTracer);
            kprint!("PKUOS>");
            let mut input = [0; BSIZE];
            let mut len = 0;
            loop {
                use crate::sbi::console_getchar;
                let ch = console_getchar() as u8;
                if ch == b'\n' {
                    break;
                }
                if len == BSIZE {
                    loop {
                        let ch = console_getchar() as u8;
                        if ch == b'\n' {
                            break;
                        }
                    }
                    kprintln!("buffer overflow");
                    continue 'shell;
                }
                input[len] = ch;
                len += 1;
            }
            let input = str::from_utf8(&input[0..len]).unwrap();
            match input {
                "whoami" => kprintln!("2300012914"),
                "enable_trace" => {
                    DEFAULT_TP.lock().enable();
                    kprintln!("trace enabled");
                }
                "disable_trace" => {
                    DEFAULT_TP.lock().disable();
                    kprintln!("trace disabled");
                }
                "exit" => break,
                _ => kprintln!("invalid command"),
            }
        }
    }

    DISKFS.unmount();

    kprintln!("Goodbye, World!");

    sbi::reset(
        sbi::system_reset::Type::Shutdown,
        sbi::system_reset::Reason::NoReason,
    )
}

/* ---------------------------------- PANIC --------------------------------- */
#[panic_handler]
unsafe fn panic(info: &core::panic::PanicInfo) -> ! {
    // Disable interrupts until shutting down the whole system
    sbi::interrupt::set(false);

    // Report the reason for invoking `panic`
    kprintln!("{}", info);

    sbi::reset(
        sbi::system_reset::Type::Shutdown,
        sbi::system_reset::Reason::SystemFailure,
    )
}
