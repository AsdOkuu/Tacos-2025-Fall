use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::sync::atomic::Ordering;

use crate::sbi;
use crate::thread::{self, Thread};

/// Atomic counting semaphore
///
/// # Examples
/// ```
/// let sema = Semaphore::new(0);
/// sema.down();
/// sema.up();
/// ```
#[derive(Clone)]
pub struct Semaphore {
    value: Cell<usize>,
    waiters: RefCell<Vec<Arc<Thread>>>,
}

unsafe impl Sync for Semaphore {}
unsafe impl Send for Semaphore {}

impl Semaphore {
    /// Creates a new semaphore of initial value n.
    pub const fn new(n: usize) -> Self {
        Semaphore {
            value: Cell::new(n),
            waiters: RefCell::new(Vec::new()),
        }
    }

    /// P operation
    pub fn down(&self) {
        let old = sbi::interrupt::set(false);

        // Is semaphore available?
        while self.value() == 0 {
            // `push_front` ensures to wake up threads in a fifo manner
            self.waiters.borrow_mut().push(thread::current());

            // Block the current thread until it's awakened by an `up` operation
            thread::block();
        }
        self.value.set(self.value() - 1);

        sbi::interrupt::set(old);
    }

    // Check next wake up thread
    fn sema_schedule(&self) -> Option<Arc<Thread>> {
        let mut index: usize = 0;
        let mut priority: u32 = 0;
        let mut tlist = self.waiters.borrow_mut();
        if tlist.is_empty() {
            None
        } else {
            for i in (0..tlist.len()).rev() {
                let thread = &tlist[i];
                let new_priority = thread.priority.load(Ordering::Relaxed);
                if new_priority >= priority {
                    priority = new_priority;
                    index = i;
                }
            }
            #[cfg(feature = "debug")]
            kprintln!("scheduler decide {} to run.", index);
            Some(tlist.remove(index))
        }
    }

    /// V operation
    pub fn up(&self) {
        let old = sbi::interrupt::set(false);
        let count = self.value.replace(self.value() + 1);

        // Check if we need to wake up a sleeping waiter
        if let Some(thread) = self.sema_schedule() {
            assert_eq!(count, 0);

            thread::wake_up(thread.clone());
        }

        sbi::interrupt::set(old);

        thread::schedule();
    }

    /// Get the current value of a semaphore
    pub fn value(&self) -> usize {
        self.value.get()
    }
}
