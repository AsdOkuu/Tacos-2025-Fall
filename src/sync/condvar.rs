//! # Condition Variable
//!
//! [`Condvar`] are able to block a thread so that it consumes no CPU time
//! while waiting for an event to occur. It is typically associated with a
//! boolean predicate (a condition) and a mutex. The predicate is always verified
//! inside of the mutex before determining that a thread must block.
//!
//! ## Usage
//!
//! Suppose there are two threads A and B, and thread A is waiting for some events
//! in thread B to happen.
//!
//! Here is the common practice of thread A:
//! ```rust
//! let pair = Arc::new(Mutex::new(false), Condvar::new());
//!
//! let (lock, cvar) = &*pair;
//! let condition = lock.lock();
//! while !condition {
//!     cvar.wait(&condition);
//! }
//! ```
//!
//! Here is a good practice of thread B:
//! ```rust
//! let (lock, cvar) = &*pair;
//!
//! // Lock must be held during a call to `Condvar.notify_one()`. Therefore, `guard` has to bind
//! // to a local variable so that it won't be dropped too soon.
//!
//! let guard = lock.lock(); // Bind `guard` to a local variable
//! *guard = true;           // Condition change
//! cvar.notify_one();       // Notify (`guard` will overlive this line)
//! ```
//!
//! Here is a bad practice of thread B:
//! ```rust
//! let (lock, cvar) = &*pair;
//!
//! *lock.lock() = true;     // Lock won't be held after this line.
//! cvar.notify_one();       // Buggy: notify another thread without holding the Lock
//! ```
//!

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::cell::RefCell;

use crate::sync::{Lock, MutexGuard, Semaphore};
use crate::thread::get_priority;

pub struct Condvar(RefCell<BTreeMap<u32, VecDeque<Arc<Semaphore>>>>);

unsafe impl Sync for Condvar {}
unsafe impl Send for Condvar {}

impl Condvar {
    pub fn new() -> Self {
        Condvar(Default::default())
    }

    pub fn wait<T, L: Lock>(&self, guard: &mut MutexGuard<'_, T, L>) {
        let sema = Arc::new(Semaphore::new(0));
        self.0
            .borrow_mut()
            .entry(get_priority())
            .or_default()
            .push_front(sema.clone());

        guard.release();
        sema.down();
        guard.acquire();
    }

    fn condvar_schedule(&self) -> Option<Arc<Semaphore>> {
        for (_priority, slist) in self.0.borrow_mut().iter_mut().rev() {
            if !slist.is_empty() {
                return slist.pop_back();
            }
        }
        None
    }

    /// Wake up one thread from the waiting list
    pub fn notify_one(&self) {
        if let Some(sema) = self.condvar_schedule() {
            sema.up();
        }
    }

    /// Wake up all waiting threads
    pub fn notify_all(&self) {
        for (_priority, slist) in self.0.borrow().iter().rev() {
            for sema in slist {
                sema.up();
            }
        }
        self.0.borrow_mut().clear();
    }
}
