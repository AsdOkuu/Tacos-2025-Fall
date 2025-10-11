use alloc::sync::Arc;
use core::cell::RefCell;

use crate::sync::{Lock, Semaphore};
use crate::thread::{self, Thread};

/// Sleep lock. Uses [`Semaphore`] under the hood.
#[derive(Clone)]
pub struct Sleep {
    inner: Semaphore,
    holder: RefCell<Option<Arc<Thread>>>,
}

impl Default for Sleep {
    fn default() -> Self {
        Self {
            inner: Semaphore::new(1),
            holder: Default::default(),
        }
    }
}

impl Lock for Sleep {
    fn acquire(&self) {
        if let Some(thread) = self.holder.borrow().as_ref() {
            thread::current().wait(Arc::clone(thread));
        }
        self.inner.down();
        thread::current().unwait();
        #[cfg(feature = "debug")]
        kprintln!(
            "[INNER] change to {} {}",
            thread::current().name(),
            thread::current().id()
        );
        self.holder.borrow_mut().replace(thread::current());
    }

    fn release(&self) {
        assert!(Arc::ptr_eq(
            self.holder.borrow().as_ref().unwrap(),
            &thread::current()
        ));

        self.holder.borrow_mut().take().unwrap();
        self.inner.up();
    }
}

unsafe impl Sync for Sleep {}
