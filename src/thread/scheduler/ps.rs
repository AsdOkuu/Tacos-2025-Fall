use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::thread::{Schedule, Thread};

/// Priority scheduler.
#[derive(Default)]
pub struct Ps(BTreeMap<u32, VecDeque<Arc<Thread>>>);

impl Schedule for Ps {
    fn register(&mut self, thread: Arc<Thread>) {
        let priority = thread.priority.load(Ordering::Relaxed);
        self.0.entry(priority).or_default().push_front(thread);
    }

    fn schedule(&mut self) -> Option<Arc<Thread>> {
        for (_priority, tlist) in self.0.iter_mut().rev() {
            if !tlist.is_empty() {
                let thread = tlist.pop_back();
                if let Some(thread) = &thread {
                    kprintln!(
                        "{} {} get scheduled with priority {}",
                        thread.name(),
                        thread.id(),
                        _priority
                    );
                }
                return thread;
            }
        }
        None
    }
}
