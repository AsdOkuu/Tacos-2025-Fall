//! Kernel Threads

mod imp;
pub mod manager;
pub mod scheduler;
pub mod switch;

pub use self::imp::*;
pub use self::manager::Manager;
pub(self) use self::scheduler::{Schedule, Scheduler};

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

/// Create a new thread
pub fn spawn<F>(name: &'static str, f: F) -> Arc<Thread>
where
    F: FnOnce() + Send + 'static,
{
    Builder::new(f).name(name).spawn()
}

/// Get the current running thread
pub fn current() -> Arc<Thread> {
    Manager::get().current.lock().clone()
}

/// Destroy all `Dying` threads
pub fn destroy() {
    Manager::get().destroy();
}

/// Yield the control to another thread (if there's another one ready to run).
pub fn schedule() {
    // kprintln!("sched!");
    Manager::get().schedule()
}

/// Wake up timer threads.
pub fn timer_wake() {
    Manager::get().timer_wake();
}

/// Gracefully shut down the current thread, and schedule another one.
pub fn exit() -> ! {
    {
        let current = Manager::get().current.lock();

        #[cfg(feature = "debug")]
        kprintln!("Exit: {:?}", *current);

        current.set_status(Status::Dying);
    }

    schedule();

    unreachable!("An exited thread shouldn't be scheduled again");
}

/// Mark the current thread as [`Blocked`](Status::Blocked) and
/// yield the control to another thread
pub fn block() {
    let current = current();
    current.set_status(Status::Blocked);

    #[cfg(feature = "debug")]
    kprintln!("[THREAD] Block {:?}", current);

    schedule();
}

/// Wake up a previously blocked thread, mark it as [`Ready`](Status::Ready),
/// and register it into the scheduler.
pub fn wake_up(thread: Arc<Thread>) {
    assert_eq!(thread.status(), Status::Blocked);
    thread.set_status(Status::Ready);

    #[cfg(feature = "debug")]
    kprintln!("[THREAD] Wake up {:?}", thread);

    Manager::get().scheduler.lock().register(thread);
}

/// (Lab1) Sets the current thread's priority to a given value
pub fn set_priority(_priority: u32) {
    if *current().locking.lock() > 0 {
        let old_priority = current().origin_priority.load(Ordering::Relaxed);
        current()
            .origin_priority
            .fetch_add(_priority - old_priority, Ordering::Relaxed);
    } else {
        let old_priority = get_priority();
        current()
            .priority
            .fetch_add(_priority - old_priority, Ordering::Relaxed);
        if _priority < old_priority {
            schedule();
        }
    }
}

/// (Lab1) Returns the current thread's effective priority.
pub fn get_priority() -> u32 {
    current().priority.load(Ordering::Relaxed)
}

/// (Lab1) Make the current thread sleep for the given ticks.
pub fn sleep(ticks: i64) {
    use crate::sbi::timer::timer_ticks;

    let start = timer_ticks();

    #[cfg(feature = "debug")]
    kprintln!("sleep time: {}; sleep end time: {}", ticks, start + ticks);

    if ticks > 0 {
        Manager::get().timer_register(current(), start + ticks);
        block();
    } else {
        schedule();
    }
}
