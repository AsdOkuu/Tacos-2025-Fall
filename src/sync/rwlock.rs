use crate::sync::sema::Semaphore;
use core::cell::{Cell, UnsafeCell};
use core::ops::{Deref, DerefMut};

/// Reader-Writer Lock
///
/// This lock allows multiple readers or one writer, but not both at the same time.
pub struct RwLock<T> {
    readers: Semaphore,          // Semaphore to track reader count
    writer: Semaphore,           // Semaphore to ensure exclusive writer access
    active_readers: Cell<usize>, // Tracks the number of active readers
    value: UnsafeCell<T>,        // The wrapped value
}

impl<T> RwLock<T> {
    /// Creates a new reader-writer lock wrapping the given value.
    pub fn new(value: T) -> Self {
        RwLock {
            readers: Semaphore::new(1),
            writer: Semaphore::new(1),
            active_readers: Cell::new(0),
            value: UnsafeCell::new(value),
        }
    }

    /// Acquires the lock for reading.
    /// Multiple readers can acquire the lock simultaneously.
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        self.readers.down();
        let count = self.active_readers.get();
        if count == 0 {
            self.writer.down(); // Block writers if this is the first reader
        }
        self.active_readers.set(count + 1);
        self.readers.up();
        RwLockReadGuard { lock: self }
    }

    /// Acquires the lock for writing.
    /// Only one writer can acquire the lock at a time, and no readers are allowed.
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        self.writer.down();
        RwLockWriteGuard { lock: self }
    }
}

/// RAII guard for reading access to the RwLock.
pub struct RwLockReadGuard<'a, T> {
    lock: &'a RwLock<T>,
}

impl<T> Deref for RwLockReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> Drop for RwLockReadGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.readers.down();
        let count = self.lock.active_readers.get() - 1;
        self.lock.active_readers.set(count);
        if count == 0 {
            self.lock.writer.up(); // Allow writers if this was the last reader
        }
        self.lock.readers.up();
    }
}

/// RAII guard for writing access to the RwLock.
pub struct RwLockWriteGuard<'a, T> {
    lock: &'a RwLock<T>,
}

impl<T> Deref for RwLockWriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for RwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for RwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.writer.up();
    }
}

// SAFETY: RwLock is Send if T is Send because the lock can be safely transferred between threads.
unsafe impl<T: Send> Send for RwLock<T> {}

// SAFETY: RwLock is Sync if T is Send + Sync because the lock can be safely shared between threads.
unsafe impl<T: Send + Sync> Sync for RwLock<T> {}
