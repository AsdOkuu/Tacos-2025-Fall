//! Swap file.
//!
// Swap may not be used.
#![allow(dead_code)]
use super::DISKFS;
use crate::fs::{File, FileSys};
use crate::io::{Read, Seek, SeekFrom};
use crate::mem::PG_SIZE;
use crate::sync::{Lazy, Mutex, MutexGuard, Primitive};
use io::Write;

const SWAP_SIZE: usize = 4096;

pub struct SwapBitmap;

static SWAP_BITMAP: Lazy<Mutex<[u8; SWAP_SIZE]>> = Lazy::new(|| Mutex::new([0u8; SWAP_SIZE]));

impl SwapBitmap {
    pub fn lock() -> MutexGuard<'static, [u8; SWAP_SIZE], Primitive> {
        SWAP_BITMAP.lock()
    }

    pub fn take() -> Option<usize> {
        let mut bitmap = Self::lock();
        for (i, byte) in bitmap.iter_mut().enumerate() {
            if *byte != 0xFF {
                for bit in 0..8 {
                    if (*byte & (1 << bit)) == 0 {
                        *byte |= 1 << bit;
                        return Some(i * 8 + bit);
                    }
                }
            }
        }
        None
    }

    pub fn release(index: usize) {
        let mut bitmap = Self::lock();
        let byte_index = index / 8;
        let bit_index = index % 8;
        bitmap[byte_index] &= !(1 << bit_index);
    }
}

pub struct Swap;

static SWAPFILE: Lazy<Mutex<File>> = Lazy::new(|| {
    Mutex::new(
        DISKFS
            .open(".glbswap".into())
            .expect("swap file \".glbswap\" should exist"),
    )
});

impl Swap {
    pub fn len() -> usize {
        SWAPFILE.lock().len().unwrap()
    }

    pub fn page_num() -> usize {
        // Round down.
        Self::len() / PG_SIZE
    }

    pub fn write(buf: &[u8; PG_SIZE]) -> usize {
        let mut file = Swap::lock();
        let index = SwapBitmap::take().expect("swap space full");
        file.seek(SeekFrom::Start((index * PG_SIZE) as usize))
            .unwrap();
        file.write(buf).unwrap();
        index
    }

    pub fn read(index: usize, buf: &mut [u8; PG_SIZE]) {
        let mut file = Swap::lock();
        file.seek(SeekFrom::Start((index * PG_SIZE) as usize))
            .unwrap();
        file.read(buf).unwrap();
        SwapBitmap::release(index);
    }

    /// TODO: Design high-level interfaces, or do in lab3?
    pub fn lock() -> MutexGuard<'static, File, Primitive> {
        SWAPFILE.lock()
    }
}
