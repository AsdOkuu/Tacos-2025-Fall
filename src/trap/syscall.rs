//! Syscall handlers
//!

#![allow(dead_code)]

/* -------------------------------------------------------------------------- */
/*                               SYSCALL NUMBER                               */
/* -------------------------------------------------------------------------- */

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::{mem::size_of, str::from_utf8};

use crate::io::{Read, Seek, SeekFrom, Write};
use crate::sbi::console_getchar;
use crate::sync::Mutex;
use crate::{
    fs::{disk::DISKFS, FileSys},
    sbi::shutdown,
    thread::current,
    userproc::{execute, exit, wait},
};

const SYS_HALT: usize = 1;
const SYS_EXIT: usize = 2;
const SYS_EXEC: usize = 3;
const SYS_WAIT: usize = 4;
const SYS_REMOVE: usize = 5;
const SYS_OPEN: usize = 6;
const SYS_READ: usize = 7;
const SYS_WRITE: usize = 8;
const SYS_SEEK: usize = 9;
const SYS_TELL: usize = 10;
const SYS_CLOSE: usize = 11;
const SYS_FSTAT: usize = 12;

fn get_u8array_checked(mut ptr: usize, size: usize) -> Result<Vec<u8>, ()> {
    let mut raw = Vec::new();
    let mut len = size;
    while len > 0 {
        match current().pagetable.as_ref().unwrap().lock().get_pte(ptr) {
            None => return Err(()),
            Some(pte) => {
                if !pte.is_valid() {
                    return Err(());
                }
            }
        }
        let ch = unsafe { *(ptr as *const u8) };
        raw.push(ch);

        let newptr = ptr.checked_add(1);
        if newptr.is_none() {
            return Err(());
        }
        ptr = newptr.unwrap();
        len -= 1;
    }

    Ok(raw)
}

fn get_string_checked(mut ptr: usize) -> Result<String, ()> {
    let mut raw = Vec::new();
    loop {
        match current().pagetable.as_ref().unwrap().lock().get_pte(ptr) {
            None => return Err(()),
            Some(pte) => {
                if !pte.is_valid() {
                    return Err(());
                }
            }
        }
        let ch = unsafe { *(ptr as *const u8) };

        if ch == 0 {
            break;
        }
        raw.push(ch);

        let newptr = ptr.checked_add(1);
        if newptr.is_none() {
            return Err(());
        }
        ptr = newptr.unwrap();
    }

    let s = from_utf8(&raw);
    if s.is_err() {
        return Err(());
    }
    Ok(s.unwrap().to_string())
}

pub fn syscall_handler(_id: usize, _args: [usize; 3]) -> isize {
    // TODO: LAB2 impl
    match _id {
        SYS_HALT => shutdown(),
        SYS_EXIT => exit(_args[0] as isize),
        SYS_EXEC => {
            // pagetable required.
            if current().pagetable.is_none() {
                return -1;
            }

            // check file name validity.
            let name = match get_string_checked(_args[0] as usize) {
                Ok(n) => n,
                Err(_) => return -1,
            };
            let file = match DISKFS.open(name.as_str().into()) {
                Ok(f) => f,
                Err(_) => return -1,
            };
            // check argv validity.
            let mut argv = _args[1] as usize;
            let mut arglist = Vec::new();
            loop {
                match current().pagetable.as_ref().unwrap().lock().get_pte(argv) {
                    None => return -1,
                    Some(pte) => {
                        if !pte.is_valid() {
                            return -1;
                        }
                    }
                }
                let arg = unsafe { *(argv as *const usize) };
                if arg == 0 {
                    break;
                }

                // check inner arg validity.
                let s = match get_string_checked(arg) {
                    Ok(s) => s,
                    Err(_) => return -1,
                };
                arglist.push(s);

                argv = match argv.checked_add(size_of::<usize>()) {
                    Some(n) => n,
                    None => return -1,
                };
            }

            execute(file, arglist)
        }
        SYS_WAIT => match wait(_args[0] as isize) {
            Some(status) => status,
            None => -1,
        },
        SYS_OPEN => {
            if current().pagetable.is_none() {
                return -1;
            }
            if current().userproc.is_none() {
                return -1;
            }
            let name = match get_string_checked(_args[0]) {
                Ok(n) => n,
                Err(_) => return -1,
            };
            if name.is_empty() {
                return -1;
            }
            let flag = _args[1];
            let mut file = match DISKFS.open(name.as_str().into()) {
                Ok(f) => f,
                Err(_) => {
                    if flag & (0x200 as usize) == 0 {
                        return -1;
                    } else {
                        match DISKFS.create(name.as_str().into()) {
                            Ok(f) => f,
                            Err(_) => return -1,
                        }
                    }
                }
            };
            if flag & (0x3 as usize) == 0 {
                file.deny_write();
            } else if flag & (0x1 as usize) != 0 {
                file.deny_read();
            }
            current()
                .userproc
                .as_ref()
                .unwrap()
                .fdlist
                .lock()
                .push(Some(Mutex::new(file)));
            current().userproc.as_ref().unwrap().fdlist.lock().len() as isize + 2
        }
        SYS_READ => {
            if current().pagetable.is_none() {
                return -1;
            }
            let fd = _args[0];
            let buf = _args[1] as *mut u8;
            let size = _args[2];
            // check buf
            for i in 0..size {
                match current()
                    .pagetable
                    .as_ref()
                    .unwrap()
                    .lock()
                    .get_pte(buf as usize + i)
                {
                    None => return -1,
                    Some(pte) => {
                        if !pte.is_valid() {
                            return -1;
                        }
                    }
                }
            }
            match fd {
                0 => {
                    // stdin
                    for i in 0..size {
                        let ch = console_getchar();
                        unsafe {
                            *(buf.add(i) as *mut u8) = ch as u8;
                        }
                    }
                    size as isize
                }
                1 | 2 => {
                    // stdout | stderr
                    -1
                }
                fd => {
                    if current().userproc.is_none() {
                        return -1;
                    }
                    let cur = current();
                    let fdlist = cur.userproc.as_ref().unwrap().fdlist.lock();
                    let mut file = match fdlist.get(fd - 3) {
                        Some(Some(f)) => f.lock(),
                        _ => return -1,
                    };

                    match file.read(unsafe { core::slice::from_raw_parts_mut(buf, size) }) {
                        Ok(n) => n as isize,
                        Err(_) => -1,
                    }
                }
            }
        }
        SYS_WRITE => {
            if current().pagetable.is_none() {
                return -1;
            }
            let fd = _args[0];
            let size = _args[2];
            let s = match get_u8array_checked(_args[1], size) {
                Ok(n) => n,
                Err(_) => return -1,
            };
            match fd {
                0 => {
                    // stdin
                    -1
                }
                1 | 2 => {
                    // stdout | stderr
                    kprint!("{}", s.iter().map(|&c| c as char).collect::<String>());
                    size as isize
                }
                fd => {
                    if current().userproc.is_none() {
                        return -1;
                    }
                    let cur = current();
                    let fdlist = cur.userproc.as_ref().unwrap().fdlist.lock();
                    let mut file = match fdlist.get(fd - 3) {
                        Some(Some(f)) => f.lock(),
                        _ => return -1,
                    };
                    match file
                        .write(unsafe { core::slice::from_raw_parts(_args[1] as *const u8, size) })
                    {
                        Ok(n) => n as isize,
                        Err(_) => -1,
                    }
                }
            }
        }
        SYS_REMOVE => {
            let name = match get_string_checked(_args[0]) {
                Ok(n) => n,
                Err(_) => return -1,
            };
            match DISKFS.remove(name.as_str().into()) {
                Ok(_) => 0,
                Err(_) => -1,
            }
        }
        SYS_SEEK => {
            let fd = _args[0];
            let pos = _args[1];
            match fd {
                0 | 1 | 2 => -1,
                fd => {
                    if current().userproc.is_none() {
                        return -1;
                    }
                    let cur = current();
                    let fdlist = cur.userproc.as_ref().unwrap().fdlist.lock();
                    let mut file = match fdlist.get(fd - 3) {
                        Some(Some(f)) => f.lock(),
                        _ => return -1,
                    };
                    match file.seek(SeekFrom::Start(pos as usize)) {
                        Ok(_) => 0,
                        Err(_) => -1,
                    }
                }
            }
        }
        SYS_TELL => {
            let fd = _args[0];
            match fd {
                0 | 1 | 2 => -1,
                fd => {
                    if current().userproc.is_none() {
                        return -1;
                    }
                    let cur = current();
                    let fdlist = cur.userproc.as_ref().unwrap().fdlist.lock();
                    let mut file = match fdlist.get(fd - 3) {
                        Some(Some(f)) => f.lock(),
                        _ => return -1,
                    };
                    match file.pos() {
                        Ok(pos) => *pos as isize,
                        Err(_) => -1,
                    }
                }
            }
        }
        SYS_FSTAT => {
            let fd = _args[0];
            match fd {
                0 | 1 | 2 => -1,
                fd => {
                    if current().pagetable.is_none() {
                        return -1;
                    }
                    for i in 0..2 * size_of::<usize>() {
                        match current()
                            .pagetable
                            .as_ref()
                            .unwrap()
                            .lock()
                            .get_pte(_args[1] + i)
                        {
                            None => return -1,
                            Some(pte) => {
                                if !pte.is_valid() {
                                    return -1;
                                }
                            }
                        }
                    }
                    if current().userproc.is_none() {
                        return -1;
                    }
                    let cur = current();
                    let fdlist = cur.userproc.as_ref().unwrap().fdlist.lock();
                    let file = match fdlist.get(fd - 3) {
                        Some(Some(f)) => f.lock(),
                        _ => return -1,
                    };
                    let inum = file.inum();
                    let size = match file.len() {
                        Ok(s) => s,
                        Err(_) => return -1,
                    };
                    unsafe {
                        let ptr = _args[1] as *mut usize;
                        *ptr = inum;
                        *(ptr.add(1)) = size;
                    }
                    0
                }
            }
        }
        SYS_CLOSE => {
            let fd = _args[0];
            match fd {
                0 | 1 | 2 => 0,
                fd => {
                    if current().userproc.is_none() {
                        return -1;
                    }
                    if current()
                        .userproc
                        .as_ref()
                        .unwrap()
                        .fdlist
                        .lock()
                        .get(fd - 3)
                        .is_none()
                    {
                        return -1;
                    }
                    if current()
                        .userproc
                        .as_ref()
                        .unwrap()
                        .fdlist
                        .lock()
                        .get(fd - 3)
                        .unwrap()
                        .is_none()
                    {
                        return -1;
                    }
                    current()
                        .userproc
                        .as_ref()
                        .unwrap()
                        .fdlist
                        .lock()
                        .push(None);
                    current()
                        .userproc
                        .as_ref()
                        .unwrap()
                        .fdlist
                        .lock()
                        .swap_remove(fd - 3);
                    0
                }
            }
        }
        _ => -1,
    }
}
