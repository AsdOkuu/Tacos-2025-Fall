use alloc::collections::btree_map::BTreeMap;
use alloc::vec;
use elf_rs::{Elf, ElfFile, ProgramHeaderEntry, ProgramHeaderFlags, ProgramType};

use crate::fs::File;
use crate::io::prelude::*;
use crate::mem::pagetable::{PTEFlags, PageTable};
use crate::mem::palloc::UserPool;
use crate::mem::{div_round_up, PageAlign, PG_MASK, PG_SIZE};
use crate::userproc::ZERO_PAGE;
use crate::userproc::{MMapTableEntry, PT_SEMA};
use crate::{OsError, Result};

#[derive(Debug, Clone, Copy)]
pub(super) struct ExecInfo {
    pub entry_point: usize,
    pub init_sp: usize,
}

pub(super) fn lazy_load_executable(
    file: &mut File,
    pagetable: &mut PageTable,
) -> Result<(ExecInfo, BTreeMap<usize, MMapTableEntry>)> {
    let (exec_info, mmap_table) = lazy_load_elf(file, pagetable)?;
    // Forbid modifying executable file when running
    file.deny_write();

    Ok((exec_info, mmap_table))
}

fn lazy_load_elf(
    file: &mut File,
    _pagetable: &mut PageTable,
) -> Result<(ExecInfo, BTreeMap<usize, MMapTableEntry>)> {
    // Ensure cursor is at the beginning
    file.rewind()?;

    let len = file.len()?;
    let mut buf = vec![0u8; len];
    file.read(&mut buf)?;

    let elf = match Elf::from_bytes(&buf) {
        Ok(Elf::Elf64(elf)) => elf,
        Ok(Elf::Elf32(_)) | Err(_) => return Err(OsError::UnknownFormat),
    };

    let mut mmap_table = BTreeMap::new();

    // load each loadable segment into memory
    elf.program_header_iter()
        .filter(|p| p.ph_type() == ProgramType::LOAD)
        .for_each(|p| {
            let entry = gen_segment_entry(file, &p);
            mmap_table.insert(entry.addr, entry);
        });

    Ok((
        ExecInfo {
            entry_point: elf.elf_header().entry_point() as _,
            init_sp: 0x80500000,
        },
        mmap_table,
    ))
}

/// gen segment entry in mmap table
fn gen_segment_entry(file: &File, phdr: &ProgramHeaderEntry) -> MMapTableEntry {
    #[cfg(feature = "debug")]
    kprintln!(
        "[USERPROC] MMap Segment: vaddr={:#x}, memsz={:#x}, filesz={:#x}, offset={:#x}",
        phdr.vaddr(),
        phdr.memsz(),
        phdr.filesz(),
        phdr.offset()
    );
    let pageoff = (phdr.vaddr() as usize) & PG_MASK;
    MMapTableEntry {
        addr: (phdr.vaddr() as usize) & !PG_MASK,
        length: pageoff + (phdr.filesz() as usize),
        pages: div_round_up(pageoff + (phdr.memsz() as usize), PG_SIZE),
        offset: phdr.offset() as usize & !PG_MASK,
        fd: file.clone(),
        flags: {
            let mut flags = PTEFlags::V | PTEFlags::U | PTEFlags::R;
            if phdr.flags().contains(ProgramHeaderFlags::EXECUTE) {
                flags |= PTEFlags::X;
            }
            if phdr.flags().contains(ProgramHeaderFlags::WRITE) {
                flags |= PTEFlags::W;
            }
            flags
        },
        writeback: false,
    }
}

/// Initializes the user stack.
pub fn init_user_stack(init_sp: usize) {
    assert!(init_sp % PG_SIZE == 0, "initial sp address misaligns");

    // Allocate a page from UserPool as user stack.
    PT_SEMA.down();
    unsafe {
        UserPool::alloc_page(
            PageAlign::floor(init_sp - 1),
            PTEFlags::V | PTEFlags::R | PTEFlags::W | PTEFlags::U,
            &ZERO_PAGE,
        );
    }
    PT_SEMA.up();

    #[cfg(feature = "debug")]
    kprintln!(
        "[USERPROC] User Stack Mapping: (k){:p} -> (u) {:#x}",
        stack_va,
        stack_page_begin
    );
}
