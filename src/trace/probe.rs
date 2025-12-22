use alloc::{collections::btree_map::BTreeMap, sync::Arc, vec::Vec};
use riscv_decode::decode;
use riscv_decode::Instruction;

use crate::{
    mem::KernelPgTable,
    sync::{Lazy, Mutex, Semaphore},
    thread::current,
    trace::symbol::name_to_address,
    trap::Frame,
};

struct ProbeData {
    pre_handler: Option<fn(&mut Frame)>,
    post_handler: Option<fn(&mut Frame)>,
    addr: usize,
    break_addr: usize,
    insts: [u8; 6],
    enable: bool,
}

impl ProbeData {
    fn new(addr: usize) -> Self {
        Self {
            insts: [0; 6],
            addr: addr,
            break_addr: 0,
            pre_handler: None,
            post_handler: None,
            enable: false,
        }
    }

    fn set_pre_handler(&mut self, handler: fn(&mut Frame)) {
        self.pre_handler = Some(handler);
    }

    fn set_post_handler(&mut self, handler: fn(&mut Frame)) {
        self.post_handler = Some(handler);
    }

    fn enable(&mut self) {
        if !self.enable {
            self.enable = true;
            let len = get_inst_len(unsafe { *(self.addr as *const u8) });
            for i in 0..len {
                self.insts[i] = unsafe { *((self.addr as *const u8).add(i)) };
            }
            self.break_addr = unsafe { self.insts.as_ptr().add(len) as usize };
            self.insts[len] = 0x02;
            self.insts[len + 1] = 0x90;
            kprintln!(
                "[PROBE ENABLE] addr: {:#x}, break_addr: {:#x}, insts: {:x?}",
                self.addr,
                self.break_addr,
                &self.insts[0..len + 2]
            );
            // edit instruction at addr
            if len == 2 {
                let writable = KernelPgTable::get()
                    .read()
                    .get_pte(self.addr)
                    .unwrap()
                    .is_writable();
                KernelPgTable::get()
                    .write()
                    .get_mut_pte(self.addr)
                    .unwrap()
                    .set_writable(true);
                unsafe {
                    *((self.addr as *mut u8).add(0)) = 0x02;
                    *((self.addr as *mut u8).add(1)) = 0x90;
                }
                KernelPgTable::get()
                    .write()
                    .get_mut_pte(self.addr)
                    .unwrap()
                    .set_writable(writable);
            } else if len == 4 {
                let writable0 = KernelPgTable::get()
                    .read()
                    .get_pte(self.addr)
                    .unwrap()
                    .is_writable();
                let writable3 = KernelPgTable::get()
                    .read()
                    .get_pte(self.addr + 3)
                    .unwrap()
                    .is_writable();
                KernelPgTable::get()
                    .write()
                    .get_mut_pte(self.addr)
                    .unwrap()
                    .set_writable(true);
                KernelPgTable::get()
                    .write()
                    .get_mut_pte(self.addr + 3)
                    .unwrap()
                    .set_writable(true);
                unsafe {
                    *((self.addr as *mut u8).add(0)) = 0x73;
                    *((self.addr as *mut u8).add(1)) = 0x00;
                    *((self.addr as *mut u8).add(2)) = 0x10;
                    *((self.addr as *mut u8).add(3)) = 0x00;
                }
                KernelPgTable::get()
                    .write()
                    .get_mut_pte(self.addr)
                    .unwrap()
                    .set_writable(writable0);
                KernelPgTable::get()
                    .write()
                    .get_mut_pte(self.addr + 3)
                    .unwrap()
                    .set_writable(writable3);
            }
        }
    }

    fn disable(&mut self) {
        if self.enable {
            self.enable = false;
            let len = get_inst_len(self.insts[0]);
            for i in 0..len {
                unsafe {
                    *((self.addr as *mut u8).add(i)) = self.insts[i];
                }
            }
        }
    }
}

pub struct Probe {
    inner: Mutex<ProbeData>,
    sema: Semaphore,
}

impl Probe {
    pub fn new(addr: usize) -> Self {
        Self {
            inner: Mutex::new(ProbeData::new(addr)),
            sema: Semaphore::new(1),
        }
    }

    pub fn set_pre_handler(&self, handler: fn(&mut Frame)) {
        self.sema.down();
        {
            let mut data = self.inner.lock();
            data.set_pre_handler(handler);
        }
        self.sema.up();
    }

    pub fn set_post_handler(&self, handler: fn(&mut Frame)) {
        self.sema.down();
        {
            let mut data = self.inner.lock();
            data.set_post_handler(handler);
        }
        self.sema.up();
    }

    fn enable(&self) {
        self.sema.down();
        {
            let mut data = self.inner.lock();
            data.enable();
        }
        self.sema.up();
    }

    fn disable(&self) {
        self.sema.down();
        {
            let mut data = self.inner.lock();
            data.disable();
        }
        self.sema.up();
    }
}

pub fn register_probe(probe: Arc<Probe>) {
    probe.enable();
    let addr = probe.inner.lock().addr;
    ADDR_TO_PROBE.lock().insert(addr, probe.clone());
    let break_addr = probe.inner.lock().break_addr;
    BREAK_ADDR_TO_PROBE.lock().insert(break_addr, probe);
}

pub fn unregister_probe(probe: Arc<Probe>) {
    let addr = probe.inner.lock().addr;
    if let Some(probe) = ADDR_TO_PROBE.lock().remove(&addr) {
        let break_addr = probe.inner.lock().break_addr;
        BREAK_ADDR_TO_PROBE.lock().remove(&break_addr);
    }
    probe.disable();
}

fn get_inst_len(first_byte: u8) -> usize {
    if first_byte & 0b11 != 0b11 {
        2
    } else {
        4
    }
}

fn get_first_inst(insts: &[u8]) -> u32 {
    if get_inst_len(insts[0]) == 2 {
        ((insts[1] as u32) << 8) | (insts[0] as u32)
    } else {
        ((insts[3] as u32) << 24)
            | ((insts[2] as u32) << 16)
            | ((insts[1] as u32) << 8)
            | (insts[0] as u32)
    }
}

static ADDR_TO_PROBE: Lazy<Mutex<BTreeMap<usize, Arc<Probe>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

static BREAK_ADDR_TO_PROBE: Lazy<Mutex<BTreeMap<usize, Arc<Probe>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

pub fn break_handler(frame: &mut Frame) {
    kprintln!("[PROBE] Breakpoint at address {:#x}", frame.sepc);
    let addr = frame.sepc;
    if let Some(probe) = ADDR_TO_PROBE.lock().get_mut(&addr) {
        probe.sema.down();
        // call pre handler
        if let Some(handler) = probe.inner.lock().pre_handler {
            handler(frame);
        }
        let inst = get_first_inst(&probe.inner.lock().insts);
        kprintln!(
            "[PROBE] Emulating instruction {:#x} at address {:#x}, decoded: {:?}",
            inst,
            addr,
            decode(inst)
        );
        // emulate control flow instructions & directly run other instructions
        match decode(inst) {
            Ok(Instruction::Jal(i)) => {
                let offset = i.imm();
                frame.sepc = addr + offset as usize;
                frame.x[i.rd() as usize] = addr + 4;
            }
            Ok(Instruction::Jalr(i)) => {
                let base = frame.x[i.rs1() as usize];
                let offset = i.imm();
                frame.sepc = (base + offset as usize) & !1;
                frame.x[i.rd() as usize] = addr + 4;
            }
            Ok(Instruction::Beq(i)) => {
                kprintln!("beq");
                if frame.x[i.rs1() as usize] == frame.x[i.rs2() as usize] {
                    let offset = i.imm();
                    frame.sepc = addr + offset as usize;
                } else {
                    frame.sepc += 4;
                }
            }
            Ok(Instruction::Bne(i)) => {
                if frame.x[i.rs1() as usize] != frame.x[i.rs2() as usize] {
                    let offset = i.imm();
                    frame.sepc = addr + offset as usize;
                } else {
                    frame.sepc += 4;
                }
            }
            Ok(Instruction::Bge(i)) => {
                if frame.x[i.rs1() as usize] as isize >= frame.x[i.rs2() as usize] as isize {
                    let offset = i.imm();
                    frame.sepc = addr + offset as usize;
                } else {
                    frame.sepc += 4;
                }
            }
            Ok(Instruction::Bgeu(i)) => {
                if frame.x[i.rs1() as usize] >= frame.x[i.rs2() as usize] {
                    let offset = i.imm();
                    frame.sepc = addr + offset as usize;
                } else {
                    frame.sepc += 4;
                }
            }
            Ok(Instruction::Blt(i)) => {
                kprintln!("blt");
                if (frame.x[i.rs1() as usize] as isize) < frame.x[i.rs2() as usize] as isize {
                    let offset = i.imm();
                    frame.sepc = addr + offset as usize;
                } else {
                    frame.sepc += 4;
                }
            }
            Ok(Instruction::Bltu(i)) => {
                if frame.x[i.rs1() as usize] < frame.x[i.rs2() as usize] {
                    let offset = i.imm();
                    frame.sepc = addr + offset as usize;
                } else {
                    frame.sepc += 4;
                }
            }
            _ => {
                kprintln!("no any");
                // set sepc to insts
                frame.sepc = probe.inner.lock().insts.as_ptr() as usize;
                // set kernel pagetable executable
                let insts = probe.inner.lock().insts.as_ptr() as usize;
                KernelPgTable::get()
                    .write()
                    .get_mut_pte(insts)
                    .unwrap()
                    .set_executable(true);
                KernelPgTable::get()
                    .write()
                    .get_mut_pte(insts + 3)
                    .unwrap()
                    .set_executable(true);
                KernelPgTable::get()
                    .write()
                    .get_mut_pte(insts + 5)
                    .unwrap()
                    .set_executable(true);
                return;
            }
        }

        // call post handler when emulated
        if let Some(handler) = probe.inner.lock().post_handler {
            handler(frame);
        }
        probe.sema.up();
    } else if let Some(probe) = BREAK_ADDR_TO_PROBE.lock().get_mut(&addr) {
        let insts = probe.inner.lock().insts.as_ptr() as usize;
        KernelPgTable::get()
            .write()
            .get_mut_pte(insts)
            .unwrap()
            .set_executable(false);
        KernelPgTable::get()
            .write()
            .get_mut_pte(insts + 3)
            .unwrap()
            .set_executable(false);
        KernelPgTable::get()
            .write()
            .get_mut_pte(insts + 5)
            .unwrap()
            .set_executable(false);
        // call post handler
        if let Some(handler) = probe.inner.lock().post_handler {
            handler(frame);
        }
        // set sepc to addr
        frame.sepc = probe.inner.lock().addr;
        frame.sepc += get_inst_len(unsafe { *(probe.inner.lock().addr as *const u8) }) as usize;
        // kprintln!("[PROBE] Returning to address {:#x}", frame.sepc);
        probe.sema.up();
    } else {
        panic!("No probe found at address {:#x}", addr);
    }
}

pub fn probe_symbol(name: &str, offset: isize) -> Vec<Arc<Probe>> {
    let mut probes = Vec::new();
    let addresses = name_to_address(name);
    for addr in addresses {
        let probe = Arc::new(Probe::new(addr + offset as usize));
        probes.push(probe);
    }
    probes
}
