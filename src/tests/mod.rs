#[cfg(feature = "test-probe")]
pub mod test_probe {
    #[allow(named_asm_labels)]
    fn test_probe_func(a: usize, b: usize) {
        use core::arch::asm;
        kprintln!("[TEST PROBE] In test_probe function with a={}, b={}", a, b);
        let mut res = 0;
        unsafe {
            asm!("test_probe_flag:", "beq t0, t1, test_probe_flag2", in("t0") a, in("t1") b);
        }
        res += 1;
        unsafe {
            asm!("test_probe_flag2:", "c.addi t0, 5");
        }
        kprintln!("[TEST PROBE] Inside test_probe function. res={}", res);
    }

    extern "C" {
        fn test_probe_flag();
    }

    pub fn test_probe() {
        use crate::trace::probe_symbol;
        use crate::trace::unregister_probe;
        use alloc::sync::Arc;
        use trace::register_probe;
        use trace::Probe;

        // let probe_addr = test_probe_flag as usize;
        // let probe = Arc::new(Probe::new(probe_addr));
        let probes = probe_symbol("test_probe_flag", 0);
        let probe = probes.get(0).unwrap();
        probe.set_pre_handler(|frame| {
            kprintln!("[PROBE] Pre handler called.");
        });
        probe.set_post_handler(|frame| {
            kprintln!("[PROBE] Post handler called.");
        });
        register_probe(probe.clone());

        kprintln!("[TEST PROBE] Calling test_probe function.");

        test_probe_func(10, 10);

        kprintln!("[TEST PROBE] test_probe function returned.");

        test_probe_func(10, 12);

        unregister_probe(probe.clone());

        test_probe_func(10, 10);
        test_probe_func(10, 12);
    }
}

#[cfg(feature = "test-kallsyms")]
pub mod test_kallsyms {
    use crate::trace;
    use core::slice;
    use core::str;
    pub fn test_kallsyms() {
        kprintln!("[TEST KALLSYMS]");
        kprintln!("[TEST KALLSYMS] Number of symbols: {}", unsafe {
            *trace::symbol::get_kallsyms_num()
        });
        kprintln!("[TEST KALLSYMS] The first name: {}", unsafe {
            let name_ptr = trace::symbol::get_kallsyms_names();
            let index_ptr = trace::symbol::get_kallsyms_names_index();
            let sname_ptr = name_ptr.add(*index_ptr as usize);
            let mut len = 0;
            while *sname_ptr.add(len) != 0 {
                len += 1;
            }
            let name_slice = slice::from_raw_parts(sname_ptr, len);
            str::from_utf8(name_slice).unwrap()
        });
        kprintln!("[TEST KALLSYMS] The first address: {:#x}", unsafe {
            let addr_ptr = trace::symbol::get_kallsyms_address();
            *addr_ptr as usize
        });
        kprintln!("[TEST KALLSYMS] Lookup 'core::option::Option<T>::map':");
        let addresses = trace::symbol::name_to_address("core::option::Option<T>::map");
        kprintln!("[TEST KALLSYMS] Addresses found: {:?}", addresses);
    }
}

#[cfg(feature = "test-retprobe")]
pub mod test_retprobe {
    use crate::thread::current;
    use crate::trace::{register_retprobe, unregister_retprobe, RetProbe};
    use alloc::sync::Arc;

    fn test_retprobe_func(a: usize, b: usize) -> usize {
        if a == b {
            kprintln!("[TEST RETPROBE] Ret: 1");
            return 1;
        }
        kprintln!("[TEST RETPROBE] Ret: 99");
        return 99;
    }

    fn test_retprobe_gcd(a: usize, b: usize) -> usize {
        kprintln!("[TEST RETPROBE] gcd(a: {},b: {})", a, b);
        if a == 0 {
            return b;
        } else if a > b {
            return test_retprobe_gcd(b, a);
        }
        return test_retprobe_gcd(b % a, a);
    }

    pub fn test_retprobe() {
        kprintln!(
            "[TEST RETPROBE] test_retprobe: {:#x}",
            test_retprobe as usize
        );
        let retprobe = Arc::new(RetProbe::new(
            test_retprobe_func as usize,
            current().id(),
            Some(|_frame| kprintln!("[TEST RETPROBE] Return from func.")),
        ));
        register_retprobe(retprobe.clone());
        test_retprobe_func(1, 1);
        test_retprobe_func(1, 2);
        unregister_retprobe(retprobe.clone());
        test_retprobe_func(1, 1);
        test_retprobe_func(1, 2);

        let gcdprobe = Arc::new(RetProbe::new(
            test_retprobe_gcd as usize,
            current().id(),
            Some(|frame| kprintln!("[TEST RETPROBE] Return from gcd. res: {}", frame.x[10])),
        ));
        register_retprobe(gcdprobe.clone());
        test_retprobe_gcd(16, 12);
        unregister_retprobe(gcdprobe.clone());
        test_retprobe_gcd(16, 12);
    }
}
