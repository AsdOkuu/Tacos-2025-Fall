#[cfg(feature = "test-tracepoint")]
pub mod test_tracepoint {
    use crate::sync::lazy::Lazy;
    use crate::sync::Mutex;
    use crate::trace::TraceLevel;
    use crate::trace::Traceable;
    use crate::trace::Tracepoint;
    struct TestTrace {
        a: u32,
        b: u32,
    }
    impl Traceable for TestTrace {
        fn trace_handler(&self) {
            kprintln!("[TEST TP] a: {}, b: {}", self.a, self.b);
        }
    }
    static TP: Lazy<Mutex<Tracepoint<TestTrace>>> =
        Lazy::new(|| Mutex::new(Tracepoint::<TestTrace>::new(TraceLevel::Debug)));
    fn gcd(a: u32, b: u32) -> u32 {
        TP.lock().trace(&TestTrace { a, b });
        if a == 0 {
            a
        } else if a > b {
            gcd(b, a)
        } else {
            gcd(b % a, a)
        }
    }
    pub fn test_tracepoint() {
        TP.lock().enable();
        gcd(16, 12);
        TP.lock().disable();
        gcd(16, 12);
        kprintln!("[TEST TP] trace count: {}", TP.lock().trace_count());
    }
}

#[cfg(feature = "test-probe")]
pub mod test_probe {
    #[allow(named_asm_labels)]
    fn test_probe_func(a: usize, b: usize) {
        use core::arch::asm;
        // kprintln!("[TEST PROBE] In test_probe function with a={}, b={}", a, b);
        let mut res = 0;
        unsafe {
            asm!("test_probe_flag:", "j test_probe_flag2");
        }
        res += 1;
        unsafe {
            asm!("test_probe_flag2:", "c.addi t0, 5");
        }
        // kprintln!("[TEST PROBE] Inside test_probe function. res={}", res);
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
            kprintln!("[TEST PROBE] Pre handler called.");
        });
        probe.set_post_handler(|frame| {
            kprintln!("[TEST PROBE] Post handler called.");
        });
        register_probe(probe.clone());

        kprintln!("[TEST PROBE] Calling test_probe function.");

        test_probe_func(0, 0);

        kprintln!("[TEST PROBE] test_probe function returned.");

        test_probe_func(0, 1);

        unregister_probe(probe.clone());

        test_probe_func(0, 0);
        test_probe_func(0, 1);

        kprintln!("{:#x}", unregister_probe as usize);
    }

    use crate::sync::lazy::Lazy;
    use crate::sync::Mutex;
    use crate::trace::Probe;
    use alloc::sync::Arc;
    static PRB: Lazy<Arc<Probe>> = Lazy::new(|| Arc::new(Probe::new(test_probe_func as usize)));

    fn test_probe_mt_child() {
        use crate::thread::current;
        use crate::thread::exit;
        use crate::thread::sleep;
        for i in 0..3 {
            test_probe_func(0, 0);
            sleep(1);
        }
        kprintln!("{} end", current().id());
        exit();
    }

    pub fn test_probe_mt() {
        use crate::thread::current;
        use crate::thread::sleep;
        use crate::thread::spawn;
        use crate::trace::register_probe;
        use crate::trace::unregister_probe;
        kprintln!("{:#x}", unregister_probe as usize);
        PRB.set_pre_handler(|_frame| {
            kprintln!("[TEST PROBE] {} {} in", current().name(), current().id())
        });
        register_probe(PRB.clone());
        for i in 0..10 {
            spawn("Child", test_probe_mt_child);
        }
        sleep(13);
        let prb = PRB.clone();
        unregister_probe(prb);
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
            kprintln!("[TEST RETPROBE] Equal.");
            return 1;
        }
        kprintln!("[TEST RETPROBE] Not equal.");
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

    use crate::thread::exit;
    use crate::thread::sleep;
    use crate::thread::spawn;
    use sync::Lazy;
    use trap::Frame;

    static RPRB: Lazy<Arc<RetProbe>> = Lazy::new(|| {
        Arc::new(RetProbe::new(
            recur as usize,
            -1,
            Some(|frame: &mut Frame| {
                kprintln!(
                    "{} {}: height: {}",
                    current().name(),
                    current().id(),
                    frame.x[10]
                );
            }),
        ))
    });

    fn recur(depth: u32) -> u32 {
        if depth == 0 {
            0
        } else {
            let res = recur(depth - 1);
            sleep(1);
            res + 1
        }
    }

    fn test_retprobe_mt_child() {
        recur(3);
        exit();
    }

    pub fn test_retprobe_mt() {
        register_retprobe(RPRB.clone());
        for _ in 0..10 {
            spawn("RetChild", test_retprobe_mt_child);
            sleep(1);
        }
        sleep(5);
        unregister_retprobe(RPRB.clone());
    }
}
