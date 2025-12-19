use core::marker::PhantomData;

pub trait Traceable {
    fn trace_handler(&self);
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TraceLevel {
    Debug,
    Info,
    Warn,
    Error,
}

pub struct Tracepoint<T: Traceable> {
    enable: bool,
    level: TraceLevel,
    trace_count: usize,
    _marker: PhantomData<T>,
}

pub static GLOBAL_TRACE_LEVEL: TraceLevel = TraceLevel::Debug;

impl<T: Traceable> Tracepoint<T> {
    pub fn new(level: TraceLevel) -> Self {
        Self {
            enable: false,
            level,
            trace_count: 0,
            _marker: PhantomData,
        }
    }

    pub fn enable(&mut self) {
        self.enable = true;
    }

    pub fn disable(&mut self) {
        self.enable = false;
    }

    pub fn set_level(&mut self, level: TraceLevel) {
        self.level = level;
    }

    pub fn trace(&mut self, traceable: &T) {
        if self.enable && GLOBAL_TRACE_LEVEL >= self.level {
            self.trace_count += 1;
            traceable.trace_handler();
        }
    }

    pub fn trace_count(&self) -> usize {
        self.trace_count
    }
}
