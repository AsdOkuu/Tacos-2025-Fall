use core::marker::PhantomData;

pub trait Traceable {
    fn trace_handler(&self);
}

pub struct Tracepoint<T: Traceable> {
    enable: bool,
    _marker: PhantomData<T>,
}

impl<T: Traceable> Tracepoint<T> {
    pub fn new() -> Self {
        Self {
            enable: false,
            _marker: PhantomData,
        }
    }

    pub fn enable(&mut self) {
        self.enable = true;
    }

    pub fn disable(&mut self) {
        self.enable = false;
    }

    pub fn trace(&self, traceable: &T) {
        if self.enable {
            traceable.trace_handler();
        }
    }
}
