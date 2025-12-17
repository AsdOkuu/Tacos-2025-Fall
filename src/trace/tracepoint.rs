pub trait Traceable {
    fn trace_handler(&self);
}

pub struct Tracepoint {
    enable: bool,
}

impl Tracepoint {
    pub fn new() -> Self {
        Self { enable: false }
    }

    pub fn enable(&mut self) {
        self.enable = true;
    }

    pub fn disable(&mut self) {
        self.enable = false;
    }

    pub fn trace(&self, traceable: &dyn Traceable) {
        if self.enable {
            traceable.trace_handler();
        }
    }
}
