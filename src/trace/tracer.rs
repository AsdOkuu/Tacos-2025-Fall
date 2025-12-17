use crate::trace::tracepoint::*;

pub struct DefaultTracer;

impl Traceable for DefaultTracer {
    fn trace_handler(&self) {
        // Default trace handling logic.
        kprintln!("Default trace handler invoked.");
    }
}
