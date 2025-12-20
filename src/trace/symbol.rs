extern "C" {
    pub fn get_kallsyms_num() -> *const i32;
    pub fn get_kallsyms_names() -> *const u8;
    pub fn get_kallsyms_names_index() -> *const u32;
    pub fn get_kallsyms_address() -> *const usize;
}
