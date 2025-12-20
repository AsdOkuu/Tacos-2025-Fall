use alloc::vec::Vec;

extern "C" {
    pub fn get_kallsyms_num() -> *const i32;
    pub fn get_kallsyms_names() -> *const u8;
    pub fn get_kallsyms_names_index() -> *const u32;
    pub fn get_kallsyms_address() -> *const usize;
}

pub fn name_to_address(name: &str) -> Vec<usize> {
    let mut addresses = Vec::new();
    unsafe {
        let num_symbols = *get_kallsyms_num() as usize;
        let names_ptr = get_kallsyms_names();
        let index_ptr = get_kallsyms_names_index();
        let address_ptr = get_kallsyms_address();

        for i in 0..num_symbols {
            let name_offset = *index_ptr.add(i) as isize;
            let name_ptr = names_ptr.offset(name_offset);
            let mut len = 0;
            while *name_ptr.offset(len) != 0 {
                len += 1;
            }
            let name_slice = core::slice::from_raw_parts(name_ptr, len as usize);
            if let Ok(symbol_name) = core::str::from_utf8(name_slice) {
                if symbol_name == name {
                    let address = *address_ptr.add(i);
                    addresses.push(address);
                }
            }
        }
    }
    addresses
}
