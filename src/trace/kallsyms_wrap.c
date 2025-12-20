__attribute__((weak)) extern void kallsyms_num();
__attribute__((weak)) extern void kallsyms_names();
__attribute__((weak)) extern void kallsyms_names_index();
__attribute__((weak)) extern void kallsyms_address();

int* get_kallsyms_num() {
    return (int*) &kallsyms_num;
}

char* get_kallsyms_names() {
    return (char*) &kallsyms_names;
}

unsigned int* get_kallsyms_names_index() {
    return (unsigned int*) &kallsyms_names_index;
}

unsigned long* get_kallsyms_address() {
    return (unsigned long*) &kallsyms_address;
}