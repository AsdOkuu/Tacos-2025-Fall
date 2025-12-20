#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 1024
#define MAX_SYMBOLS 10000

char line[MAX_LINE_LENGTH];
char addresses[MAX_SYMBOLS][MAX_LINE_LENGTH];
char names[MAX_SYMBOLS][MAX_LINE_LENGTH];

void write_header(FILE *out) {
    fprintf(out, ".section .rodata\n");
    fprintf(out, ".balign 8\n");
    fprintf(out, ".global kallsyms_address\n");
    fprintf(out, "kallsyms_address:\n");
}

void write_addresses(FILE *out, const char addresses[][MAX_LINE_LENGTH], int count) {
    for (int i = 0; i < count; i++) {
        fprintf(out, ".dword 0x%s\n", addresses[i]);
    }
}

void write_names_header(FILE *out) {
    fprintf(out, ".balign 8\n");
    fprintf(out, ".global kallsyms_names\n");
    fprintf(out, "kallsyms_names:\n");
}

void write_names(FILE *out, const char names[][MAX_LINE_LENGTH], int count) {
    for (int i = 0; i < count; i++) {
        fprintf(out, ".asciz \"%s\"\n", names[i]);
    }
}

void write_names_index(FILE *out, const char names[][MAX_LINE_LENGTH], int count) {
    fprintf(out, ".balign 8\n");
    fprintf(out, ".global kallsyms_names_index\n");
    fprintf(out, "kallsyms_names_index:\n");

    int offset = 0;
    for (int i = 0; i < count; i++) {
        fprintf(out, ".word %d\n", offset);
        offset += strlen(names[i]) + 1; // +1 for the null terminator
    }
}

void write_symbol_count(FILE *out, int count) {
    fprintf(out, ".balign 8\n");
    fprintf(out, ".global kallsyms_num\n");
    fprintf(out, "kallsyms_num:\n");
    fprintf(out, ".word %d\n", count);
}

int main() {

    write_header(stdout);
    int symbol_count = 0;

    while (fgets(line, sizeof(line), stdin)) {
        char address[MAX_LINE_LENGTH];
        char type[MAX_LINE_LENGTH];
        char symbol[MAX_LINE_LENGTH];

        // Use sscanf to parse the line
        if (sscanf(line, "%s %s %[^\n]", address, type, symbol) == 3) {
            strncpy(addresses[symbol_count], address, MAX_LINE_LENGTH);
            strncpy(names[symbol_count], symbol, MAX_LINE_LENGTH);
            symbol_count++;
        } else {
            fprintf(stderr, "Warning: Invalid line format: %s", line);
        }
    }

    if (symbol_count == 0) {
        fprintf(stderr, "Error: No valid symbols found in input.\n");
        return EXIT_FAILURE;
    }
    write_addresses(stdout, addresses, symbol_count);
    write_names_header(stdout);
    write_names(stdout, names, symbol_count);
    write_names_index(stdout, names, symbol_count);
    write_symbol_count(stdout, symbol_count);

    return EXIT_SUCCESS;
}