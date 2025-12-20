#!/bin/bash

REAL_LD="rust-lld"

ARGS=()

OUTPUT_DIR="target/riscv64gc-unknown-none-elf/debug"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o)
            OUTPUT_FILE="$2"
            ARGS+=("$1")
            ARGS+=("$2")
            shift 2
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

riscv64-unknown-elf-gcc src/trace/kallsyms_wrap.c -nostdlib -nostartfiles -fPIC -mcmodel=medany -shared -o "$OUTPUT_DIR/kallsyms_wrap.o" -c

$REAL_LD "${ARGS[@]}" "$OUTPUT_DIR/kallsyms_wrap.o"

cd scripts && make all && cd ..

# 5 times
for i in {1..5}; do

nm -n -C $OUTPUT_FILE | scripts/gen_kallsyms > "$OUTPUT_DIR/kallsyms.S"

riscv64-unknown-elf-gcc -nostdlib -nostartfiles -mcmodel=medany -shared -o "$OUTPUT_DIR/kallsyms.o" -c "$OUTPUT_DIR/kallsyms.S"

$REAL_LD "${ARGS[@]}" "$OUTPUT_DIR/kallsyms_wrap.o" "$OUTPUT_DIR/kallsyms.o"

done

nm -n -C "$OUTPUT_FILE" > "$OUTPUT_DIR/kallsyms.txt"

cd scripts && make clean && cd ..

