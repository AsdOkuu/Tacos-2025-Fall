# Makefile to compile gen_kallsyms.c into gen_kallsyms

CC := gcc
CFLAGS := -Wall -Wextra -O2

# Target
all: gen_kallsyms

# Rule to compile gen_kallsyms
gen_kallsyms: gen_kallsyms.c
	$(CC) $(CFLAGS) -o $@ $<

# Clean up build artifacts
clean:
	rm -f gen_kallsyms