/** Receives no additional command line arguments,
   except for its own executable path. */

#include "user.h"

// int val[1024];

void main(int argc, char* argv[]) {
    assert(argc == 1);
    assert(strcmp("args-none", argv[0]) == 0);
    // printf("val pos: %p\n", val);
}
