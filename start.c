void _init();
int main();

void _start() {
    _init();
    main();
    // TODO: exit syscall
    while(1) {}
}

// https://github.com/eblot/newlib/blob/master/newlib/libc/misc/init.c

#include <stdint.h>

typedef void(*InitFunction)();

extern InitFunction __init_array_start;
extern InitFunction __init_array_end;

void _init() {
    for(InitFunction* itr = &__init_array_start; itr != &__init_array_end; itr++)
        (*itr)();
}
