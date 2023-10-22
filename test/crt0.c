static void exit(int exit_code);
static void relocs();
static void init();
int __attribute((noinline)) main();

void _start() {
    relocs();
    init();
    exit(main());
    asm volatile("ebreak");
}

#include <stdint.h>

static __attribute((noinline)) void exit(int exit_code) {
    register uintptr_t a0 asm("a0") = exit_code;
    register uintptr_t a7 asm("a7") = 10000;
    asm volatile (
        "scall"
        : "+r"(a0)
        : "r"(a7)
        : "memory"
    );
}

typedef struct {
    uint8_t type;
    uint32_t offset;
    int64_t addend;
} __attribute__((packed)) Relocation;

extern uint8_t __base[];
extern uint8_t __relocs_start[];

#define LINK_BASE 0x8000000
#define R_RISCV_NONE 0
#define R_RISCV_64 2

static __attribute((noinline)) void relocs() {
    if(*(uint32_t*)__relocs_start != 'ALER') {
        asm volatile("ebreak");
    }

    uintptr_t load_base = (uintptr_t)__base;

    for(Relocation* itr = (Relocation*)(__relocs_start + sizeof(uint32_t)); itr->type != R_RISCV_NONE; itr++) {
        if(itr->type == R_RISCV_64) {
            uint64_t* ptr = (uint64_t*)((uintptr_t)itr->offset - LINK_BASE + load_base);
            *ptr -= LINK_BASE;
            *ptr += load_base;
        } else {
            asm volatile("ebreak");
        }
    }
}

typedef void(*InitFunction)();
extern InitFunction __init_array_start;
extern InitFunction __init_array_end;

static __attribute((optnone)) void init() {
    for(InitFunction* itr = &__init_array_start; itr != &__init_array_end; itr++) {
        (*itr)();
    }
}
