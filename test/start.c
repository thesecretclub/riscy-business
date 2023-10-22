static void exit();
static void relocs();
static void init();
int main();

void _start() {
    relocs();
    init();
    main();
    exit();
    asm volatile("ebreak");
}

#include <stdint.h>

static void exit() {
    register long syscall_id asm("s10") = 10000;  
    asm volatile ("scall" : : "r"(syscall_id));
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

static void relocs() {
    if(*(uint32_t*)__relocs_start != 'ALER') {
        asm volatile("ebreak");
    }

    uintptr_t load_base = (uintptr_t)__base;

    for(Relocation* itr = (Relocation*)(__relocs_start + sizeof(uint32_t)); itr->type != R_RISCV_NONE; itr++) {
        if(itr->type == R_RISCV_64) {
            uint64_t* ptr = (uint64_t*)(uintptr_t)itr->offset;
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

static void init() {
    // Call the init functions
    for(InitFunction* itr = &__init_array_start; itr != &__init_array_end; itr++) {
        (*itr)();
    }
}
