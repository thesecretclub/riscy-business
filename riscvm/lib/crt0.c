static void exit(int exit_code);
static void riscvm_relocs();
void        riscvm_imports() __attribute__((weak));
static void riscvm_init_arrays();
extern int __attribute((noinline)) main();

// NOTE: This function has to be first in the file
void _start()
{
    riscvm_relocs();
    riscvm_imports();
    riscvm_init_arrays();
    exit(main());
    asm volatile("ebreak");
}

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

static __attribute((noinline)) void exit(int exit_code)
{
    register uintptr_t a0 asm("a0") = exit_code;
    register uintptr_t a7 asm("a7") = 10000;
    asm volatile("scall" : "+r"(a0) : "r"(a7) : "memory");
}

typedef struct
{
    uint8_t  type;
    uint32_t offset;
    int64_t  addend;
} __attribute__((packed)) Relocation;

extern uint8_t __base[];
extern uint8_t __relocs_start[];

#define LINK_BASE    0x8000000
#define R_RISCV_NONE 0
#define R_RISCV_64   2

static __attribute((noinline)) void riscvm_relocs()
{
    if (*(uint32_t*)__relocs_start != 'ALER')
    {
        asm volatile("ebreak");
    }

    uintptr_t load_base = (uintptr_t)__base;

    for (Relocation* itr = (Relocation*)(__relocs_start + sizeof(uint32_t)); itr->type != R_RISCV_NONE; itr++)
    {
        if (itr->type == R_RISCV_64)
        {
            uint64_t* ptr = (uint64_t*)((uintptr_t)itr->offset - LINK_BASE + load_base);
            *ptr -= LINK_BASE;
            *ptr += load_base;
        }
        else
        {
            asm volatile("ebreak");
        }
    }
}

typedef void (*InitFunction)();
extern InitFunction __init_array_start;
extern InitFunction __init_array_end;

static __attribute((optnone)) void riscvm_init_arrays()
{
    for (InitFunction* itr = &__init_array_start; itr != &__init_array_end; itr++)
    {
        (*itr)();
    }
}

void riscvm_imports()
{
}

// TODO: are these necessary on all platforms?

void* memset(void* dest, int ch, uintptr_t count)
{
    // TODO: replace with ntdll import?
    for (uintptr_t i = 0; i < count; i++)
    {
        ((uint8_t*)dest)[i] = ch;
    }
    return dest;
}

void* memcpy(void* dest, const void* src, size_t count)
{
    // TODO: replace with ntdll import?
    for (size_t i = 0; i < count; i++)
    {
        ((uint8_t*)dest)[i] = ((uint8_t*)src)[i];
    }
    return dest;
}

void* memmove(void* dest, const void* src, uintptr_t count)
{
    // TODO: replace with ntdll import?
    if (dest < src)
    {
        for (uintptr_t i = 0; i < count; i++)
        {
            ((uint8_t*)dest)[i] = ((uint8_t*)src)[i];
        }
    }
    else
    {
        for (uintptr_t i = count; i > 0; i--)
        {
            ((uint8_t*)dest)[i - 1] = ((uint8_t*)src)[i - 1];
        }
    }
    return dest;
}

#ifdef CRT0_MSVC
#include "crt0-msvc.h"
#endif // CRT0_MSVC
