#define _CRT_SECURE_NO_WARNINGS

#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <wchar.h>

#include "riscvm.h"

#pragma section(".vmcode", read, write)
__declspec(align(4096)) uint8_t g_code[0x10000];

#pragma section(".vmstack", read, write)
__declspec(align(4096)) uint8_t g_stack[0x10000];

void riscvm_loadfile(riscvm_ptr self, const char* filename)
{
    FILE* fp = fopen(filename, "rb");
    if ((!(fp != NULL)))
    {
        puts("failed to open file");
    }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (size > sizeof(g_code))
    {
        puts("loaded code too big!");
        exit(EXIT_FAILURE);
    }
    fread(g_code, size, 1, fp);
    fclose(fp);
    reg_write(reg_sp, (uint64_t)&g_stack[sizeof(g_stack) - 0x10]);
    self->pc = (int64_t)g_code;
}

uint32_t riscvm_fetch(riscvm_ptr self)
{
    uint32_t data;
    memcpy(&data, (const void*)self->pc, sizeof(data));
    return data;
}

int8_t riscvm_read_int8(riscvm_ptr self, uint64_t addr)
{
    int8_t data;
    memcpy(&data, (const void*)addr, sizeof(data));
    return data;
}

int16_t riscvm_read_int16(riscvm_ptr self, uint64_t addr)
{
    int16_t data;
    memcpy(&data, (const void*)addr, sizeof(data));
    return data;
}

int32_t riscvm_read_int32(riscvm_ptr self, uint64_t addr)
{
    int32_t data;
    memcpy(&data, (const void*)addr, sizeof(data));
    return data;
}

int64_t riscvm_read_int64(riscvm_ptr self, uint64_t addr)
{
    int64_t data;
    memcpy(&data, (const void*)addr, sizeof(data));
    return data;
}

uint8_t riscvm_read_uint8(riscvm_ptr self, uint64_t addr)
{
    uint8_t data;
    memcpy(&data, (const void*)addr, sizeof(data));
    return data;
}

uint16_t riscvm_read_uint16(riscvm_ptr self, uint64_t addr)
{
    uint16_t data;
    memcpy(&data, (const void*)addr, sizeof(data));
    return data;
}

uint32_t riscvm_read_uint32(riscvm_ptr self, uint64_t addr)
{
    uint32_t data;
    memcpy(&data, (const void*)addr, sizeof(data));
    return data;
}

void* riscvm_getptr(riscvm_ptr self, uint64_t addr)
{
    return (void*)addr;
}

void riscvm_write_uint8(riscvm_ptr self, uint64_t addr, uint8_t val)
{
    memcpy((void*)addr, &val, sizeof(val));
}

void riscvm_write_uint16(riscvm_ptr self, uint64_t addr, uint16_t val)
{
    memcpy((void*)addr, &val, sizeof(val));
}

void riscvm_write_uint32(riscvm_ptr self, uint64_t addr, uint32_t val)
{
    memcpy((void*)addr, &val, sizeof(val));
}

void riscvm_write_uint64(riscvm_ptr self, uint64_t addr, uint64_t val)
{
    memcpy((void*)addr, &val, sizeof(val));
}

ALWAYS_INLINE int32_t bit_signer(uint32_t field, uint32_t size)
{
    return (field & (1U << (size - 1))) ? (int32_t)(field | (0xFFFFFFFFU << size)) : (int32_t)field;
}

ALWAYS_INLINE uint32_t syscall_0_stub(uint32_t id)
{
    register void* a1 asm("r10");
    void*          a2;
    register void* a3 asm("r8");
    register void* a4 asm("r9");

    void*          unused_output;
    register void* unused_output2 asm("r11");

    uint32_t status;
    asm volatile("syscall\n"
                 : "=a"(status), "=r"(a1), "=d"(a2), "=r"(a3), "=r"(a4), "=c"(unused_output), "=r"(unused_output2)
                 : "a"(id)
                 : "memory", "cc");
    return status;
}

ALWAYS_INLINE uint32_t syscall_1_stub(uint32_t id, uint64_t _1)
{
    register uint64_t a1 asm("r10") = _1;
    void*             a2;
    register void*    a3 asm("r8");
    register void*    a4 asm("r9");

    void*          unused_output;
    register void* unused_output2 asm("r11");

    uint32_t status;
    asm volatile("syscall\n"
                 : "=a"(status), "=r"(a1), "=d"(a2), "=r"(a3), "=r"(a4), "=c"(unused_output), "=r"(unused_output2)
                 : "a"(id), "r"(a1)
                 : "memory", "cc");
    return status;
}

ALWAYS_INLINE uint32_t syscall_2_stub(uint32_t id, uint64_t _1, uint64_t _2)
{
    register uint64_t a1 asm("r10") = _1;
    register void*    a3 asm("r8");
    register void*    a4 asm("r9");

    void*          unused_output;
    register void* unused_output2 asm("r11");

    uint32_t status;
    asm volatile("syscall\n"
                 : "=a"(status), "=r"(a1), "=d"(_2), "=r"(a3), "=r"(a4), "=c"(unused_output), "=r"(unused_output2)
                 : "a"(id), "r"(a1), "d"(_2)
                 : "memory", "cc");
    return status;
}

ALWAYS_INLINE uint32_t syscall_3_stub(uint32_t id, uint64_t _1, uint64_t _2, uint64_t _3)
{
    register uint64_t a1 asm("r10") = _1;
    register uint64_t a3 asm("r8")  = _3;
    register void*    a4 asm("r9");

    void*          unused_output;
    register void* unused_output2 asm("r11");

    uint32_t status;
    asm volatile("syscall\n"
                 : "=a"(status), "=r"(a1), "=d"(_2), "=r"(a3), "=r"(a4), "=c"(unused_output), "=r"(unused_output2)
                 : "a"(id), "r"(a1), "d"(_2), "r"(a3)
                 : "memory", "cc");
    return status;
}

ALWAYS_INLINE uint32_t syscall_4_stub(uint32_t id, uint64_t _1, uint64_t _2, uint64_t _3, uint64_t _4)
{
    register uint64_t a1 asm("r10") = _1;
    register uint64_t a3 asm("r8")  = _3;
    register uint64_t a4 asm("r9")  = _4;

    void*          unused_output;
    register void* unused_output2 asm("r11");

    uint32_t status;
    asm volatile("syscall\n"
                 : "=a"(status), "=r"(a1), "=d"(_2), "=r"(a3), "=r"(a4), "=c"(unused_output), "=r"(unused_output2)
                 : "a"(id), "r"(a1), "d"(_2), "r"(a3), "r"(a4)
                 : "memory", "cc");
    return status;
}

ALWAYS_INLINE uint32_t syscall_5_stub(uint32_t id, uint64_t _1, uint64_t _2, uint64_t _3, uint64_t _4, uint64_t _5)
{
    register uint64_t a1 asm("r10") = _1;
    register uint64_t a3 asm("r8")  = _3;
    register uint64_t a4 asm("r9")  = _4;

    void*          unused_output;
    register void* unused_output2 asm("r11");

    uint32_t status;
    asm volatile("sub $48, %%rsp\n"
                 "movq %[a5], 40(%%rsp)\n"
                 "syscall\n"
                 "add $48, %%rsp"
                 : "=a"(status), "=r"(a1), "=d"(_2), "=r"(a3), "=r"(a4), "=c"(unused_output), "=r"(unused_output2)
                 : "a"(id), "r"(a1), "d"(_2), "r"(a3), "r"(a4), [a5] "re"((void*)(_5))
                 : "cc");
    return status;
}

ALWAYS_INLINE uint32_t
syscall_6_stub(uint32_t id, uint64_t _1, uint64_t _2, uint64_t _3, uint64_t _4, uint64_t _5, uint64_t _6)
{
    register uint64_t a1 asm("r10") = _1;
    register uint64_t a3 asm("r8")  = _3;
    register uint64_t a4 asm("r9")  = _4;

    void*             unused_output;
    register uint64_t unused_output2 asm("r11");

    uint32_t status;
    asm volatile("sub $64, %%rsp\n"
                 "movq %[a5], 40(%%rsp)\n"
                 "movq %[a6], 48(%%rsp)\n"
                 "syscall\n"
                 "add $64, %%rsp"
                 : "=a"(status), "=r"(a1), "=d"(_2), "=r"(a3), "=r"(a4), "=c"(unused_output), "=r"(unused_output2)
                 : "a"(id), "r"(a1), "d"(_2), "r"(a3), "r"(a4), [a5] "re"(_5), [a6] "re"(_6)
                 : "memory", "cc");
    return status;
}

ALWAYS_INLINE uint32_t syscall_7_stub(
    uint32_t id, uint64_t _1, uint64_t _2, uint64_t _3, uint64_t _4, uint64_t _5, uint64_t _6, uint64_t _7
)
{
    register uint64_t a1 asm("r10") = _1;
    register uint64_t a3 asm("r8")  = _3;
    register uint64_t a4 asm("r9")  = _4;

    void*             unused_output;
    register uint64_t unused_output2 asm("r11");

    uint32_t status;
    asm volatile("sub $64, %%rsp\n"
                 "movq %[a5], 40(%%rsp)\n"
                 "movq %[a6], 48(%%rsp)\n"
                 "movq %[a7], 56(%%rsp)\n"
                 "syscall\n"
                 "add $64, %%rsp"
                 : "=a"(status), "=r"(a1), "=d"(_2), "=r"(a3), "=r"(a4), "=c"(unused_output), "=r"(unused_output2)
                 : "a"(id), "r"(a1), "d"(_2), "r"(a3), "r"(a4), [a5] "re"(_5), [a6] "re"(_6), [a7] "re"(_7)
                 : "memory", "cc");
    return status;
}

ALWAYS_INLINE uint32_t syscall_8_stub(
    uint32_t id, uint64_t _1, uint64_t _2, uint64_t _3, uint64_t _4, uint64_t _5, uint64_t _6, uint64_t _7, uint64_t _8
)
{
    register uint64_t a1 asm("r10") = _1;
    register uint64_t a3 asm("r8")  = _3;
    register uint64_t a4 asm("r9")  = _4;

    void*             unused_output;
    register uint64_t unused_output2 asm("r11");

    uint32_t status;
    asm volatile(
        "sub $80, %%rsp\n"
        "movq %[a5], 40(%%rsp)\n"
        "movq %[a6], 48(%%rsp)\n"
        "movq %[a7], 56(%%rsp)\n"
        "movq %[a8], 64(%%rsp)\n"
        "syscall\n"
        "add $80, %%rsp"
        : "=a"(status), "=r"(a1), "=d"(_2), "=r"(a3), "=r"(a4), "=c"(unused_output), "=r"(unused_output2)
        : "a"(id), "r"(a1), "d"(_2), "r"(a3), "r"(a4), [a5] "re"(_5), [a6] "re"(_6), [a7] "re"(_7), [a8] "re"(_8)
        : "memory", "cc"
    );
    return status;
}

ALWAYS_INLINE uint32_t syscall_9_stub(
    uint32_t id, uint64_t _1, uint64_t _2, uint64_t _3, uint64_t _4, uint64_t _5, uint64_t _6, uint64_t _7, uint64_t _8, uint64_t _9
)
{
    register uint64_t a1 asm("r10") = _1;
    register uint64_t a3 asm("r8")  = _3;
    register uint64_t a4 asm("r9")  = _4;

    void*             unused_output;
    register uint64_t unused_output2 asm("r11");

    uint32_t status;
    asm volatile(
        "sub $80, %%rsp\n"
        "movq %[a5], 40(%%rsp)\n"
        "movq %[a6], 48(%%rsp)\n"
        "movq %[a7], 56(%%rsp)\n"
        "movq %[a8], 64(%%rsp)\n"
        "movq %[a9], 72(%%rsp)\n"
        "syscall\n"
        "add $80, %%rsp"
        : "=a"(status), "=r"(a1), "=d"(_2), "=r"(a3), "=r"(a4), "=c"(unused_output), "=r"(unused_output2)
        : "a"(id), "r"(a1), "d"(_2), "r"(a3), "r"(a4), [a5] "re"(_5), [a6] "re"(_6), [a7] "re"(_7), [a8] "re"(_8), [a9] "re"(_9)
        : "memory", "cc"
    );
    return status;
}

ALWAYS_INLINE uint32_t syscall_10_stub(
    uint32_t id,
    uint64_t _1,
    uint64_t _2,
    uint64_t _3,
    uint64_t _4,
    uint64_t _5,
    uint64_t _6,
    uint64_t _7,
    uint64_t _8,
    uint64_t _9,
    uint64_t _10
)
{
    register uint64_t a1 asm("r10") = _1;
    register uint64_t a3 asm("r8")  = _3;
    register uint64_t a4 asm("r9")  = _4;

    void*             unused_output;
    register uint64_t unused_output2 asm("r11");

    uint32_t status;
    asm volatile(
        "sub $96, %%rsp\n"
        "movq %[a5], 40(%%rsp)\n"
        "movq %[a6], 48(%%rsp)\n"
        "movq %[a7], 56(%%rsp)\n"
        "movq %[a8], 64(%%rsp)\n"
        "movq %[a9], 72(%%rsp)\n"
        "movq %[a10], 80(%%rsp)\n"
        "syscall\n"
        "add $96, %%rsp"
        : "=a"(status), "=r"(a1), "=d"(_2), "=r"(a3), "=r"(a4), "=c"(unused_output), "=r"(unused_output2)
        : "a"(id), "r"(a1), "d"(_2), "r"(a3), "r"(a4), [a5] "re"(_5), [a6] "re"(_6), [a7] "re"(_7), [a8] "re"(_8), [a9] "re"(_9), [a10] "re"(_10)
        : "memory", "cc"
    );
    return status;
}

ALWAYS_INLINE uint32_t syscall_11_stub(
    uint32_t id,
    uint64_t _1,
    uint64_t _2,
    uint64_t _3,
    uint64_t _4,
    uint64_t _5,
    uint64_t _6,
    uint64_t _7,
    uint64_t _8,
    uint64_t _9,
    uint64_t _10,
    uint64_t _11
)
{
    register uint64_t a1 asm("r10") = _1;
    register uint64_t a3 asm("r8")  = _3;
    register uint64_t a4 asm("r9")  = _4;

    void*             unused_output;
    register uint64_t unused_output2 asm("r11");

    uint32_t status;
    asm volatile(
        "sub $96, %%rsp\n"
        "movq %[a5], 40(%%rsp)\n"
        "movq %[a6], 48(%%rsp)\n"
        "movq %[a7], 56(%%rsp)\n"
        "movq %[a8], 64(%%rsp)\n"
        "movq %[a9], 72(%%rsp)\n"
        "movq %[a10], 80(%%rsp)\n"
        "movq %[a11], 88(%%rsp)\n"
        "syscall\n"
        "add $96, %%rsp"
        : "=a"(status), "=r"(a1), "=d"(_2), "=r"(a3), "=r"(a4), "=c"(unused_output), "=r"(unused_output2)
        : "a"(id), "r"(a1), "d"(_2), "r"(a3), "r"(a4), [a5] "re"(_5), [a6] "re"(_6), [a7] "re"(_7), [a8] "re"(_8), [a9] "re"(_9), [a10] "re"(_10), [a11] "re"(_11)
        : "memory", "cc"
    );
    return status;
}

ALWAYS_INLINE uint32_t syscall_12_stub(
    uint32_t id,
    uint64_t _1,
    uint64_t _2,
    uint64_t _3,
    uint64_t _4,
    uint64_t _5,
    uint64_t _6,
    uint64_t _7,
    uint64_t _8,
    uint64_t _9,
    uint64_t _10,
    uint64_t _11,
    uint64_t _12
)
{
    register uint64_t a1 asm("r10") = _1;
    register uint64_t a3 asm("r8")  = _3;
    register uint64_t a4 asm("r9")  = _4;

    void*             unused_output;
    register uint64_t unused_output2 asm("r11");

    uint32_t status;
    asm volatile("sub $112, %%rsp\n"
                 "movq %[a5], 40(%%rsp)\n"
                 "movq %[a6], 48(%%rsp)\n"
                 "movq %[a7], 56(%%rsp)\n"
                 "movq %[a8], 64(%%rsp)\n"
                 "movq %[a9], 72(%%rsp)\n"
                 "movq %[a10], 80(%%rsp)\n"
                 "movq %[a11], 88(%%rsp)\n"
                 "movq %[a12], 96(%%rsp)\n"
                 "syscall\n"
                 "add $112, %%rsp"
                 : "=a"(status), "=r"(a1), "=d"(_2), "=r"(a3), "=r"(a4), "=c"(unused_output), "=r"(unused_output2)
                 : "a"(id),
                   "r"(a1),
                   "d"(_2),
                   "r"(a3),
                   "r"(a4),
                   [a5] "re"(_5),
                   [a6] "re"(_6),
                   [a7] "re"(_7),
                   [a8] "re"(_8),
                   [a9] "re"(_9),
                   [a10] "re"(_10),
                   [a11] "re"(_11),
                   [a12] "re"(_12)
                 : "memory", "cc");
    return status;
}

ALWAYS_INLINE uint32_t syscall_13_stub(
    uint32_t id,
    uint64_t _1,
    uint64_t _2,
    uint64_t _3,
    uint64_t _4,
    uint64_t _5,
    uint64_t _6,
    uint64_t _7,
    uint64_t _8,
    uint64_t _9,
    uint64_t _10,
    uint64_t _11,
    uint64_t _12,
    uint64_t _13
)
{
    register uint64_t a1 asm("r10") = _1;
    register uint64_t a3 asm("r8")  = _3;
    register uint64_t a4 asm("r9")  = _4;

    void*             unused_output;
    register uint64_t unused_output2 asm("r11");

    uint32_t status;
    asm volatile("sub $112, %%rsp\n"
                 "movq %[a5], 40(%%rsp)\n"
                 "movq %[a6], 48(%%rsp)\n"
                 "movq %[a7], 56(%%rsp)\n"
                 "movq %[a8], 64(%%rsp)\n"
                 "movq %[a9], 72(%%rsp)\n"
                 "movq %[a10], 80(%%rsp)\n"
                 "movq %[a11], 88(%%rsp)\n"
                 "movq %[a12], 96(%%rsp)\n"
                 "movq %[a13], 104(%%rsp)\n"
                 "syscall\n"
                 "add $112, %%rsp"
                 : "=a"(status), "=r"(a1), "=d"(_2), "=r"(a3), "=r"(a4), "=c"(unused_output), "=r"(unused_output2)
                 : "a"(id),
                   "r"(a1),
                   "d"(_2),
                   "r"(a3),
                   "r"(a4),
                   [a5] "re"(_5),
                   [a6] "re"(_6),
                   [a7] "re"(_7),
                   [a8] "re"(_8),
                   [a9] "re"(_9),
                   [a10] "re"(_10),
                   [a11] "re"(_11),
                   [a12] "re"(_12),
                   [a13] "re"(_13)
                 : "memory", "cc");
    return status;
}

uint64_t riscvm_handle_syscall(riscvm_ptr self, uint64_t code)
{
    trace("syscall %llu\n", code);
    switch (code)
    {
    case 10000:
    {
        self->running  = false;
        self->exitcode = reg_read(reg_a0);
        break;
    }
    case 10001:
    {
        panic("aborted!");
        break;
    }
    case 10006:
    {
        void* src  = riscvm_getptr(self, reg_read(reg_a0));
        void* dest = riscvm_getptr(self, reg_read(reg_a1));
        void* res  = memcpy(dest, src, (size_t)reg_read(reg_a2));
        return (uint64_t)res;
    }
    case 10007:
    {
        void* dest = riscvm_getptr(self, reg_read(reg_a0));
        void* res  = memset(dest, (int)reg_read(reg_a1), (size_t)reg_read(reg_a2));
        return (uint64_t)res;
    }
    case 10008:
    {
        void* src  = riscvm_getptr(self, reg_read(reg_a0));
        void* dest = riscvm_getptr(self, reg_read(reg_a1));
        void* res  = memmove(dest, src, (size_t)reg_read(reg_a2));
        return (uint64_t)res;
    }
    case 10009:
    {
        void* src1 = riscvm_getptr(self, reg_read(reg_a0));
        void* src2 = riscvm_getptr(self, reg_read(reg_a1));
        return (uint64_t)memcmp(src1, src2, (size_t)reg_read(reg_a2));
    }
    case 10100:
    {
        wchar_t* s = (wchar_t*)riscvm_getptr(self, reg_read(reg_a0));
        if (s != NULL)
        {
            wprintf(L"%ls\n", s);
        }
        break;
    }
    case 10101:
    {
        char* s = (char*)riscvm_getptr(self, reg_read(reg_a0));
        if (s != NULL)
        {
            puts(s);
        }
        break;
    }
    case 10102:
    {
        printf("value: %lli\n", reg_read(reg_a0));
        break;
    }
    case 10103:
    {
        printf("value: 0x%llx\n", reg_read(reg_a0));
        break;
    }
    case 10104:
    {
        printf("%s: 0x%llx\n", reg_read(reg_a0), reg_read(reg_a1));
        break;
    }
    case 20000:
    {
        uint64_t  func_addr = reg_read(reg_a0);
        uint64_t* args      = (uint64_t*)riscvm_getptr(self, reg_read(reg_a1));

        using syscall_fn = uint64_t(__fastcall*)(
            uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t
        );

        syscall_fn fn = (syscall_fn)func_addr;
        return fn(
            args[0],
            args[1],
            args[2],
            args[3],
            args[4],
            args[5],
            args[6],
            args[7],
            args[8],
            args[9],
            args[10],
            args[11],
            args[12]);
    }
    case 20001:
    {
        // return PEB
        return __readgsqword(0x60);
    }
    default:
    {
        panic("illegal system call %llu (0x%llX)\n", code, code);
        break;
    }
    }
    return 0U;
}
int64_t riscvm_shl_int64(int64_t a, int64_t b)
{
    if (LIKELY(b >= 0 && b < 64))
    {
        return ((uint64_t)a) << b;
    }
    else if (UNLIKELY(b < 0 && b > -64))
    {
        return (uint64_t)a >> -b;
    }
    else
    {
        return 0;
    }
}
int64_t riscvm_shr_int64(int64_t a, int64_t b)
{
    if (LIKELY(b >= 0 && b < 64))
    {
        return (uint64_t)a >> b;
    }
    else if (UNLIKELY(b < 0 && b > -64))
    {
        return (uint64_t)a << -b;
    }
    else
    {
        return 0;
    }
}
int64_t riscvm_asr_int64(int64_t a, int64_t b)
{
    if (LIKELY(b >= 0 && b < 64))
    {
        return a >> b;
    }
    else if (UNLIKELY(b >= 64))
    {
        return a < 0 ? -1 : 0;
    }
    else if (UNLIKELY(b < 0 && b > -64))
    {
        return a << -b;
    }
    else
    {
        return 0;
    }
}
__int128 riscvm_shr_int128(__int128 a, __int128 b)
{
    if (LIKELY(b >= 0 && b < 128))
    {
        return (unsigned __int128)a >> b;
    }
    else if (UNLIKELY(b < 0 && b > -128))
    {
        return (unsigned __int128)a << -b;
    }
    else
    {
        return 0;
    }
}
void riscvm_execute(riscvm_ptr self, Instruction inst)
{
    switch (inst.opcode)
    {
    case 0b0000011: // load memory
    {
        uint64_t addr = reg_read(inst.itype.rs1) + inst.itype.imm;
        int64_t  val  = 0;
        switch (inst.itype.funct3)
        {
        case 0b000: // lb
        {
            val = riscvm_read_int8(self, addr);
            break;
        }
        case 0b001: // lh
        {
            val = riscvm_read_int16(self, addr);
            break;
        }
        case 0b010: // lw
        {
            val = riscvm_read_int32(self, addr);
            break;
        }
        case 0b011: // ld
        {
            val = riscvm_read_int64(self, addr);
            break;
        }
        case 0b100: // lbu
        {
            val = riscvm_read_uint8(self, addr);
            break;
        }
        case 0b101: // lhu
        {
            val = riscvm_read_uint16(self, addr);
            break;
        }
        case 0b110: // lwu
        {
            val = riscvm_read_uint32(self, addr);
            break;
        }
        default:
        {
            panic("illegal load instruction");
            break;
        }
        }
        if (LIKELY(inst.itype.rd != reg_zero))
        {
            reg_write(inst.itype.rd, (uint64_t)val);
        }
        break;
    }
    case 0b100011: // store memory
    {
        int32_t  imm  = bit_signer((inst.stype.imm7 << 5) | inst.stype.imm5, 12);
        uint64_t addr = reg_read(inst.stype.rs1) + imm;
        uint64_t val  = reg_read(inst.stype.rs2);
        switch (inst.stype.funct3)
        {
        case 0x0:
        {
            riscvm_write_uint8(self, addr, (uint8_t)val);
            break;
        }
        case 0x1:
        {
            riscvm_write_uint16(self, addr, (uint16_t)val);
            break;
        }
        case 0x2:
        {
            riscvm_write_uint32(self, addr, (uint32_t)val);
            break;
        }
        case 0x3:
        {
            riscvm_write_uint64(self, addr, val);
            break;
        }
        default:
        {
            panic("illegal store instruction");
            break;
        }
        }
        break;
    }
    case 0b0010011: // arithmetic
    {
        int64_t imm = bit_signer(inst.itype.imm, 12);
        int64_t val = reg_read(inst.itype.rs1);
        switch (inst.itype.funct3)
        {
        case 0b000: // addi
        {
            val = val + imm;
            break;
        }
        case 0b001: // slli
        {
            val = riscvm_shl_int64(val, inst.rwtype.rs2);
            break;
        }
        case 0b010: // slti
        {
            if (val < imm)
            {
                val = 1;
            }
            else
            {
                val = 0;
            }
            break;
        }
        case 0b011: // sltiu
        {
            if ((uint64_t)val < (uint64_t)imm)
            {
                val = 1;
            }
            else
            {
                val = 0;
            }
            break;
        }
        case 0b100: // xori
        {
            val = val ^ imm;
            break;
        }
        case 0b101: // srli
        {
            if (inst.rwtype.shamt)
            {
                val = riscvm_asr_int64(val, inst.rwtype.rs2);
            }
            else
            {
                val = riscvm_shr_int64(val, inst.rwtype.rs2);
            }
            break;
        }
        case 0b110: // ori
        {
            val = val | imm;
            break;
        }
        case 0b111: // andi
        {
            val = val & imm;
            break;
        }
        default:
        {
            panic("illegal op-imm instruction");
            break;
        }
        }
        if (LIKELY(inst.itype.rd != reg_zero))
        {
            reg_write(inst.itype.rd, val);
        }
        break;
    }
    case 0b0011011: // rv64i arithmetic
    {
        int64_t imm = bit_signer(inst.itype.imm, 12);
        int64_t val = reg_read(inst.itype.rs1);
        switch (inst.itype.funct3)
        {
        case 0b000: // addiw
        {
            val = (int64_t)(int32_t)(val + imm);
            break;
        }
        case 0b001: // slliw
        {
            val = (int64_t)(int32_t)riscvm_shl_int64(val, imm);
            break;
        }
        case 0b101: // srliw/sraiw
        {
            if (inst.rwtype.shamt)
            {
                val = (int64_t)(int32_t)riscvm_asr_int64(val, inst.rwtype.rs2);
            }
            else
            {
                val = (int64_t)(int32_t)riscvm_shr_int64(val, inst.rwtype.rs2);
            }
            break;
        }
        default:
        {
            panic("illegal op-imm-32 instruction");
            break;
        }
        }
        if (LIKELY(inst.itype.rd != reg_zero))
        {
            reg_write(inst.itype.rd, val);
        }
        break;
    }
    case 0b0110011: // rv32 arithmetic
    {
        int64_t val1 = reg_read(inst.rtype.rs1);
        int64_t val2 = reg_read(inst.rtype.rs2);
        int64_t val  = 0;
        switch ((inst.rtype.funct7 << 3) | inst.rtype.funct3)
        {
        case 0b000: // ADD
        {
            val = val1 + val2;
            break;
        }
        case 0b100000000: // SUB
        {
            val = val1 - val2;
            break;
        }
        case 0b001: // SLL
        {
            val = riscvm_shl_int64(val1, val2 & 0x1f);
            break;
        }
        case 0b010: // SLT
        {
            if (val1 < val2)
            {
                val = 1;
            }
            else
            {
                val = 0;
            }
            break;
        }
        case 0b011: // SLTU
        {
            if ((uint64_t)val1 < (uint64_t)val2)
            {
                val = 1;
            }
            else
            {
                val = 0;
            }
            break;
        }
        case 0b100: // XOR
        {
            val = val1 ^ val2;
            break;
        }
        case 0b101: // SRL
        {
            val = riscvm_shr_int64(val1, val2 & 0x1f);
            break;
        }
        case 0b100000101: // SRA
        {
            val = riscvm_asr_int64(val1, val2 & 0x1f);
            break;
        }
        case 0b110: // OR
        {
            val = val1 | val2;
            break;
        }
        case 0b111: // AND
        {
            val = val1 & val2;
            break;
        }
        case 0b1000: // MUL
        {
            val = val1 * val2;
            break;
        }
        case 0b1001: // MULH
        {
            val = (int64_t)(uint64_t)riscvm_shr_int128((__int128)val1 * (__int128)val2, 64);
            break;
        }
        case 0b1010: // MULHSU
        {
            val = (int64_t)(uint64_t)riscvm_shr_int128((__int128)val1 * (__int128)(uint64_t)val2, 64);
            break;
        }
        case 0b1011: // MULHU
        {
            val = (int64_t)(uint64_t)riscvm_shr_int128((__int128)(uint64_t)val1 * (__int128)(uint64_t)val2, 64);
            break;
        }
        case 0b1100: // DIV
        {
            int64_t dividend = val1;
            int64_t divisor  = val2;
            if (UNLIKELY((dividend == (-9223372036854775807LL - 1)) && (divisor == -1)))
            {
                val = (-9223372036854775807LL - 1);
            }
            else if (UNLIKELY(divisor == 0))
            {
                val = -1;
            }
            else
            {
                val = dividend / divisor;
            }
            break;
        }
        case 0b1101: // DIVU
        {
            uint64_t dividend = (uint64_t)val1;
            uint64_t divisor  = (uint64_t)val2;
            if (UNLIKELY(divisor == 0))
            {
                val = -1;
            }
            else
            {
                val = (int64_t)(dividend / divisor);
            }
            break;
        }
        case 0b1110: // REM
        {
            int64_t dividend = val1;
            int64_t divisor  = val2;
            if (UNLIKELY((dividend == (-9223372036854775807LL - 1)) && (divisor == -1)))
            {
                val = 0;
            }
            else if (UNLIKELY(divisor == 0))
            {
                val = dividend;
            }
            else
            {
                val = dividend % divisor;
            }
            break;
        }
        case 0b1111: // REMU
        {
            uint64_t dividend = (uint64_t)val1;
            uint64_t divisor  = (uint64_t)val2;
            if (UNLIKELY(divisor == 0))
            {
                val = (int64_t)dividend;
            }
            else
            {
                val = (int64_t)(dividend % divisor);
            }
            break;
        }
        default:
        {
            panic("illegal op instruction");
            break;
        }
        }
        if (LIKELY(inst.rtype.rd != reg_zero))
        {
            reg_write(inst.rtype.rd, val);
        }
        break;
    }
    case 0b0111011: // rv64 arithmetic
    {
        int64_t val1 = reg_read(inst.rtype.rs1);
        int64_t val2 = reg_read(inst.rtype.rs2);
        int64_t val;
        switch ((inst.rtype.funct7 << 3) | inst.rtype.funct3)
        {
        case 0b000: // ADDW
        {
            val = (int64_t)(int32_t)(val1 + val2);
            break;
        }
        case 0b001: // SLLW
        {
            val = (int64_t)(int32_t)riscvm_shl_int64(val1, (val2 & 0x1f));
            break;
        }
        case 0b101: // SRLW
        {
            val = (int64_t)(int32_t)riscvm_shr_int64(val1, (val2 & 0x1f));
            break;
        }
        case 0b1000: // MULW
        {
            val = (int64_t)((int32_t)val1 * (int32_t)val2);
            break;
        }
        case 0b1100: // DIVW
        {
            int32_t dividend = (int32_t)val1;
            int32_t divisor  = (int32_t)val2;
            if (UNLIKELY((dividend == (-2147483647 - 1)) && (divisor == -1)))
            {
                val = -2147483648LL;
            }
            else if (UNLIKELY(divisor == 0))
            {
                val = -1;
            }
            else
            {
                val = (int64_t)(dividend / divisor);
            }
            break;
        }
        case 0b1101: // DIVUW
        {
            uint32_t dividend = (uint32_t)val1;
            uint32_t divisor  = (uint32_t)val2;
            if (UNLIKELY(divisor == 0))
            {
                val = -1;
            }
            else
            {
                val = (int64_t)(int32_t)(dividend / divisor);
            }
            break;
        }
        case 0b1110: // REMW
        {
            int32_t dividend = (int32_t)val1;
            int32_t divisor  = (int32_t)val2;
            if (UNLIKELY((dividend == (-2147483647 - 1)) && (divisor == -1)))
            {
                val = 0;
            }
            else if (UNLIKELY(divisor == 0))
            {
                val = (int64_t)dividend;
            }
            else
            {
                val = (int64_t)(dividend % divisor);
            }
            break;
        }
        case 0b1111: // REMUW
        {
            uint32_t dividend = (uint32_t)val1;
            uint32_t divisor  = (uint32_t)val2;
            if (UNLIKELY((divisor == 0)))
            {
                val = (int64_t)(int32_t)dividend;
            }
            else
            {
                val = (int64_t)(int32_t)(dividend % divisor);
            }
            break;
        }
        case 0b100000101: // SRAW
        {
            val = (int64_t)(int32_t)riscvm_asr_int64(val1, val2 & 0x1f);
            break;
        }
        case 0b100000000: // SUBW
        {
            val = (int64_t)(int32_t)(val1 - val2);
            break;
        }
        default:
        {
            panic("illegal op-32 instruction");
            break;
        }
        }
        if (LIKELY(inst.rtype.rd != reg_zero))
        {
            reg_write(inst.rtype.rd, val);
        }
        break;
    }
    case 0b0110111: // lui
    {
        int64_t imm = bit_signer(inst.utype.imm, 20) << 12;
        if (LIKELY(inst.utype.rd != reg_zero))
        {
            reg_write(inst.utype.rd, imm);
        }
        break;
    }
    case 0b0010111: // auipc
    {
        int64_t imm = bit_signer(inst.utype.imm, 20) << 12;
        if (LIKELY(inst.utype.rd != reg_zero))
        {
            reg_write(inst.utype.rd, self->pc + imm);
        }
        break;
    }
    case 0b1101111: // jal (call)
    {
#ifdef HAS_TRACE
        if (inst.ujtype.rd == reg_ra)
        {
            trace("^^ call\n");
            g_trace_calldepth++;
        }
        else if (inst.ujtype.rd != reg_zero)
            trace("sus link register (jal): %d\n", inst.ujtype.rd);
#endif // HAS_TRACE

        int64_t imm = bit_signer(
            (inst.ujtype.imm20 << 20) | (inst.ujtype.imm1 << 1) | (inst.ujtype.imm11 << 11)
                | (inst.ujtype.imm12 << 12),
            20
        );

        if (LIKELY(inst.ujtype.rd != reg_zero))
        {
            reg_write(inst.ujtype.rd, self->pc + 4);
        }
        self->pc = self->pc + imm;
        return;
    }
    case 0b1100111: // jalr (ret)
    {
#ifdef HAS_TRACE
        if (inst.itype.rs1 == reg_ra)
        {
            trace("^^ return\n");
            g_trace_calldepth--;
        }
        else
            trace("sus link register (ret): %d\n", inst.itype.rs1);
#endif // HAS_TRACE

        int64_t pc = self->pc + 4;
        self->pc   = (int64_t)(reg_read(inst.itype.rs1) + inst.itype.imm) & -2;

        if (UNLIKELY(inst.itype.rd != reg_zero))
        {
            reg_write(inst.itype.rd, pc);
        }
        return;
    }
    case 0b1100011: // BEQ (conditional branch)
    {
        trace("^^ conditional branch\n");

        int32_t imm = (inst.sbtype.imm_12 << 12) |  // Bit 31 -> Position 12
                      (inst.sbtype.imm_5_10 << 5) | // Bits 30-25 -> Positions 10-5
                      (inst.sbtype.imm_1_4 << 1) |  // Bits 11-8 -> Positions 4-1
                      (inst.sbtype.imm_11 << 11);   // Bit 7 -> Position 11

        // Sign extend from the 12th bit
        imm = (imm << 19) >> 19;

        uint64_t val1 = reg_read(inst.sbtype.rs1);
        uint64_t val2 = reg_read(inst.sbtype.rs2);
        bool     cond = 0;

        switch (inst.sbtype.funct3)
        {
        case 0b000: // beq
        {
            cond = val1 == val2;
            break;
        }
        case 0b001: // bne
        {
            cond = val1 != val2;
            break;
        }
        case 0b100: // blt
        {
            cond = (int64_t)val1 < (int64_t)val2;
            break;
        }
        case 0b101: // bge
        {
            cond = (int64_t)val1 >= (int64_t)val2;
            break;
        }
        case 0b110: // bltu
        {
            cond = val1 < val2;
            break;
        }
        case 0b111: // bgeu
        {
            cond = val1 >= val2;
            break;
        }
        default:
        {
            panic("illegal branch instruction");
            break;
        }
        }
        if (cond)
        {
            self->pc = self->pc + imm;
            return;
        }
        break;
    }
    case 0b0001111:
    {
        break;
    }
    case 0b1110011: // system calls and breakpoints
    {
        switch (inst.itype.imm)
        {
        case 0b000000000000: // ecall
        {
            uint64_t code = reg_read(reg_a7);
            reg_write(reg_a0, riscvm_handle_syscall(self, code));
            break;
        }
        case 0b000000000001: // ebreak
        {
            self->exitcode = -1;
            self->running  = false;
            break;
        }
        default:
        {
            panic("illegal system instruction");
            break;
        }
        }
        break;
    }
    default:
    {
        panic("illegal instruction");
        break;
    }
    }
    self->pc = (self->pc + 4);
}
void riscvm_run(riscvm_ptr self)
{
    self->running = true;
    while (LIKELY(self->running))
    {
        Instruction inst;
        inst.bits = riscvm_fetch(self);

        unsigned char* p_inst = (unsigned char*)&inst.bits;
        (void)p_inst;
        trace("pc: 0x%llx, inst: %02x %02x %02x %02x\n", self->pc, p_inst[0], p_inst[1], p_inst[2], p_inst[3]);

        riscvm_execute(self, inst);
    }
}
int main(int argc, char** argv)
{
    if (argc < 2)
    {
        puts("please supply a RV64I program to run!");
        return EXIT_FAILURE;
    }
#ifdef _DEBUG
    g_trace = argc > 2 && _stricmp(argv[2], "--trace") == 0;
#endif
    riscvm_ptr machine = (riscvm_ptr)malloc(sizeof(riscvm));
    memset(machine, 0, sizeof(riscvm));
    riscvm_loadfile(machine, argv[1]);
    riscvm_run(machine);
    exit((int)machine->exitcode);
    return EXIT_SUCCESS;
}
