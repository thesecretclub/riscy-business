#pragma once

#include <stdio.h>
#include <stdint.h>
#include <wchar.h>

#ifdef TRACING
#pragma message("Tracing enabled")

extern bool g_trace;

#define ALWAYS_INLINE
#define NEVER_INLINE
#define LIKELY(x)   (x)
#define UNLIKELY(x) (x)

#define panic(...)           \
    do                       \
    {                        \
        printf(__VA_ARGS__); \
        __debugbreak();      \
    } while (0)

#define log(...)  printf(__VA_ARGS__)
#define logw(...) wprintf(__VA_ARGS__)

#else

#define log(...)
#define logw(...)

#if defined(SILENT_PANIC)
#define panic(...) return false
#else
#define panic(...) __debugbreak()
#endif

#if defined(__clang__)
#define ALWAYS_INLINE __attribute__((always_inline)) inline
#elif defined(__GNUC__)
#define ALWAYS_INLINE [[gnu::always_inline]] inline
#elif defined(_MSC_VER)
#define ALWAYS_INLINE __forceinline
#elif __STDC_VERSION__ >= 199901L
#define ALWAYS_INLINE inline
#else
#define ALWAYS_INLINE
#endif

#if defined(__clang__)
#define NEVER_INLINE __attribute__((noinline))
#elif defined(__GNUC__)
#define NEVER_INLINE [[gnu::noinline]]
#elif defined(_MSC_VER)
#define NEVER_INLINE __declspec(noinline)
#else
#define NEVER_INLINE
#endif

#if defined(__GNUC__) || defined(__clang__)
#define LIKELY(x) __builtin_expect(x, 1)
#else
#define LIKELY(x) (x)
#endif

#if defined(__GNUC__) || defined(__clang__)
#define UNLIKELY(x) __builtin_expect(x, 0)
#else
#define UNLIKELY(x) (x)
#endif

#endif // TRACING

#define reg_read(idx) (int64_t) self->regs[idx]

#define reg_write(idx, value)        \
    do                               \
    {                                \
        if (LIKELY(idx != reg_zero)) \
        {                            \
            self->regs[idx] = value; \
        }                            \
    } while (0)

struct riscvm
{
    int64_t  pc;
    uint64_t regs[32];

#ifdef TRACING
    FILE*   trace;
    int64_t rebase;
#endif // TRACING

#ifdef CODE_ENCRYPTION
    int64_t  base;
    uint32_t key;
#endif // CODE_ENCRYPTION

#ifdef CUSTOM_SYSCALLS
    void* userdata;
    bool (*handle_syscall)(riscvm* self, uint64_t code, uint64_t* result);
#endif // CUSTOM_SYSCALLS
};
typedef riscvm* riscvm_ptr;

union Instruction
{
    struct
    {
        uint32_t compressed_flags : 2;
        uint32_t opcode           : 5;
        uint32_t                  : 25;
    };

    struct
    {
        uint32_t opcode : 7;
        uint32_t rd     : 5;
        uint32_t funct3 : 3;
        uint32_t rs1    : 5;
        uint32_t rs2    : 5;
        uint32_t funct7 : 7;
    } rtype;

    struct
    {
        uint32_t opcode : 7;
        uint32_t rd     : 5;
        uint32_t funct3 : 3;
        uint32_t rs1    : 5;
        uint32_t rs2    : 5;
        uint32_t shamt  : 1;
        uint32_t imm    : 6;
    } rwtype;

    struct
    {
        uint32_t opcode : 7;
        uint32_t rd     : 5;
        uint32_t funct3 : 3;
        uint32_t rs1    : 5;
        uint32_t imm    : 12;
    } itype;

    struct
    {
        uint32_t opcode : 7;
        uint32_t rd     : 5;
        uint32_t imm    : 20;
    } utype;

    struct
    {
        uint32_t opcode : 7;
        uint32_t rd     : 5;
        uint32_t imm12  : 8;
        uint32_t imm11  : 1;
        uint32_t imm1   : 10;
        uint32_t imm20  : 1;
    } ujtype;

    struct
    {
        uint32_t opcode : 7;
        uint32_t imm5   : 5;
        uint32_t funct3 : 3;
        uint32_t rs1    : 5;
        uint32_t rs2    : 5;
        uint32_t imm7   : 7;
    } stype;

    /*
     * RISC-V SB-Type Instruction Format:
     *
     *  31      | 30     25 | 24  20 | 19  15 | 14  12 | 11     8 |    7    | 6     0
     * ---------|-----------|--------|--------|--------|----------|---------|---------
     * imm[12]  | imm[10:5] |  rs2   |  rs1   | funct3 | imm[4:1] | imm[11] | opcode
     * ---------|-----------|--------|--------|--------|----------|---------|---------
     *  1 bit   |  6 bits   | 5 bits | 5 bits | 3 bits |  4 bits  |  1 bit  |  7 bits
     *
     * Fields:
     * imm[12]        - Immediate value bit 12
     * imm[10:5]      - Immediate value bits 10 through 5
     * rs2            - Source register 2
     * rs1            - Source register 1
     * funct3         - Function code for instruction format
     * imm[4:1]       - Immediate value bits 4 through 1
     * imm[11]        - Immediate value bit 11
     * opcode         - Operation code specifying the operation to be performed
     */

    struct
    {
        uint32_t opcode   : 7;
        uint32_t imm_11   : 1;
        uint32_t imm_1_4  : 4;
        uint32_t funct3   : 3;
        uint32_t rs1      : 5;
        uint32_t rs2      : 5;
        uint32_t imm_5_10 : 6;
        uint32_t imm_12   : 1;
    } sbtype;

    int16_t  chunks16[2];
    uint32_t bits;
};

static_assert(sizeof(Instruction) == sizeof(uint32_t), "");

enum InstructionType
{
    insn_rtype  = 0b0110011,
    insn_itype  = 0b0010011,
    insn_stype  = 0b0100011,
    insn_utype  = 0b0110111,
    insn_ujtype = 0b1101111,
    insn_sbtype = 0b1100011,
    insn_istype = 0b0000011,
};

// Reference: https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-cc.adoc
enum RegIndex
{
    reg_zero, // always zero
    reg_ra,   // return address
    reg_sp,   // stack pointer
    reg_gp,   // global pointer
    reg_tp,   // thread pointer
    reg_t0,
    reg_t1,
    reg_t2,
    reg_s0,
    reg_s1,
    reg_a0,
    reg_a1,
    reg_a2,
    reg_a3,
    reg_a4,
    reg_a5,
    reg_a6,
    reg_a7,
    reg_s2,
    reg_s3,
    reg_s4,
    reg_s5,
    reg_s6,
    reg_s7,
    reg_s8,
    reg_s9,
    reg_s10,
    reg_s11,
    reg_t3,
    reg_t4,
    reg_t5,
    reg_t6,
};

#ifdef OPCODE_SHUFFLING
#pragma message("Opcode shuffling enabled")
#include "shuffled_opcodes.h"
#else
#include "opcodes.h"
#endif // OPCODE_SHUFFLING

template <typename T> ALWAYS_INLINE T riscvm_read(uint64_t addr)
{
    T data;
    memcpy(&data, (const void*)addr, sizeof(data));
    return data;
}

template <typename T> ALWAYS_INLINE void riscvm_write(uint64_t addr, T val)
{
    memcpy((void*)addr, &val, sizeof(val));
}

ALWAYS_INLINE static void* riscvm_getptr(riscvm_ptr self, uint64_t addr)
{
    return (void*)addr;
}

ALWAYS_INLINE static int32_t bit_signer(uint32_t field, uint32_t size)
{
    return (field & (1U << (size - 1))) ? (int32_t)(field | (0xFFFFFFFFU << size)) : (int32_t)field;
}

#ifdef _MSC_VER
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif

extern "C" DLLEXPORT void riscvm_run(riscvm_ptr self);
