#define _CRT_SECURE_NO_WARNINGS

#include <array>

#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <intrin.h>

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
        log("failed to open file\n");
    }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (size > sizeof(g_code))
    {
        log("loaded code too big!\n");
        exit(EXIT_FAILURE);
    }
    fread(g_code, size, 1, fp);
    fclose(fp);
    reg_write(reg_sp, (uint64_t)&g_stack[sizeof(g_stack) - 0x10]);
    self->pc = (int64_t)g_code;

#pragma pack(1)
    struct Features
    {
        uint32_t magic;
        struct
        {
            bool encrypted : 1;
            bool shuffled  : 1;
        };
        uint32_t key;
    };
    static_assert(sizeof(Features) == 9, "");

    auto features = (Features*)(g_code + size - sizeof(Features));
    if (features->magic != 'ETAG')
    {
        log("no features in the file (unencrypted payload?)\n");
#if defined(CODE_ENCRYPTION) || defined(OPCODE_SHUFFLING)
        exit(EXIT_FAILURE);
#else
        return;
#endif
    }

#ifdef OPCODE_SHUFFLING
    if (!features->shuffled)
    {
        log("shuffling enabled on the host, disabled in the bytecode");
        exit(EXIT_FAILURE);
    }
#else
    if (features->shuffled)
    {
        log("shuffling disabled on the host, enabled in the bytecode");
        exit(EXIT_FAILURE);
    }
#endif // OPCODE_SHUFFLING

#ifdef CODE_ENCRYPTION
    if (!features->encrypted)
    {
        log("encryption enabled on the host, disabled in the bytecode");
        exit(EXIT_FAILURE);
    }
    self->base = self->pc;
    self->key  = features->key;
#else
    if (features->encrypted)
    {
        log("encryption disabled on the host, enabled in the bytecode");
        exit(EXIT_FAILURE);
    }
#endif // CODE_ENCRYPTION
}

#ifdef CODE_ENCRYPTION
#warning Code encryption enabled
// TODO: replace with something with better distribution?
ALWAYS_INLINE static uint32_t djb2_hash(const uint8_t* data)
{
    uint32_t hash = 5381;
    for (size_t i = 0; i < sizeof(uint32_t); ++i)
    {
        hash = ((hash << 5) + hash) + data[i];
    }
    return hash;
}

ALWAYS_INLINE static uint32_t transform(uintptr_t offset, uint32_t key)
{
    uint32_t key2 = key + offset;
    return djb2_hash((const uint8_t*)&key2);
}
#endif // CODE_ENCRYPTION

ALWAYS_INLINE static uint32_t riscvm_fetch(riscvm_ptr self)
{
    uint32_t data;
    memcpy(&data, (const void*)self->pc, sizeof(data));

#ifdef CODE_ENCRYPTION
    return data ^ transform(self->pc - self->base, self->key);
#else
    return data;
#endif // CODE_ENCRYPTION
}

ALWAYS_INLINE static int8_t riscvm_read_int8(riscvm_ptr self, uint64_t addr)
{
    int8_t data;
    memcpy(&data, (const void*)addr, sizeof(data));
    return data;
}

ALWAYS_INLINE static int16_t riscvm_read_int16(riscvm_ptr self, uint64_t addr)
{
    int16_t data;
    memcpy(&data, (const void*)addr, sizeof(data));
    return data;
}

ALWAYS_INLINE static int32_t riscvm_read_int32(riscvm_ptr self, uint64_t addr)
{
    int32_t data;
    memcpy(&data, (const void*)addr, sizeof(data));
    return data;
}

ALWAYS_INLINE static int64_t riscvm_read_int64(riscvm_ptr self, uint64_t addr)
{
    int64_t data;
    memcpy(&data, (const void*)addr, sizeof(data));
    return data;
}

ALWAYS_INLINE static uint8_t riscvm_read_uint8(riscvm_ptr self, uint64_t addr)
{
    uint8_t data;
    memcpy(&data, (const void*)addr, sizeof(data));
    return data;
}

ALWAYS_INLINE static uint16_t riscvm_read_uint16(riscvm_ptr self, uint64_t addr)
{
    uint16_t data;
    memcpy(&data, (const void*)addr, sizeof(data));
    return data;
}

ALWAYS_INLINE static uint32_t riscvm_read_uint32(riscvm_ptr self, uint64_t addr)
{
    uint32_t data;
    memcpy(&data, (const void*)addr, sizeof(data));
    return data;
}

ALWAYS_INLINE static void* riscvm_getptr(riscvm_ptr self, uint64_t addr)
{
    return (void*)addr;
}

ALWAYS_INLINE static void riscvm_write_uint8(riscvm_ptr self, uint64_t addr, uint8_t val)
{
    memcpy((void*)addr, &val, sizeof(val));
}

ALWAYS_INLINE static void riscvm_write_uint16(riscvm_ptr self, uint64_t addr, uint16_t val)
{
    memcpy((void*)addr, &val, sizeof(val));
}

ALWAYS_INLINE static void riscvm_write_uint32(riscvm_ptr self, uint64_t addr, uint32_t val)
{
    memcpy((void*)addr, &val, sizeof(val));
}

ALWAYS_INLINE static void riscvm_write_uint64(riscvm_ptr self, uint64_t addr, uint64_t val)
{
    memcpy((void*)addr, &val, sizeof(val));
}

ALWAYS_INLINE static int32_t bit_signer(uint32_t field, uint32_t size)
{
    return (field & (1U << (size - 1))) ? (int32_t)(field | (0xFFFFFFFFU << size)) : (int32_t)field;
}

ALWAYS_INLINE static bool riscvm_handle_syscall(riscvm_ptr self, uint64_t code, uint64_t& result)
{
    trace("syscall %llu\n", code);
    switch (code)
    {
    case 10000: // exit
    {
        self->exitcode = reg_read(reg_a0);
        return false;
    }

#ifdef DEBUG_SYSCALLS
    case 10001: // abort
    {
        panic("aborted!");
        return false;
    }

    case 10006: // memcpy
    {
        void* src  = riscvm_getptr(self, reg_read(reg_a0));
        void* dest = riscvm_getptr(self, reg_read(reg_a1));
        void* res  = memcpy(dest, src, (size_t)reg_read(reg_a2));
        result     = (uint64_t)res;
        break;
    }

    case 10007: // memset
    {
        void* dest = riscvm_getptr(self, reg_read(reg_a0));
        void* res  = memset(dest, (int)reg_read(reg_a1), (size_t)reg_read(reg_a2));
        result     = (uint64_t)res;
        break;
    }

    case 10008: // memmove
    {
        void* src  = riscvm_getptr(self, reg_read(reg_a0));
        void* dest = riscvm_getptr(self, reg_read(reg_a1));
        void* res  = memmove(dest, src, (size_t)reg_read(reg_a2));
        result     = (uint64_t)res;
        break;
    }

    case 10009: // memcmp
    {
        void* src1 = riscvm_getptr(self, reg_read(reg_a0));
        void* src2 = riscvm_getptr(self, reg_read(reg_a1));
        result     = (uint64_t)memcmp(src1, src2, (size_t)reg_read(reg_a2));
        break;
    }

    case 10100: // print_wstring
    {
        wchar_t* s = (wchar_t*)riscvm_getptr(self, reg_read(reg_a0));
        if (s != NULL)
        {
            wprintf(L"print: %ls\n", s);
        }
        break;
    }

    case 10101: // print_string
    {
        char* s = (char*)riscvm_getptr(self, reg_read(reg_a0));
        if (s != NULL)
        {
            printf("print: %s\n", s);
        }
        break;
    }

    case 10102: // print_int
    {
        printf("value: %lli\n", reg_read(reg_a0));
        break;
    }

    case 10103: // print_hex
    {
        printf("value: 0x%llx\n", reg_read(reg_a0));
        break;
    }

    case 10104: // print_tag_hex
    {
        printf("%s: 0x%llx\n", (char*)reg_read(reg_a0), reg_read(reg_a1));
        break;
    }
#endif // DEBUG_SYSCALLS

    case 20000: // host_call
    {
        uint64_t  func_addr = reg_read(reg_a0);
        uint64_t* args      = (uint64_t*)riscvm_getptr(self, reg_read(reg_a1));

        using syscall_fn = uint64_t(__fastcall*)(
            uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t
        );

        syscall_fn fn = (syscall_fn)func_addr;
        result =
            fn(args[0],
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
        break;
    }

    case 20001: // get_peb
    {
        result = __readgsqword(0x60);
        break;
    }

    default:
    {
        panic("illegal system call %llu (0x%llX)\n", code, code);
        return false;
    }
    }
    return true;
}

ALWAYS_INLINE static int64_t riscvm_shl_int64(int64_t a, int64_t b)
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

ALWAYS_INLINE static int64_t riscvm_shr_int64(int64_t a, int64_t b)
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

ALWAYS_INLINE static int64_t riscvm_asr_int64(int64_t a, int64_t b)
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

ALWAYS_INLINE static __int128 riscvm_shr_int128(__int128 a, __int128 b)
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

#ifdef OPCODE_SHUFFLING
#define trace_inst(inst)                                                                                    \
    unsigned char* p_inst = (unsigned char*)&inst.bits;                                                     \
    (void)p_inst;                                                                                           \
    uint8_t opcode = inst.opcode;                                                                           \
    inst.opcode    = riscvm_original_opcode(inst.opcode);                                                   \
    trace("pc: 0x%llx, inst: %02x %02x %02x %02x\n", self->pc, p_inst[0], p_inst[1], p_inst[2], p_inst[3]); \
    inst.opcode = opcode
#else
#define trace_inst(inst)                                \
    unsigned char* p_inst = (unsigned char*)&inst.bits; \
    (void)p_inst;                                       \
    trace("pc: 0x%llx, inst: %02x %02x %02x %02x\n", self->pc, p_inst[0], p_inst[1], p_inst[2], p_inst[3])
#endif // OPCODE_SHUFFLING

#ifdef DIRECT_DISPATCH
#warning Direct dispatch enabled
#define HANDLER(op)   handler_##op
#define FWHANDLER(op) static bool HANDLER(op)(riscvm_ptr self, Instruction inst)
FWHANDLER(rv64_load);
FWHANDLER(rv64_fence);
FWHANDLER(rv64_imm64);
FWHANDLER(rv64_auipc);
FWHANDLER(rv64_imm32);
FWHANDLER(rv64_store);
FWHANDLER(rv64_op64);
FWHANDLER(rv64_lui);
FWHANDLER(rv64_op32);
FWHANDLER(rv64_branch);
FWHANDLER(rv64_jalr);
FWHANDLER(rv64_jal);
FWHANDLER(rv64_system);
FWHANDLER(rv64_invalid);
#undef FWHANDLER

typedef bool (*riscvm_handler_t)(riscvm_ptr, Instruction);

static constexpr std::array<riscvm_handler_t, 32> riscvm_handlers = []
{
    std::array<riscvm_handler_t, 32> result = {};
    for (size_t i = 0; i < result.size(); i++)
    {
        result[i] = handler_rv64_invalid;
    }
#define INSERT(op) result[op] = HANDLER(op)
    INSERT(rv64_load);
    INSERT(rv64_fence);
    INSERT(rv64_imm64);
    INSERT(rv64_auipc);
    INSERT(rv64_imm32);
    INSERT(rv64_store);
    INSERT(rv64_op64);
    INSERT(rv64_lui);
    INSERT(rv64_op32);
    INSERT(rv64_branch);
    INSERT(rv64_jalr);
    INSERT(rv64_jal);
    INSERT(rv64_system);
#undef CHECK
    return result;
}();

#define dispatch()                                       \
    Instruction next;                                    \
    next.bits = riscvm_fetch(self);                      \
    if (next.compressed_flags != 0b11)                   \
    {                                                    \
        panic("compressed instructions not supported!"); \
    }                                                    \
    trace_inst(next);                                    \
    __attribute__((musttail)) return riscvm_handlers[next.opcode](self, next)

#else
#define dispatch() return true
#endif // DIRECT_DISPATCH

ALWAYS_INLINE static bool handler_rv64_load(riscvm_ptr self, Instruction inst)
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

    self->pc += 4;
    dispatch();
}

ALWAYS_INLINE static bool handler_rv64_store(riscvm_ptr self, Instruction inst)
{
    int32_t  imm  = bit_signer((inst.stype.imm7 << 5) | inst.stype.imm5, 12);
    uint64_t addr = reg_read(inst.stype.rs1) + imm;
    uint64_t val  = reg_read(inst.stype.rs2);
    switch (inst.stype.funct3)
    {
    case 0b00:
    {
        riscvm_write_uint8(self, addr, (uint8_t)val);
        break;
    }
    case 0b01:
    {
        riscvm_write_uint16(self, addr, (uint16_t)val);
        break;
    }
    case 0b10:
    {
        riscvm_write_uint32(self, addr, (uint32_t)val);
        break;
    }
    case 0b11:
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

    self->pc += 4;
    dispatch();
}

ALWAYS_INLINE static bool handler_rv64_imm64(riscvm_ptr self, Instruction inst)
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

    self->pc += 4;
    dispatch();
}

ALWAYS_INLINE static bool handler_rv64_imm32(riscvm_ptr self, Instruction inst)
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

    self->pc += 4;
    dispatch();
}

ALWAYS_INLINE static bool handler_rv64_op64(riscvm_ptr self, Instruction inst)
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

    self->pc += 4;
    dispatch();
}

ALWAYS_INLINE static bool handler_rv64_op32(riscvm_ptr self, Instruction inst)
{
    int64_t val1 = reg_read(inst.rtype.rs1);
    int64_t val2 = reg_read(inst.rtype.rs2);
    int64_t val  = 0;
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

    self->pc += 4;
    dispatch();
}

ALWAYS_INLINE static bool handler_rv64_lui(riscvm_ptr self, Instruction inst)
{
    int64_t imm = bit_signer(inst.utype.imm, 20) << 12;
    if (LIKELY(inst.utype.rd != reg_zero))
    {
        reg_write(inst.utype.rd, imm);
    }

    self->pc += 4;
    dispatch();
}

ALWAYS_INLINE static bool handler_rv64_auipc(riscvm_ptr self, Instruction inst)
{
    int64_t imm = bit_signer(inst.utype.imm, 20) << 12;
    if (LIKELY(inst.utype.rd != reg_zero))
    {
        reg_write(inst.utype.rd, self->pc + imm);
    }

    self->pc += 4;
    dispatch();
}

ALWAYS_INLINE static bool handler_rv64_jal(riscvm_ptr self, Instruction inst)
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

    self->pc += imm;
    dispatch();
}

ALWAYS_INLINE static bool handler_rv64_jalr(riscvm_ptr self, Instruction inst)
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

    if (UNLIKELY(inst.itype.rd != reg_zero))
    {
        reg_write(inst.itype.rd, self->pc + 4);
    }

    self->pc = (int64_t)(reg_read(inst.itype.rs1) + inst.itype.imm) & -2;
    dispatch();
}

ALWAYS_INLINE static bool handler_rv64_branch(riscvm_ptr self, Instruction inst)
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
        self->pc += imm;
    }
    else
    {
        self->pc += 4;
    }
    dispatch();
}

ALWAYS_INLINE static bool handler_rv64_fence(riscvm_ptr self, Instruction inst)
{
    // no-op on x86

    self->pc += 4;
    dispatch();
}

ALWAYS_INLINE static bool handler_rv64_system(riscvm_ptr self, Instruction inst)
{
    switch (inst.itype.imm)
    {
    case 0b000000000000: // ecall
    {
        uint64_t code   = reg_read(reg_a7);
        uint64_t result = 0;
        if (!riscvm_handle_syscall(self, code, result))
            return false;
        reg_write(reg_a0, result);
        break;
    }
    case 0b000000000001: // ebreak
    {
        self->exitcode = -1;
        return false;
    }
    default:
    {
        panic("illegal system instruction");
        break;
    }
    }

    self->pc += 4;
    dispatch();
}

ALWAYS_INLINE static bool handler_rv64_invalid(riscvm_ptr self, Instruction inst)
{
    panic("illegal instruction");
    return false;
}

#ifdef DIRECT_DISPATCH
ALWAYS_INLINE static bool riscvm_execute(riscvm_ptr self, Instruction inst)
{
    dispatch();
}

NEVER_INLINE void riscvm_run(riscvm_ptr self)
{
    Instruction inst;
    riscvm_execute(self, inst);
}
#else
ALWAYS_INLINE static bool riscvm_execute(riscvm_ptr self, Instruction inst)
{
    if (inst.compressed_flags != 0b11)
    {
        panic("compressed instructions not supported!");
    }

    switch (inst.opcode)
    {
    case rv64_load:
    {
        return handler_rv64_load(self, inst);
    }

    case rv64_store:
    {
        return handler_rv64_store(self, inst);
    }

    case rv64_imm64:
    {
        return handler_rv64_imm64(self, inst);
    }

    case rv64_imm32:
    {
        return handler_rv64_imm32(self, inst);
    }

    case rv64_op64:
    {
        return handler_rv64_op64(self, inst);
    }

    case rv64_op32:
    {
        return handler_rv64_op32(self, inst);
    }

    case rv64_lui:
    {
        return handler_rv64_lui(self, inst);
    }

    case rv64_auipc:
    {
        return handler_rv64_auipc(self, inst);
    }

    case rv64_jal: // call
    {
        return handler_rv64_jal(self, inst);
    }

    case rv64_jalr: // ret
    {
        return handler_rv64_jalr(self, inst);
    }

    case rv64_branch:
    {
        return handler_rv64_branch(self, inst);
    }

    case rv64_fence:
    {
        return handler_rv64_fence(self, inst);
    }

    case rv64_system: // system calls and breakpoints
    {
        return handler_rv64_system(self, inst);
    }

    default:
    {
        return handler_rv64_invalid(self, inst);
    }
    }
}

NEVER_INLINE void riscvm_run(riscvm_ptr self)
{
    while (true)
    {
        Instruction inst;
        inst.bits = riscvm_fetch(self);

        trace_inst(inst);

        if (!riscvm_execute(self, inst))
            break;
    }
}
#endif

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        log("please supply a RV64I program to run!\n");
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
