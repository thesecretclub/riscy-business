#pragma once

#ifdef _DEBUG

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "riscvm.h"

const char* reg_names[] = {
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0",  "a1",  "a2", "a3", "a4", "a5",
    "a6",   "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
};

int g_calldepth = 0;

#define TO_SIGNED_HEX_32(val)                                                                               \
    char buf_##val[12];                                                                                     \
    ((val) < 0 ? sprintf(buf_##val, "-0x%x", -(int32_t)(val)) : sprintf(buf_##val, "0x%x", (int32_t)(val)), \
     buf_##val)

#define TO_SIGNED_HEX_64(val)                                                                                   \
    char buf_##val[20];                                                                                         \
    ((val) < 0 ? sprintf(buf_##val, "-0x%llx", -(int64_t)(val)) : sprintf(buf_##val, "0x%llx", (int64_t)(val)), \
     buf_##val)

void trace_load(riscvm_ptr self, Instruction inst, char* buffer)
{
    int32_t  imm  = bit_signer(inst.itype.imm, 12);
    uint64_t addr = reg_read(inst.itype.rs1) + imm;
    int64_t  val  = 0;

    const char* memnomic = nullptr;
    const char* reg      = reg_names[inst.itype.rs1];
    const char* ra       = reg_names[inst.itype.rd];

    switch (inst.itype.funct3)
    {
    case rv64_load_lb:
    {
        memnomic = "lb";
        val      = riscvm_read<int8_t>(addr);
        break;
    }
    case rv64_load_lh:
    {
        memnomic = "lh";
        val      = riscvm_read<int16_t>(addr);
        break;
    }
    case rv64_load_lw:
    {
        memnomic = "lw";
        val      = riscvm_read<int32_t>(addr);
        break;
    }
    case rv64_load_ld:
    {
        memnomic = "ld";
        val      = riscvm_read<int64_t>(addr);
        break;
    }
    case rv64_load_lbu:
    {
        memnomic = "lbu";
        val      = riscvm_read<uint8_t>(addr);
        break;
    }
    case rv64_load_lhu:
    {
        memnomic = "lhu";
        val      = riscvm_read<uint16_t>(addr);
        break;
    }
    case rv64_load_lwu:
    {
        memnomic = "lwu";
        val      = riscvm_read<uint32_t>(addr);
        break;
    }
    default:
        memnomic = "unk(load)";
        break;
    }

    TO_SIGNED_HEX_32(imm);
    TO_SIGNED_HEX_64(val);
    TO_SIGNED_HEX_64(addr);

    sprintf(buffer, "%-8s %s, %s(%s=>%s) = %s", memnomic, ra, buf_imm, reg, buf_addr, buf_val);
}

void trace_imm64(riscvm_ptr self, Instruction inst, char* buffer)
{
    int64_t imm = bit_signer(inst.itype.imm, 12);
    int64_t rs1 = reg_read(inst.itype.rs1);
    int64_t val = 0;

    const char* memnomic = nullptr;
    const char* reg      = reg_names[inst.itype.rs1];
    const char* ra       = reg_names[inst.itype.rd];

    // tracing
    switch (inst.itype.funct3)
    {
    case rv64_imm64_addi:
        memnomic = "addi";
        val      = rs1 + imm;
        break;
    case rv64_imm64_slli:
        memnomic = "slli";
        imm      = inst.rwtype.rs2;
        val      = rs1 << imm;
        break;
    case rv64_imm64_slti:
        memnomic = "slti";
        val      = rs1 < imm;
        break;
    case rv64_imm64_sltiu:
        memnomic = "sltiu";
        val      = rs1 < imm;
        break;
    case rv64_imm64_xori:
        memnomic = "xori";
        val      = rs1 ^ imm;
        break;
    case rv64_imm64_srli:
        memnomic = "srli";
        imm      = inst.rwtype.rs2;
        val      = rs1 >> imm;
        break;
    case rv64_imm64_ori:
        memnomic = "ori";
        val      = rs1 | imm;
        break;
    case rv64_imm64_andi:
        memnomic = "andi";
        val      = rs1 & imm;
        break;
    default:
        memnomic = "unk(imm64)";
        break;
    }

    TO_SIGNED_HEX_64(imm);
    TO_SIGNED_HEX_64(val);
    sprintf(buffer, "%-8s %s, %s, %s = %s", memnomic, ra, reg, buf_imm, buf_val);
}

void trace_imm32(riscvm_ptr self, Instruction inst, char* buffer)
{
    int64_t imm = bit_signer(inst.itype.imm, 12);
    int64_t rs1 = reg_read(inst.itype.rs1);
    int64_t val = 0;

    const char* memnomic = nullptr;
    const char* reg      = reg_names[inst.itype.rs1];
    const char* ra       = reg_names[inst.itype.rd];

    // tracing
    switch (inst.itype.funct3)
    {
    case rv64_imm32_addiw:
        memnomic = "addiw";
        val      = rs1 + imm;
        break;
    case rv64_imm32_slliw:
        memnomic = "slliw";
        imm      = inst.rwtype.rs2;
        val      = rs1 << imm;
        break;
    case rv64_imm32_srliw:
        memnomic = "srliw";
        imm      = inst.rwtype.rs2;
        val      = rs1 >> imm;
        break;
    default:
        memnomic = "unk(imm32)";
        break;
    }

    TO_SIGNED_HEX_32(imm);
    TO_SIGNED_HEX_32(val);

    sprintf(buffer, "%-8s %s, %s, %s = %s", memnomic, ra, reg, buf_imm, buf_val);
}

void trace_op64(riscvm_ptr self, Instruction inst, char* buffer)
{
    int64_t rs1 = reg_read(inst.rtype.rs1);
    int64_t rs2 = reg_read(inst.rtype.rs2);
    int64_t val = 0;

    const char* memnomic = nullptr;
    const char* reg1     = reg_names[inst.rtype.rs1];
    const char* reg2     = reg_names[inst.rtype.rs2];
    const char* ra       = reg_names[inst.rtype.rd];

    switch ((inst.rtype.funct7 << 3) | inst.rtype.funct3)
    {
    case rv64_op64_add:
        memnomic = "add";
        val      = rs1 + rs2;
        break;
    case rv64_op64_sub:
        memnomic = "sub";
        val      = rs1 - rs2;
        break;
    case rv64_op64_sll:
        memnomic = "sll";
        val      = rs1 << rs2;
        break;
    case rv64_op64_slt:
        memnomic = "slt";
        val      = rs1 < rs2;
        break;
    case rv64_op64_sltu:
        memnomic = "sltu";
        val      = rs1 < rs2;
        break;
    case rv64_op64_xor:
        memnomic = "xor";
        val      = rs1 ^ rs2;
        break;
    case rv64_op64_srl:
        memnomic = "srl";
        val      = rs1 >> rs2;
        break;
    case rv64_op64_sra:
        memnomic = "sra";
        val      = rs1 >> rs2;
        break;
    case rv64_op64_or:
        memnomic = "or";
        val      = rs1 | rs2;
        break;
    case rv64_op64_and:
        memnomic = "and";
        val      = rs1 & rs2;
        break;
    case rv64_op64_mul:
        memnomic = "mul";
        val      = rs1 * rs2;
        break;
    case rv64_op64_mulh:
        memnomic = "mulh";
        val      = (__int128)(rs1 * rs2) >> 64;
        break;
    case rv64_op64_mulhsu:
        memnomic = "mulhsu";
        val      = (__int128)(rs1 * rs2) >> 64;
        break;
    case rv64_op64_mulhu:
        memnomic = "mulhu";
        val      = (__int128)(rs1 * rs2) >> 64;
        break;
    case rv64_op64_div:
        memnomic = "div";
        val      = rs1 / rs2;
        break;
    case rv64_op64_divu:
        memnomic = "divu";
        val      = rs1 / rs2;
        break;
    case rv64_op64_rem:
        memnomic = "rem";
        val      = rs1 % rs2;
        break;
    case rv64_op64_remu:
        memnomic = "remu";
        val      = rs1 % rs2;
        break;
    default:
        memnomic = "unk(op64)";
        break;
    }

    TO_SIGNED_HEX_64(val);
    sprintf(buffer, "%-8s %s, %s, %s = %s", memnomic, ra, reg1, reg2, buf_val);
}

void trace_op32(riscvm_ptr self, Instruction inst, char* buffer)
{
    int64_t rs1 = reg_read(inst.rtype.rs1);
    int64_t rs2 = reg_read(inst.rtype.rs2);
    int64_t val = 0;

    const char* memnomic = nullptr;
    const char* reg1     = reg_names[inst.rtype.rs1];
    const char* reg2     = reg_names[inst.rtype.rs2];
    const char* ra       = reg_names[inst.rtype.rd];

    switch ((inst.rtype.funct7 << 3) | inst.rtype.funct3)
    {
    case rv64_op32_addw:
        memnomic = "addw";
        val      = rs1 + rs2;
        break;
    case rv64_op32_subw:
        memnomic = "subw";
        val      = rs1 - rs2;
        break;
    case rv64_op32_sllw:
        memnomic = "sllw";
        val      = rs1 << rs2;
        break;
    case rv64_op32_srlw:
        memnomic = "srlw";
        val      = rs1 >> rs2;
        break;
    case rv64_op32_sraw:
        memnomic = "sraw";
        val      = rs1 >> rs2;
        break;
    case rv64_op32_mulw:
        memnomic = "mulw";
        val      = rs1 * rs2;
        break;
    case rv64_op32_divw:
        memnomic = "divw";
        val      = rs1 / rs2;
        break;
    case rv64_op32_divuw:
        memnomic = "divuw";
        val      = rs1 / rs2;
        break;
    case rv64_op32_remw:
        memnomic = "remw";
        val      = rs1 % rs2;
        break;
    case rv64_op32_remuw:
        memnomic = "remuw";
        val      = rs1 % rs2;
        break;
    default:
        memnomic = "unk(op32)";
        break;
    }

    TO_SIGNED_HEX_32(val);
    sprintf(buffer, "%-8s %s, %s, %s = %s", memnomic, ra, reg1, reg2, buf_val);
}

void trace_fence(riscvm_ptr self, Instruction inst, char* buffer)
{
    sprintf(buffer, "fence");
}

void trace_auipc(riscvm_ptr self, Instruction inst, char* buffer)
{
    int32_t imm = inst.utype.imm;
    int64_t val = self->pc + (bit_signer(imm, 20) << 12);

    const char* memnomic = "auipc";
    const char* ra       = reg_names[inst.utype.rd];

    TO_SIGNED_HEX_64(val);
    TO_SIGNED_HEX_32(imm);

    sprintf(buffer, "%-8s %s, %s = %s", memnomic, ra, buf_imm, buf_val);
}

void trace_store(riscvm_ptr self, Instruction inst, char* buffer)
{
    int32_t  imm = bit_signer((inst.stype.imm7 << 5) | inst.stype.imm5, 12);
    uint64_t val = reg_read(inst.stype.rs2);

    const char* memnomic = nullptr;
    const char* reg1     = reg_names[inst.stype.rs1];
    const char* reg2     = reg_names[inst.stype.rs2];

    switch (inst.stype.funct3)
    {
    case rv64_store_sb:
    {
        memnomic = "sb";
        break;
    }
    case rv64_store_sh:
    {
        memnomic = "sh";
        break;
    }
    case rv64_store_sw:
    {
        memnomic = "sw";
        break;
    }
    case rv64_store_sd:
    {
        memnomic = "sd";
        break;
    }
    default:
    {
        memnomic = "unk(store)";
        break;
    }
    }

    TO_SIGNED_HEX_64(val);
    TO_SIGNED_HEX_32(imm);

    sprintf(buffer, "%-8s %s, %s(%s) = %s", memnomic, reg2, buf_imm, reg1, buf_val);
}

void trace_lui(riscvm_ptr self, Instruction inst, char* buffer)
{
    int32_t imm = inst.utype.imm;
    int64_t val = bit_signer(imm, 20) << 12;

    const char* memnomic = "lui";
    const char* ra       = reg_names[inst.utype.rd];

    TO_SIGNED_HEX_64(val);
    TO_SIGNED_HEX_32(imm);

    sprintf(buffer, "%-8s %s, %s = %s", memnomic, ra, buf_imm, buf_val);
}

void trace_branch(riscvm_ptr self, Instruction inst, char* buffer)
{
    int32_t imm = (inst.sbtype.imm_12 << 12) |  // Bit 31 -> Position 12
                  (inst.sbtype.imm_5_10 << 5) | // Bits 30-25 -> Positions 10-5
                  (inst.sbtype.imm_1_4 << 1) |  // Bits 11-8 -> Positions 4-1
                  (inst.sbtype.imm_11 << 11);   // Bit 7 -> Position 11

    // Sign extend from the 12th bit
    imm = (imm << 19) >> 19;

    uint64_t val1 = reg_read(inst.sbtype.rs1);
    uint64_t val2 = reg_read(inst.sbtype.rs2);
    bool     cond = false;

    const char* memnomic = nullptr;
    const char* reg1     = reg_names[inst.sbtype.rs1];
    const char* reg2     = reg_names[inst.sbtype.rs2];

    switch (inst.sbtype.funct3)
    {
    case rv64_branch_beq:
        memnomic = "beq";
        cond     = val1 == val2;
        break;
    case rv64_branch_bne:
        memnomic = "bne";
        cond     = val1 != val2;
        break;
    case rv64_branch_blt:
        memnomic = "blt";
        cond     = (int64_t)val1 < (int64_t)val2;
        break;
    case rv64_branch_bge:
        memnomic = "bge";
        cond     = (int64_t)val1 >= (int64_t)val2;
        break;
    case rv64_branch_bltu:
        memnomic = "bltu";
        cond     = val1 < val2;
        break;
    case rv64_branch_bgeu:
        memnomic = "bgeu";
        cond     = val1 >= val2;
        break;
    default:
        memnomic = "unk(branch)";
        break;
    }

    TO_SIGNED_HEX_32(imm);

    if (cond)
    {
        int64_t dest = self->pc + imm;
        TO_SIGNED_HEX_64(dest);
        sprintf(buffer, "%-8s %s, %s, %s -> %s", memnomic, reg1, reg2, buf_imm, buf_dest);
    }
    else
    {
        sprintf(buffer, "%-8s %s, %s, %s (not taken)", memnomic, reg1, reg2, buf_imm);
    }
}

void trace_jalr(riscvm_ptr self, Instruction inst, char* buffer)
{
    int32_t imm = bit_signer(inst.itype.imm, 12);

    const char* memnomic = nullptr;
    const char* ra       = reg_names[inst.itype.rd];
    const char* reg1     = reg_names[inst.itype.rs1];

    if (inst.itype.rs1 == reg_ra)
    {
        g_calldepth--;
        memnomic        = "ret";
        int64_t retaddr = (int64_t)(reg_read(inst.itype.rs1) + imm) & ~1;
        sprintf(buffer, "%-8s (0x%llx)", memnomic, retaddr);
    }
    else
    {
        memnomic = "jalr";
        TO_SIGNED_HEX_32(imm);
        sprintf(buffer, "%-8s %s, %s(%s)", memnomic, ra, buf_imm, reg1);
    }
}

void trace_jal(riscvm_ptr self, Instruction inst, char* buffer)
{
    int64_t imm = bit_signer(
        (inst.ujtype.imm20 << 20) | (inst.ujtype.imm1 << 1) | (inst.ujtype.imm11 << 11)
            | (inst.ujtype.imm12 << 12),
        20
    );

    if (inst.ujtype.rd == reg_ra)
    {
        g_calldepth++;
    }

    const char* memnomic = "jal";
    const char* ra       = reg_names[inst.ujtype.rd];

    TO_SIGNED_HEX_64(imm);
    sprintf(buffer, "%-8s %s, %s -> 0x%llx", memnomic, ra, buf_imm, (self->pc + imm));
}

void trace_system(riscvm_ptr self, Instruction inst, char* buffer)
{
    const char* memnomic = nullptr;

    switch (inst.itype.imm)
    {
    case 0x000:
    {
        uint64_t code = reg_read(reg_a7);
        memnomic      = "ecall";
        sprintf(buffer, "%-8s 0x%llx", memnomic, code);
        return;
    }
    case 0x001:
        memnomic = "ebreak";
        break;
    default:
        memnomic = "unk(system)";
        break;
    }

    sprintf(buffer, "%-8s", memnomic);
}

void riscvm_trace(riscvm_ptr self, Instruction inst)
{
    char buffer[256];

    int calldepth = g_calldepth;

    switch (inst.opcode)
    {
    case rv64_load:
        trace_load(self, inst, buffer);
        break;
    case rv64_fence:
        trace_fence(self, inst, buffer);
        break;
    case rv64_imm64:
        trace_imm64(self, inst, buffer);
        break;
    case rv64_auipc:
        trace_auipc(self, inst, buffer);
        break;
    case rv64_imm32:
        trace_imm32(self, inst, buffer);
        break;
    case rv64_store:
        trace_store(self, inst, buffer);
        break;
    case rv64_op64:
        trace_op64(self, inst, buffer);
        break;
    case rv64_lui:
        trace_lui(self, inst, buffer);
        break;
    case rv64_op32:
        trace_op32(self, inst, buffer);
        break;
    case rv64_branch:
        trace_branch(self, inst, buffer);
        break;
    case rv64_jalr:
        trace_jalr(self, inst, buffer);
        break;
    case rv64_jal:
        trace_jal(self, inst, buffer);
        break;
    case rv64_system:
        trace_system(self, inst, buffer);
        break;
    default:
        printf("Invalid opcode: 0x%x\n", inst.opcode);
        return;
    }

    fprintf(self->trace, "[trace] 0x%016llx: ", self->pc);

    for (int i = 0; i < calldepth; i++)
    {
        fprintf(self->trace, "  ");
    }

    fprintf(self->trace, "%s\n", buffer);

    fflush(self->trace);
}

#else

#define riscvm_trace(...)

#endif // _DEBUG
