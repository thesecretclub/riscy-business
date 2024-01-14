#pragma once

#include <stdint.h>

enum RV64_Opcode
{
    rv64_imm32 = 0b00000, // original 0b00110
    rv64_lui = 0b00001, // original 0b01101
    rv64_jal = 0b00010, // original 0b11011
    rv64_op32 = 0b00011, // original 0b01110
    rv64_system = 0b00100, // original 0b11100
    rv64_fence = 0b00101, // original 0b00011
    rv64_op64 = 0b00110, // original 0b01100
    rv64_imm64 = 0b00111, // original 0b00100
    rv64_load = 0b01000, // original 0b00000
    rv64_store = 0b01001, // original 0b01000
    rv64_jalr = 0b01010, // original 0b11001
    rv64_auipc = 0b01011, // original 0b00101
    rv64_branch = 0b01100, // original 0b11000
    rv64_invalid = 0b11111, // placeholder
};

enum RV64_Op64
{
    rv64_op64_mulhsu = 0b00000, // original 0b01010
    rv64_op64_srl = 0b00001, // original 0b00101
    rv64_op64_and = 0b00010, // original 0b00111
    rv64_op64_sub = 0b00011, // original 0b100000000
    rv64_op64_divu = 0b00100, // original 0b01101
    rv64_op64_xor = 0b00101, // original 0b00100
    rv64_op64_mulh = 0b00110, // original 0b01001
    rv64_op64_sltu = 0b00111, // original 0b00011
    rv64_op64_slt = 0b01000, // original 0b00010
    rv64_op64_mul = 0b01001, // original 0b01000
    rv64_op64_remu = 0b01010, // original 0b01111
    rv64_op64_or = 0b01011, // original 0b00110
    rv64_op64_mulhu = 0b01100, // original 0b01011
    rv64_op64_div = 0b01101, // original 0b01100
    rv64_op64_sra = 0b01110, // original 0b100000101
    rv64_op64_sll = 0b01111, // original 0b00001
    rv64_op64_rem = 0b10000, // original 0b01110
    rv64_op64_add = 0b10001, // original 0b00000
    rv64_op64_invalid = 0b11111, // placeholder
};

enum RV64_Op32
{
    rv64_op32_addw = 0b00000, // original 0b00000
    rv64_op32_remuw = 0b00001, // original 0b01111
    rv64_op32_sraw = 0b00010, // original 0b100000101
    rv64_op32_srlw = 0b00011, // original 0b00101
    rv64_op32_sllw = 0b00100, // original 0b00001
    rv64_op32_remw = 0b00101, // original 0b01110
    rv64_op32_divw = 0b00110, // original 0b01100
    rv64_op32_subw = 0b00111, // original 0b100000000
    rv64_op32_divuw = 0b01000, // original 0b01101
    rv64_op32_mulw = 0b01001, // original 0b01000
    rv64_op32_invalid = 0b11111, // placeholder
};

enum RV64_Imm64
{
    rv64_imm64_ori = 0b00000, // original 0b00110
    rv64_imm64_slti = 0b00001, // original 0b00010
    rv64_imm64_xori = 0b00010, // original 0b00100
    rv64_imm64_slli = 0b00011, // original 0b00001
    rv64_imm64_andi = 0b00100, // original 0b00111
    rv64_imm64_sltiu = 0b00101, // original 0b00011
    rv64_imm64_addi = 0b00110, // original 0b00000
    rv64_imm64_srxi = 0b00111, // original 0b00101
    rv64_imm64_invalid = 0b11111, // placeholder
};

enum RV64_Imm32
{
    rv64_imm32_srxiw = 0b00000, // original 0b00101
    rv64_imm32_slliw = 0b00001, // original 0b00001
    rv64_imm32_addiw = 0b00010, // original 0b00000
    rv64_imm32_invalid = 0b11111, // placeholder
};

enum RV64_Load
{
    rv64_load_lw = 0b00000, // original 0b00010
    rv64_load_lwu = 0b00001, // original 0b00110
    rv64_load_lb = 0b00010, // original 0b00000
    rv64_load_ld = 0b00011, // original 0b00011
    rv64_load_lbu = 0b00100, // original 0b00100
    rv64_load_lh = 0b00101, // original 0b00001
    rv64_load_lhu = 0b00110, // original 0b00101
    rv64_load_invalid = 0b11111, // placeholder
};

enum RV64_Store
{
    rv64_store_sh = 0b00000, // original 0b00001
    rv64_store_sw = 0b00001, // original 0b00010
    rv64_store_sd = 0b00010, // original 0b00011
    rv64_store_sb = 0b00011, // original 0b00000
    rv64_store_invalid = 0b11111, // placeholder
};

enum RV64_Branch
{
    rv64_branch_bne = 0b00000, // original 0b00001
    rv64_branch_beq = 0b00001, // original 0b00000
    rv64_branch_bgeu = 0b00010, // original 0b00111
    rv64_branch_blt = 0b00011, // original 0b00100
    rv64_branch_bge = 0b00100, // original 0b00101
    rv64_branch_bltu = 0b00101, // original 0b00110
    rv64_branch_invalid = 0b11111, // placeholder
};

