#pragma once

#include <stdint.h>

enum Opcode
{
    rv64_lui     = 0b00000, // original: 0b01101
    rv64_imm32   = 0b00001, // original: 0b00110
    rv64_fence   = 0b00010, // original: 0b00011
    rv64_jal     = 0b00011, // original: 0b11011
    rv64_auipc   = 0b00100, // original: 0b00101
    rv64_op32    = 0b00101, // original: 0b01110
    rv64_branch  = 0b00110, // original: 0b11000
    rv64_jalr    = 0b00111, // original: 0b11001
    rv64_op64    = 0b01000, // original: 0b01100
    rv64_store   = 0b01001, // original: 0b01000
    rv64_imm64   = 0b01010, // original: 0b00100
    rv64_load    = 0b01011, // original: 0b00000
    rv64_system  = 0b01100, // original: 0b11100
    rv64_invalid = 0b11111, // placeholder
};

static uint8_t riscvm_original_opcode(uint8_t insn)
{
    switch (insn)
    {
    case rv64_load:
        return 0b00000;
    case rv64_fence:
        return 0b00011;
    case rv64_imm64:
        return 0b00100;
    case rv64_auipc:
        return 0b00101;
    case rv64_imm32:
        return 0b00110;
    case rv64_store:
        return 0b01000;
    case rv64_op64:
        return 0b01100;
    case rv64_lui:
        return 0b01101;
    case rv64_op32:
        return 0b01110;
    case rv64_branch:
        return 0b11000;
    case rv64_jalr:
        return 0b11001;
    case rv64_jal:
        return 0b11011;
    case rv64_system:
        return 0b11100;
    default:
        return rv64_invalid;
    }
}
