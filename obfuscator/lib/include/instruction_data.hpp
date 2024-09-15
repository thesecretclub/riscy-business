#pragma once

#include <zasm/zasm.hpp>

namespace ObfuscatorLib
{

using namespace zasm;

struct InstructionData
{
    uint64_t address       = 0;
    uint32_t flagsModified = 0;
    uint32_t flagsTested   = 0;
    uint32_t regsWritten   = 0;
    uint32_t regsRead      = 0;

    uint32_t regsLive  = 0;
    uint32_t flagsLive = 0;

    zasm::InstructionDetail detail;
};

} // namespace ObfuscatorLib
