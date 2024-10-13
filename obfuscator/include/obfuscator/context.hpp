#pragma once

#include <deque>
#include <zasm/zasm.hpp>
#include <fmt/format.h>

template <> struct fmt::formatter<zasm::Node::Id> : fmt::formatter<std::string_view>
{
    fmt::format_context::iterator format(const zasm::Node::Id& id, fmt::format_context& ctx) const
    {
        return fmt::formatter<std::string_view>::format(fmt::format("{}", (uint32_t)id), ctx);
    }
};

template <> struct fmt::formatter<zasm::Label::Id> : fmt::formatter<std::string_view>
{
    fmt::format_context::iterator format(const zasm::Label::Id& id, fmt::format_context& ctx) const
    {
        return fmt::formatter<std::string_view>::format(fmt::format("{}", (int32_t)id), ctx);
    }
};

namespace obfuscator
{

std::string                formatFlagsMask(uint32_t mask);
std::string                formatRegsMask(uint64_t mask);
std::vector<zasm::x86::Gp> maskToRegs(uint64_t mask);
uint32_t                   regMask(const zasm::Reg& reg);

struct InstructionData
{
    uint64_t                address       = 0;
    zasm::InstructionDetail detail        = {};
    zasm::InstrCPUFlags     flagsModified = 0;
    zasm::InstrCPUFlags     flagsTested   = 0;
    uint32_t                regsWritten   = 0;
    uint32_t                regsRead      = 0;

    zasm::InstrCPUFlags flagsLive = 0;
    uint32_t            regsLive  = 0;
};

// Stores additional data for nodes in the zasm::Program
struct Context
{
    zasm::Program& program;

    explicit Context(zasm::Program& program) : program(program)
    {
    }

    InstructionData* addInstructionData(
        zasm::Node* node, uint64_t address, zasm::MachineMode mode, const zasm::InstructionDetail& detail
    );

  private:
    std::deque<InstructionData> instructionDataPool;
};

} // namespace obfuscator
