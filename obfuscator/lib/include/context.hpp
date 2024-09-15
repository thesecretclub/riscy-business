#pragma once

#include <deque>
#include <vector>
#include <zasm/zasm.hpp>
#include "instruction_data.hpp"


namespace ObfuscatorLib
{

using namespace zasm;

class Context
{
  public:
    Context(Program& program);

    void addInstructionData(Node* node, uintptr_t address, const InstructionDetail& detail);

  private:
    Program& program_;
    std::deque<InstructionData> instructionDataPool_;
};

} // namespace ObfuscatorLib
