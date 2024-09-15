#pragma once

#include "context.hpp"
#include <string>
#include <vector>
#include <zasm/zasm.hpp>

namespace ObfuscatorLib
{

using namespace zasm;

class Disassembler
{
  public:
    Disassembler(Program& program, Context& context);

    bool disassemble(
        const std::string& functionName, uintptr_t address, const std::vector<uint8_t>& code, bool verbose = false
    );

  private:
    Program& program_;
    Context& ctx_;
};

} // namespace ObfuscatorLib
