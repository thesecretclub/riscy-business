#pragma once

#include <zasm/zasm.hpp>
#include "cfg.hpp"

namespace ObfuscatorLib
{

using namespace zasm;

class Analyzer
{
  public:
    Analyzer(Program& program, CFG& cfg);

    bool analyze(bool verbose = false);
    CFG& getCFG();

  private:
    Program& program_;
    CFG&      cfg_;
};

} // namespace ObfuscatorLib
