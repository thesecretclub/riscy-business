#include <zasm/zasm.hpp>
#include "analyzer.hpp"

namespace ObfuscatorLib
{

using namespace zasm;

class ObfuscatorCore
{
  public:
    ObfuscatorCore(Program& program, Analyzer& analyzer);

    bool obfuscate(bool verbose = false);

  private:
    Program& program_;
    Analyzer& analyzer_;
};

} // namespace ObfuscatorLib
