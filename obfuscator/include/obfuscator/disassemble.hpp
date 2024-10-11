#pragma once

#include <obfuscator/context.hpp>

namespace obfuscator
{
bool disassemble(Context& ctx, const uint64_t functionStart, const std::vector<uint8_t>& code, bool verbose = false);
}
