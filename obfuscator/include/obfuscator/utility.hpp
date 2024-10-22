#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <string_view>
#include <string>

namespace obfuscator
{
bool loadFile(const std::string& path, std::vector<uint8_t>& data);
bool findFunction(const std::span<uint8_t>& pe, std::string_view name, uint64_t& address, std::vector<uint8_t>& code);
} // namespace obfuscator
