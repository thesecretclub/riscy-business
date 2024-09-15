#pragma once

#include <string>
#include <vector>

namespace ObfuscatorLib
{

class PELoader
{
  public:
    PELoader();
    ~PELoader();

    bool loadFile(const std::string& filePath);
    bool extractFunction(const std::string& functionName, uintptr_t& address, std::vector<uint8_t>& functionData);

  private:
    std::vector<uint8_t> peData_;
};

} // namespace ObfuscatorLib
