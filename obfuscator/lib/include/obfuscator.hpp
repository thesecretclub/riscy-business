#pragma once

#include <string>
#include <vector>

namespace ObfuscatorLib
{

class Obfuscator
{
  public:
    Obfuscator();
    ~Obfuscator();

    bool loadPEFile(const std::string& filePath, const std::string& functionName, bool verbose = false);
    bool disassembleFunction(const std::string& functionName, bool verbose = false);
    bool analyzeFunction(bool verbose = false);
    bool obfuscateFunction(bool verbose = false);
    bool serialize(std::vector<uint8_t>& outputCode, bool verbose = false);

  private:
    class Impl;
    Impl* impl_;
};

} // namespace ObfuscatorLib
