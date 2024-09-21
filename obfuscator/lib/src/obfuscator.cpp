#include "logger.hpp"
#include "obfuscator.hpp"
#include "obfuscator_core.hpp"
#include "context.hpp"
#include "disassembler.hpp"
#include "analyzer.hpp"
#include "pe_loader.hpp"
#include <fstream>
#include <zasm/formatter/formatter.hpp>

namespace ObfuscatorLib
{

using namespace zasm;

class Obfuscator::Impl
{
  public:
    Impl();

    bool loadPEFile(const std::string& filePath, const std::string& functionName, bool verbose = false);
    bool disassembleFunction(const std::string& functionName, bool verbose = false);
    bool analyzeFunction(bool verbose = false);
    bool obfuscateFunction(bool verbose = false);
    bool serialize(std::vector<uint8_t>& outputCode, bool verbose = false);

  private:
    PELoader       peLoader_;
    Program        program_;
    Context        context_;
    Disassembler   disassembler_;
    CFG            cfg_;
    Analyzer       analyzer_;
    ObfuscatorCore obfuscatorCore_;

    uint64_t             functionAddress_;
    std::vector<uint8_t> functionData_;
};

Obfuscator::Obfuscator() : impl_(new Impl())
{
}

Obfuscator::~Obfuscator()
{
    delete impl_;
}

bool Obfuscator::loadPEFile(const std::string& filePath, const std::string& functionName, bool verbose)
{
    return impl_->loadPEFile(filePath, functionName, verbose);
}

bool Obfuscator::disassembleFunction(const std::string& functionName, bool verbose)
{
    return impl_->disassembleFunction(functionName, verbose);
}

bool Obfuscator::analyzeFunction(bool verbose)
{
    return impl_->analyzeFunction(verbose);
}

bool Obfuscator::obfuscateFunction(bool verbose)
{
    return impl_->obfuscateFunction(verbose);
}

bool Obfuscator::serialize(std::vector<uint8_t>& outputCode, bool verbose)
{
    return impl_->serialize(outputCode, verbose);
}

// Implementation of Obfuscator::Impl
Obfuscator::Impl::Impl()
    : program_(MachineMode::AMD64)
    , context_(program_)
    , disassembler_(program_, context_)
    , analyzer_(program_, cfg_)
    , obfuscatorCore_(program_, analyzer_)
{
}

bool Obfuscator::Impl::loadPEFile(const std::string& filePath, const std::string& functionName, bool verbose)
{
    if (!peLoader_.loadFile(filePath))
    {
        Logger::logError("Failed to load PE file: %s", filePath.c_str());
        return false;
    }

    if (!peLoader_.extractFunction(functionName, functionAddress_, functionData_))
    {
        Logger::logError("Failed to extract function: %s", functionName.c_str());
        return false;
    }

    if (verbose)
    {
        Logger::logInfo("Function %s extracted at address 0x%llX", functionName.c_str(), functionAddress_);
    }

    return true;
}

bool Obfuscator::Impl::disassembleFunction(const std::string& functionName, bool verbose)
{
    return disassembler_.disassemble(functionName, functionAddress_, functionData_, verbose);
}

bool Obfuscator::Impl::analyzeFunction(bool verbose)
{
    return analyzer_.analyze(verbose);
}

bool Obfuscator::Impl::obfuscateFunction(bool verbose)
{
    return obfuscatorCore_.obfuscate(verbose);
}

bool Obfuscator::Impl::serialize(std::vector<uint8_t>& outputCode, bool verbose)
{
    Serializer serializer;
    uint64_t   baseAddress = 0;

    if (verbose)
    {
        Logger::logInfo("Serializing program");
        auto outputCode = formatter::toString(program_);
        Logger::logLine(outputCode.c_str());
    }

    if (auto res = serializer.serialize(program_, baseAddress); res != ErrorCode::None)
    {
        Logger::logError("Failed to serialize program");
        return false;
    }

    auto code = serializer.getCode();
    auto size = serializer.getCodeSize();

    outputCode.resize(size);
    std::copy(code, code + size, outputCode.data());

    return true;
}

} // namespace ObfuscatorLib
