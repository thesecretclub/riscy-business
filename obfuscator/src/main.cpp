#include "obfuscator.hpp"
#include "logger.hpp"
#include <vector>
#include <fstream>

using namespace ObfuscatorLib;

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        Logger::logError("Usage: %s <input_file> [output_file]", argv[0]);
        return EXIT_FAILURE;
    }

    std::string inputFilePath  = argv[1];
    std::string outputFilePath = "obfuscated_function.bin";
    if (argc >= 3)
    {
        outputFilePath = argv[2];
    }

    Obfuscator        obfuscator;
    const std::string functionName = "riscvm_run";

    Logger::logInfo("Loading PE file: %s", inputFilePath.c_str());
    Logger::logInfo("Obfuscating function: %s", functionName.c_str());

    if (!obfuscator.loadPEFile(inputFilePath, functionName, true))
    {
        Logger::logError("Failed to load PE file: %s", inputFilePath.c_str());
        return EXIT_FAILURE;
    }

    Logger::logInfo("Disassembling function: %s", functionName.c_str());

    if (!obfuscator.disassembleFunction(functionName, true))
    {
        Logger::logError("Failed to disassemble function");
        return EXIT_FAILURE;
    }

    Logger::logInfo("Analyzing function: %s", functionName.c_str());

    if (!obfuscator.analyzeFunction(true))
    {
        Logger::logError("Failed to analyze function");
        return EXIT_FAILURE;
    }

    Logger::logInfo("Obfuscating function: %s", functionName.c_str());

    if (!obfuscator.obfuscateFunction(true))
    {
        Logger::logError("Failed to obfuscate function");
        return EXIT_FAILURE;
    }

    std::vector<uint8_t> outputCode;

    if (!obfuscator.serialize(outputCode))
    {
        Logger::logError("Failed to serialize obfuscated function");
        return EXIT_FAILURE;
    }

    std::ofstream file(outputFilePath, std::ios::binary);
    if (!file)
    {
        Logger::logError("Failed to open file for writing: %s", outputFilePath.c_str());
        return EXIT_FAILURE;
    }
    file.write((const char*)outputCode.data(), outputCode.size());

    Logger::logInfo("Obfuscated function saved to: %s", outputFilePath.c_str());

    return EXIT_SUCCESS;
}
