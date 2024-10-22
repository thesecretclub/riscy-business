#include <fstream>
#include <iostream>
#include <cstdlib>
#include <vector>

#include <obfuscator/msvc-secure.hpp>
#include <obfuscator/utility.hpp>

#include <zasm/zasm.hpp>
#include <zasm/formatter/formatter.hpp>

#include <fmt/format.h>
#include <args.hpp>

using namespace zasm;
using namespace obfuscator;

#include <obfuscator/context.hpp>
#include <obfuscator/disassemble.hpp>
#include <obfuscator/analyze.hpp>
#include <obfuscator/obfuscate.hpp>

struct Arguments : ArgumentParser
{
    std::string input;
    std::string output;
    std::string cleanOutput;
    std::string payload;

    Arguments(int argc, char** argv) : ArgumentParser("Obfuscates the riscvm_run function")
    {
        addPositional("input", input, "Input PE file to obfuscate", true);
        addString("-output", output, "Obfuscated function binary blob");
        addString("-clean-output", cleanOutput, "Unobfuscated function binary blob");
        addString("-payload", payload, "Payload to execute (Windows only)");
        parseOrExit(argc, argv);
    }
};

int main(int argc, char** argv)
{
    Arguments args(argc, argv);

    std::vector<uint8_t> pe;
    if (!loadFile(args.input, pe))
    {
        fmt::println("Failed to load the executable.");
        return EXIT_FAILURE;
    }

    uint64_t             riscvmRunAddress = 0;
    std::vector<uint8_t> riscvmRunCode;
    if (!findFunction(pe, "riscvm_run", riscvmRunAddress, riscvmRunCode))
    {
        fmt::println("Failed to find riscvm_run function.");
        return EXIT_FAILURE;
    }

    fmt::println("riscvm_run address: {:#x}, size: {:#x}", riscvmRunAddress, riscvmRunCode.size());

    Program program(MachineMode::AMD64);
    Context ctx(program);
    if (!disassemble(ctx, riscvmRunAddress, riscvmRunCode))
    {
        fmt::println("Failed to disassemble riscvm_run function.");
        return EXIT_FAILURE;
    }

    if (!analyze(ctx, true))
    {
        fmt::println("Failed to analyze the riscvm_run function.");
        return EXIT_FAILURE;
    }

    auto serializeToFile = [&program](const std::string& outputFile, uint64_t base = 0)
    {
        // Serialize the obfuscated function
        Serializer serializer;
        if (auto res = serializer.serialize(program, base); res != zasm::ErrorCode::None)
        {
            fmt::println("Failed to serialize program at {:#x}, {}", base, res.getErrorName());
            return false;
        }

        auto ptr  = serializer.getCode();
        auto size = serializer.getCodeSize();

        // Save the code to disk
        std::ofstream ofs(outputFile, std::ios::binary);
        ofs.write((char*)ptr, size);
        return true;
    };

    if (!args.cleanOutput.empty() && !serializeToFile(args.cleanOutput))
    {
        return EXIT_FAILURE;
    }

    if (!obfuscate(ctx))
    {
        fmt::println("Failed to obfuscate riscvm_run function.");
        return EXIT_FAILURE;
    }

    fmt::println("\n{}", formatter::toString(program));

    if (!args.output.empty() && !serializeToFile(args.output))
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
