#include <obfuscator/obfuscate.hpp>
#include <fmt/format.h>

namespace obfuscator
{
using namespace zasm;

bool obfuscate(Context& ctx)
{
    Program&       program = ctx.program;
    x86::Assembler assembler(program);

    // Ideas:
    // - After a branch, put a cmov into a live register that we know will never trigger
    // - Block shuffling
    // - Move into dead registers that were live before somewhere
    // - Add dead code
    // - Replace cmp with arithmetic into recently-live registers
    // - Instruction substitution
    // - Add nops
    // - Add opaque predicates (into middle of instructions)
    // - Sprinkle a little unicorn detection (maybe in-payload only)

    fmt::println("=== OBFUSCATE === ");
    srand(1337);
    auto entryNode = program.getLabelData(program.getEntryPoint()).value().node;
    for (auto node = entryNode; node != nullptr;)
    {
        auto next = node->getNext();
        if (auto instr = node->getIf<Instruction>(); instr != nullptr)
        {
            auto data = node->getUserData<InstructionData>();
            assembler.setCursor(node->getPrev());

            auto regsDeadMask = ~data->regsLive;
            auto regsDead     = maskToRegs(regsDeadMask);
            for (auto deadReg : regsDead)
            {
                assembler.mov(deadReg, Imm(rand()));
            }
        }

        node = next;
    }
    return true;
}
} // namespace obfuscator
