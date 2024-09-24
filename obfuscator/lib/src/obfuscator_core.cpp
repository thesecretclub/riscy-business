#include "obfuscator_core.hpp"
#include "instruction_data.hpp"
#include "util.hpp"

namespace ObfuscatorLib
{

using namespace zasm;

ObfuscatorCore::ObfuscatorCore(Program& program, Analyzer& analyzer) : program_(program), analyzer_(analyzer)
{
    srand(1337);
}

bool ObfuscatorCore::obfuscate(bool verbose)
{
    x86::Assembler assembler(program_);

    auto entryNode = const_cast<Node*>(program_.getLabelData(program_.getEntryPoint()).value().node);
    for (auto node = entryNode; node != nullptr;)
    {
        auto prev = node->getPrev();
        auto next = node->getNext();
        if (auto instr = node->getIf<Instruction>(); instr != nullptr)
        {
            auto data   = node->getUserData<InstructionData>();

            auto regsDeadMask = ~data->regsLive;
            auto regsDead     = maskToRegs(regsDeadMask);

            assembler.setCursor(prev);

            for (auto deadReg : regsDead)
            {
                assembler.mov(deadReg, Imm(rand()));
            }
        }

        node = next;
    }

    return true;
}

} // namespace ObfuscatorLib
