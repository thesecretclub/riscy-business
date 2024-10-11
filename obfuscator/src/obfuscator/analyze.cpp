#include <obfuscator/analyze.hpp>
#include <obfuscator/msvc-secure.hpp>

#include <zasm/formatter/formatter.hpp>

#include <set>
#include <map>
#include <queue>

namespace obfuscator
{

using namespace zasm;

bool analyze(Context& ctx, bool verbose)
{
    Program& program = ctx.program;
    auto     mode    = program.getMode();
    if (verbose)
        puts("=== ANALYZE ===");
    std::vector<Label> queue;
    queue.push_back(program.getEntryPoint());
    std::set<Label::Id> visisted;

    // Construct the control flow graph
    struct BasicBlock
    {
        uint64_t           address = 0;
        Label              label;
        Node*              begin = nullptr;
        Node*              end   = nullptr;
        std::vector<Label> successors;

        uint32_t regsGen     = 0;
        uint32_t regsKill    = 0;
        uint32_t regsLiveIn  = 0;
        uint32_t regsLiveOut = 0;

        InstrCPUFlags flagsGen     = 0;
        InstrCPUFlags flagsKill    = 0;
        InstrCPUFlags flagsLiveIn  = 0;
        InstrCPUFlags flagsLiveOut = 0;
    };

    std::map<uint64_t, BasicBlock> blocks;
    std::set<uint64_t>             exits;
    while (!queue.empty())
    {
        auto blockStartLabel = queue.back();
        queue.pop_back();

        if (visisted.count(blockStartLabel.getId()))
        {
            continue;
        }
        visisted.insert(blockStartLabel.getId());

        const auto& labelData    = *program.getLabelData(blockStartLabel);
        auto        blockAddress = labelData.node->getUserData<InstructionData>()->address;

        BasicBlock bb;
        bb.address = blockAddress;
        bb.label   = blockStartLabel;
        bb.begin   = labelData.node->getNext();
        if (bb.begin == nullptr)
        {
            puts("empty block!");
            __debugbreak();
        }
        if (verbose)
            printf("<==> Disassembling block: %s (0x%llX)\n", labelData.name, blockAddress);

        auto node     = labelData.node->getNext();
        bool finished = false;
        while (!finished)
        {
            auto instr = node->getIf<Instruction>();
            if (instr == nullptr)
            {
                auto label = node->getIf<Label>();
                queue.push_back(*label);
                bb.successors.push_back(*label);
                if (verbose)
                    puts("not instr!");
                break;
            }

            auto data = node->getUserData<InstructionData>();
            auto str  = formatter::toString(program, instr, formatter::Options::HexImmediates);
            if (verbose)
                printf("0x%llX|%s\n", data->address, str.c_str());

            auto info = *instr->getDetail(mode);
            switch (info.getCategory())
            {
            case x86::Category::UncondBR:
            {
                auto dest = instr->getOperand<Label>(0);
                if (verbose)
                    printf("UncondBR: %d\n", dest.getId());
                queue.push_back(dest);
                bb.successors.push_back(dest);
                finished = true;
            }
            break;

            case x86::Category::CondBr:
            {
                auto brtrue  = instr->getOperand<Label>(0);
                auto brfalse = node->getNext()->get<Label>();
                if (verbose)
                    printf("CondBr: %d, %d\n", brtrue.getId(), brfalse.getId());
                queue.push_back(brfalse);
                queue.push_back(brtrue);
                bb.successors.push_back(brtrue);
                bb.successors.push_back(brfalse);
                finished = true;
            }
            break;

            case x86::Category::Call:
            {
                auto dest = instr->getOperand(0);
                if (dest.getIf<Label>() != nullptr)
                {
                    printf("unsupported call imm 0x%llX\n", data->address);
                    return false;
                }
            }
            break;

            case x86::Category::Ret:
            {
                finished = true;
                exits.insert(bb.address);
            }
            break;

            default:
            {
            }
            break;
            }

            node = node->getNext();
        }

        bb.end = node;
        if (bb.end == nullptr)
        {
            puts("empty block!");
            __debugbreak();
        }

        blocks.emplace(bb.address, bb);
    }

    // Compute the predecessors for each block
    std::map<uint64_t, std::set<uint64_t>> predecessors;
    for (const auto& [address, _] : blocks)
    {
        predecessors[address] = {};
    }

    for (const auto& [address, block] : blocks)
    {
        for (const auto& successor : block.successors)
        {
            auto data = program.getLabelData(successor).value().node->getUserData<InstructionData>();
            auto successorAddress = data->address;
            predecessors[successorAddress].insert(address);
        }
    }

    // Perform liveness analysis on the control flow graph
    // https://en.wikipedia.org/wiki/Live-variable_analysis

    // TODO: confirm this statement
    // water: "Dominator tree would not work for this, because it
    // does not take into account the next iteration of the loop"

    // Compute the GEN and KILL sets for each block
    for (auto& [address, block] : blocks)
    {
        if (verbose)
        {
            auto str = formatter::toString(program, block.begin, block.end, formatter::Options::HexImmediates);
            printf("Analyzing block 0x%llX\n==========\n%s\n==========\n", address, str.c_str());
        }

        for (auto node = block.begin; node != block.end; node = node->getNext())
        {
            auto  data   = node->getUserData<InstructionData>();
            auto& detail = data->detail;

            if (verbose)
            {
                auto instrText = formatter::toString(program, node, formatter::Options::HexImmediates);
                printf("0x%llX|%s\n", data->address, instrText.c_str());
                printf("\tregs read: %s\n", formatRegsMask(data->regsRead).c_str());
                printf("\tregs written: %s\n", formatRegsMask(data->regsWritten).c_str());
                printf("\tflags tested: %s\n", formatFlagsMask(data->flagsTested).c_str());
                printf("\tflags modified: %s\n", formatFlagsMask(data->flagsModified).c_str());
            }

            block.regsGen |= data->regsRead & ~block.regsKill;
            block.regsKill |= data->regsWritten;
            block.flagsGen  = block.flagsGen | (data->flagsTested & ~block.flagsKill);
            block.flagsKill = block.flagsKill | data->flagsModified;
        }

        if (verbose)
        {
            printf("regs_gen: %s\n", formatRegsMask(block.regsGen).c_str());
            printf("regs_kill: %s\n", formatRegsMask(block.regsKill).c_str());
            printf("flags_gen: %s\n", formatFlagsMask(block.flagsGen).c_str());
            printf("flags_kill: %s\n", formatFlagsMask(block.flagsKill).c_str());
        }
    }

    // Solve the dataflow equations
    std::queue<uint64_t> worklist;
    for (auto exit : exits)
    {
        worklist.push(exit);
    }
    while (!worklist.empty())
    {
        auto address = worklist.front();
        worklist.pop();

        auto&         block          = blocks.at(address);
        auto          newRegsLiveIn  = block.regsGen | (block.regsLiveOut & ~block.regsKill);
        InstrCPUFlags newFlagsLiveIn = block.flagsGen | (block.flagsLiveOut & ~block.flagsKill);
        if (newRegsLiveIn != block.regsLiveIn || newFlagsLiveIn != block.flagsLiveIn)
        {
            // Update the LIVEin sets
            block.regsLiveIn  = newRegsLiveIn;
            block.flagsLiveIn = newFlagsLiveIn;

            // Update the LIVEout sets in the predecessors and add them to the worklist
            for (const auto& predecessor : predecessors.at(address))
            {
                auto& predecessorBlock = blocks.at(predecessor);
                predecessorBlock.regsLiveOut |= newRegsLiveIn;
                predecessorBlock.flagsLiveOut = predecessorBlock.flagsLiveOut | newFlagsLiveIn;
                worklist.push(predecessor);
            }
        }
    }

    // Compute liveness backwards for each block individually
    for (auto& [address, block] : blocks)
    {
        if (verbose)
        {
            auto str = formatter::toString(program, block.begin, block.end, formatter::Options::HexImmediates);
            printf("Analyzing block 0x%llX\n==========\n%s\n==========\n", address, str.c_str());
        }

        // We start with the live-out set of the block
        InstrCPUFlags flagsLive = block.flagsLiveOut;
        uint32_t      regsLive  = block.regsLiveOut;
        for (auto node = block.end->getPrev(); node != block.begin->getPrev(); node = node->getPrev())
        {
            auto  data   = node->getUserData<InstructionData>();
            auto& detail = data->detail;

            auto flagsModified = data->flagsModified;
            auto flagsTested   = data->flagsTested;
            auto regsRead      = data->regsRead;
            auto regsWritten   = data->regsWritten;

            if (verbose)
            {
                auto instrText = formatter::toString(program, node, formatter::Options::HexImmediates);
                printf("0x%llX|%s\n", data->address, instrText.c_str());
                printf("\tflags modified: %s\n", formatFlagsMask(flagsModified).c_str());
                printf("\tflags tested: %s\n", formatFlagsMask(flagsTested).c_str());
                printf("\tregs read: %s\n", formatRegsMask(regsRead).c_str());
                printf("\tregs written: %s\n", formatRegsMask(regsWritten).c_str());

                if (flagsModified & flagsLive)
                {
                    printf("\tlive flags are modified: %s\n", formatFlagsMask(flagsModified & flagsLive).c_str());
                }

                if (flagsTested & flagsLive)
                {
                    printf("\tlive flags are tested: %s\n", formatFlagsMask(flagsTested & flagsLive).c_str());
                }
            }

            // If the flag is tested, it becomes live
            if (flagsTested)
            {
                flagsLive = flagsLive | flagsTested;
                if (verbose)
                    printf("\tnew live flags: %s\n", formatFlagsMask(flagsLive).c_str());
            }

            if (regsRead)
            {
                regsLive = regsLive | regsRead;
                if (verbose)
                    printf("\tnew live regs: %s\n", formatRegsMask(regsLive).c_str());
            }

            // Store the liveness state for the instruction
            data->flagsLive = flagsLive;
            data->regsLive  = regsLive;

            if (flagsModified)
            {
                // If the flag is overwritten, it becomes dead
                flagsLive = flagsLive & ~(flagsModified & ~flagsTested);
            }

            if (regsWritten)
            {
                // If the register is overwritten, it becomes dead
                // This fixes a special case where a register is both read and written by
                // the same instruction, which would otherwise cause incorrectly to be marked as dead
                regsLive = regsLive & ~(regsWritten & ~regsRead);
            }

            if (verbose)
            {
                printf("\tfinal live flags: %s\n", formatFlagsMask(data->flagsLive).c_str());
                printf("\tfinal live regs: %s\n", formatRegsMask(data->regsLive).c_str());
            }
        }
    }

    // Print the results
    if (verbose)
    {
        std::string script;
        for (const auto& [address, block] : blocks)
        {
            printf("Results for block 0x%llX\n==========\n", address);
            for (auto node = block.begin; node != block.end; node = node->getNext())
            {
                auto data = node->getUserData<InstructionData>();
                auto str  = formatter::toString(program, node, formatter::Options::HexImmediates);

                script += "commentset ";
                char address[32];
                sprintf_s(address, "0x%llX", data->address);
                script += address;
                script += ", \"";
                if (data->regsLive || data->flagsLive)
                {
                    script += formatRegsMask(data->regsLive);
                    if (data->flagsLive)
                    {
                        script += "|";
                        script += formatFlagsMask(data->flagsLive);
                    }
                }
                else
                {
                    script += "no live (HA)";
                }
                script += "\"\n";

                printf(
                    "0x%llX|%s|%s|%s\n",
                    data->address,
                    str.c_str(),
                    formatRegsMask(data->regsLive).c_str(),
                    formatFlagsMask(data->flagsLive).c_str()
                );

                if (data->regsRead & ~data->regsLive)
                {
                    printf("\tdead regs read: %s\n", formatRegsMask(data->regsRead & ~data->regsLive).c_str());
                    __debugbreak();
                }
            }
            puts("==========");

            printf("\tregs_live_in: %s\n", formatRegsMask(block.regsLiveIn).c_str());
            printf("\tregs_live_out: %s\n", formatRegsMask(block.regsLiveOut).c_str());
            printf("\tflags_live_in: %s\n", formatFlagsMask(block.flagsLiveIn).c_str());
            printf("\tflags_live_out: %s\n", formatFlagsMask(block.flagsLiveOut).c_str());
        }

        puts(script.c_str());

        auto toHex = [](uint64_t value)
        {
            char buffer[64] = "";
            sprintf_s(buffer, "\"0x%llX\"", value);
            return std::string(buffer);
        };

        std::string dot = "digraph G {\n";
        for (const auto& [address, block] : blocks)
        {
            dot += toHex(address) + " [label=\"" + program.getLabelData(block.label).value().name + "\"];\n";
            for (const auto& successor : block.successors)
            {
                auto data = program.getLabelData(successor).value().node->getUserData<InstructionData>();
                auto successorAddress = data->address;
                dot += toHex(address) + " -> " + toHex(successorAddress) + ";\n";
            }
        }
        dot += "}";

        puts(dot.c_str());
    }

    return true;
}
} // namespace obfuscator
