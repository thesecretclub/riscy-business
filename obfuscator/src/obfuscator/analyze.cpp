#include <obfuscator/analyze.hpp>
#include <obfuscator/msvc-secure.hpp>

#include <zasm/formatter/formatter.hpp>
#include <fmt/format.h>

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
        fmt::println("=== ANALYZE ===");
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
            fmt::println("empty block!");
            __debugbreak();
        }
        if (verbose)
            fmt::println("<==> Disassembling block: {} ({:#x})", labelData.name, blockAddress);

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
                    fmt::println("not instr!");
                break;
            }

            auto data = node->getUserData<InstructionData>();
            auto str  = formatter::toString(program, instr, formatter::Options::HexImmediates);
            if (verbose)
                fmt::println("{:#x}|{}", data->address, str);

            auto info = *instr->getDetail(mode);
            switch (info.getCategory())
            {
            case x86::Category::UncondBR:
            {
                auto dest = instr->getOperand<Label>(0);
                if (verbose)
                    fmt::println("UncondBR: {}", dest.getId());
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
                    fmt::println("CondBr: {}, {}", brtrue.getId(), brfalse.getId());
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
                    fmt::println("unsupported call imm {:#x}", data->address);
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
            fmt::println("empty block!");
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
            fmt::println("Analyzing block {:#x}\n==========\n{}\n==========", address, str);
        }

        for (auto node = block.begin; node != block.end; node = node->getNext())
        {
            auto  data   = node->getUserData<InstructionData>();
            auto& detail = data->detail;

            if (verbose)
            {
                auto instrText = formatter::toString(program, node, formatter::Options::HexImmediates);
                fmt::println("{:#x}|{}\n", data->address, instrText);
                fmt::println("\tregs read: {}", formatRegsMask(data->regsRead));
                fmt::println("\tregs written: {}", formatRegsMask(data->regsWritten));
                fmt::println("\tflags tested: {}", formatFlagsMask(data->flagsTested));
                fmt::println("\tflags modified: {}", formatFlagsMask(data->flagsModified));
            }

            block.regsGen |= data->regsRead & ~block.regsKill;
            block.regsKill |= data->regsWritten;
            block.flagsGen  = block.flagsGen | (data->flagsTested & ~block.flagsKill);
            block.flagsKill = block.flagsKill | data->flagsModified;
        }

        if (verbose)
        {
            fmt::println("regs_gen: {}", formatRegsMask(block.regsGen));
            fmt::println("regs_kill: {}", formatRegsMask(block.regsKill));
            fmt::println("flags_gen: {}", formatFlagsMask(block.flagsGen));
            fmt::println("flags_kill: {}", formatFlagsMask(block.flagsKill));
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
            fmt::println("Analyzing block {:#x}\n==========\n{}\n==========", address, str);
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
                fmt::println("{:#x}|{}", data->address, instrText);
                fmt::println("\tflags modified: {}", formatFlagsMask(flagsModified));
                fmt::println("\tflags tested: {}", formatFlagsMask(flagsTested));
                fmt::println("\tregs read: {}", formatRegsMask(regsRead));
                fmt::println("\tregs written: {}", formatRegsMask(regsWritten));

                if (flagsModified & flagsLive)
                {
                    fmt::println("\tlive flags are modified: {}", formatFlagsMask(flagsModified & flagsLive));
                }

                if (flagsTested & flagsLive)
                {
                    fmt::println("\tlive flags are tested: {}", formatFlagsMask(flagsTested & flagsLive));
                }
            }

            // If the flag is tested, it becomes live
            if (flagsTested)
            {
                flagsLive = flagsLive | flagsTested;
                if (verbose)
                    fmt::println("\tnew live flags: {}", formatFlagsMask(flagsLive));
            }

            if (regsRead)
            {
                regsLive = regsLive | regsRead;
                if (verbose)
                    fmt::println("\tnew live regs: {}", formatRegsMask(regsLive));
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
                fmt::println("\tfinal live flags: {}", formatFlagsMask(data->flagsLive));
                fmt::println("\tfinal live regs: {}", formatRegsMask(data->regsLive));
            }
        }
    }

    // Print the results
    if (verbose)
    {
        std::string script;
        for (const auto& [address, block] : blocks)
        {
            fmt::println("Results for block {:#x}\n==========", address);
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

                fmt::println(
                    "{:#x}|{}|{}|{}", data->address, str, formatRegsMask(data->regsLive), formatFlagsMask(data->flagsLive)
                );

                if (data->regsRead & ~data->regsLive)
                {
                    fmt::println("\tdead regs read: %s\n", formatRegsMask(data->regsRead & ~data->regsLive).c_str());
                    __debugbreak();
                }
            }
            fmt::println("==========");

            fmt::println("\tregs_live_in: {}", formatRegsMask(block.regsLiveIn));
            fmt::println("\tregs_live_out: {}", formatRegsMask(block.regsLiveOut));
            fmt::println("\tflags_live_in: {}", formatFlagsMask(block.flagsLiveIn));
            fmt::println("\tflags_live_out: {}", formatFlagsMask(block.flagsLiveOut));
        }

        fmt::println("{}", script);

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

        fmt::println("{}", dot);
    }

    return true;
}
} // namespace obfuscator
