#include "cfg.hpp"
#include "instruction_data.hpp"
#include "logger.hpp"
#include "util.hpp"
#include <deque>
#include <string>
#include <zasm/formatter/formatter.hpp>

using namespace zasm;

namespace ObfuscatorLib
{

CFG::CFG()
{
}

bool CFG::create(Program& program, Label entryLabel)
{
    std::vector<Label>  toVisit;
    std::set<Label::Id> visited;

    entry_ = entryLabel.getId();
    toVisit.push_back(entryLabel);

    while (!toVisit.empty())
    {
        auto label = toVisit.back();
        toVisit.pop_back();

        // Skip if already visited
        //
        if (!visited.insert(label.getId()).second)
            continue;

        auto& labelData = *program.getLabelData(label);
        auto& block     = getBlock(label, labelData);
        auto  node      = labelData.node->getNext();

        bool finished = false;
        while (!finished)
        {
            if (auto instr = node->getIf<Instruction>())
            {
                auto data = node->getUserData<InstructionData>();
                auto info = *instr->getDetail(program.getMode());

                // Handle control flow instructions and add edges to the CFG
                //
                switch (info.getCategory())
                {
                case x86::Category::UncondBR:
                {
                    auto target = instr->getOperand<Label>(0);
                    toVisit.push_back(target);
                    addEdge(block.label, target);
                    finished = true;
                    break;
                }
                case x86::Category::CondBr:
                {
                    auto tbranch = instr->getOperand<Label>(0);
                    auto fbranch = node->getNext()->get<Label>();
                    toVisit.push_back(tbranch);
                    toVisit.push_back(fbranch);
                    addEdge(block.label, tbranch);
                    addEdge(block.label, fbranch);
                    finished = true;
                    break;
                }
                case x86::Category::Ret:
                    finished = true;
                    exits_.insert(block.label.getId());
                    break;
                default:
                    break;
                }

                // Append liveness information to the block
                //
                block.regsUse |= (data->regsRead & ~block.regsDef);
                block.regsDef |= data->regsWritten;
                block.flagsUse |= (data->flagsTested & ~block.flagsDef);
                block.flagsDef |= data->flagsModified;
            }
            else if (auto labelNode = node->getIf<Label>())
            {
                toVisit.push_back(*labelNode);
                addEdge(block.label, *labelNode);
                break;
            }
            else
            {
                break;
            }

            node = node->getNext();
        }

        block.end = node;
        if (!block.end)
        {
            puts("empty block!");
            __debugbreak();
        }
    }

    return true;
}

void CFG::computeLiveness()
{
    // Perform liveness analysis on the control flow graph
    // https://en.wikipedia.org/wiki/Live-variable_analysis

    std::deque<Label::Id> queue;
    std::set<Label::Id>   inQueue;

    // Initialize the queue with exit blocks
    for (const auto& exit : exits_)
    {
        queue.push_back(exit);
        inQueue.insert(exit);
    }

    while (!queue.empty())
    {
        Label::Id labelId = queue.front();
        queue.pop_front();
        inQueue.erase(labelId);

        BasicBlock& block       = getBlock(labelId);
        auto        regsLiveIn  = block.regsUse | (block.regsLiveOut & ~block.regsDef);
        auto        flagsLiveIn = block.flagsUse | (block.flagsLiveOut & ~block.flagsDef);

        // Only propagate if there's a change in live-in sets
        if (regsLiveIn != block.regsLiveIn || flagsLiveIn != block.flagsLiveIn)
        {
            block.regsLiveIn  = regsLiveIn;
            block.flagsLiveIn = flagsLiveIn;

            // Iterate over predecessors and propagate liveness
            for (const auto& pred : getPredecessors(labelId))
            {
                BasicBlock& predBlock       = getBlock(pred);
                auto        newRegsLiveOut  = predBlock.regsLiveOut | regsLiveIn;
                auto        newFlagsLiveOut = predBlock.flagsLiveOut | flagsLiveIn;

                if (newRegsLiveOut != predBlock.regsLiveOut || newFlagsLiveOut != predBlock.flagsLiveOut)
                {
                    predBlock.regsLiveOut  = newRegsLiveOut;
                    predBlock.flagsLiveOut = newFlagsLiveOut;

                    if (inQueue.find(pred) == inQueue.end())
                    {
                        inQueue.insert(pred);
                        queue.push_back(pred);
                    }
                }
            }

            // Apply liveness to each instruction in the block in reverse order
            auto node      = block.end;
            auto regsLive  = block.regsLiveOut;
            auto flagsLive = block.flagsLiveOut;

            while (node != block.begin)
            {
                node      = node->getPrev();
                auto data = node->getUserData<InstructionData>();

                // If the register/flag is read, it must be live
                regsLive |= data->regsRead;
                flagsLive |= data->flagsTested;

                if (regsLive != data->regsLive || flagsLive != data->flagsLive)
                {
                    // Store liveness info in instruction data
                    data->regsLive  = regsLive;
                    data->flagsLive = flagsLive;

                    // Clear registers and flags that are written but not read/tested
                    // TODO: Can this always be applied or only if regs are written?
                    regsLive &= ~(data->regsWritten & ~data->regsRead);
                    flagsLive &= ~(data->flagsModified & ~data->flagsTested);
                }
                else
                {
                    break;
                }
            }
        }
    }
}

std::map<Label::Id, BasicBlock>& CFG::getBasicBlocks()
{
    return blocks_;
}

void CFG::printResults(Program& program)
{
    std::string script;
    for (const auto& [label, block] : blocks_)
    {
        Logger::logLine("Results for block 0x%llX\n==========", block.address);
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

            Logger::logLine(
                "0x%llX|%s|%s|%s",
                data->address,
                str.c_str(),
                formatRegsMask(data->regsLive).c_str(),
                formatFlagsMask(data->flagsLive).c_str()
            );

            if (data->regsRead & ~data->regsLive)
            {
                Logger::logError("\tdead regs read: %s", formatRegsMask(data->regsRead & ~data->regsLive).c_str());
                __debugbreak();
            }
        }
        Logger::logLine("==========");

        Logger::logLine("\tregs_live_in: %s", formatRegsMask(block.regsLiveIn).c_str());
        Logger::logLine("\tregs_live_out: %s", formatRegsMask(block.regsLiveOut).c_str());
        Logger::logLine("\tflags_live_in: %s", formatFlagsMask(block.flagsLiveIn).c_str());
        Logger::logLine("\tflags_live_out: %s", formatFlagsMask(block.flagsLiveOut).c_str());
    }

    Logger::logLine("%s", script.c_str());
}

void CFG::printDot(Program& program)
{
    auto toHex = [](uint64_t value) -> std::string
    {
        char buffer[64] = "";
        sprintf_s(buffer, "\"0x%llX\"", value);
        return std::string(buffer);
    };

    std::string dot = "digraph G {\n";
    for (const auto& [address, block] : blocks_)
    {
        dot += toHex(block.address) + " [label=\"" + program.getLabelData(block.label).value().name + "\"];\n";
        for (const auto& successorId : getSuccessors(block.label.getId()))
        {
            auto successor = getBlock(successorId);
            auto data = program.getLabelData(successor.label).value().node->getUserData<InstructionData>();
            auto successorAddress = data->address;
            dot += toHex(block.address) + " -> " + toHex(successorAddress) + ";\n";
        }
    }
    dot += "}";
    Logger::logLine("%s", dot.c_str());
}

BasicBlock& CFG::getBlock(Label label, LabelData& data)
{
    auto it = blocks_.find(label.getId());
    if (it != blocks_.end())
        return it->second;

    BasicBlock block{};
    block.label   = label;
    block.address = data.node->getUserData<InstructionData>()->address;
    block.begin   = data.node->getNext();
    if (!block.begin)
    {
        puts("empty block!");
        __debugbreak();
    }
    return blocks_[label.getId()] = block;
}

BasicBlock& CFG::getBlock(Label::Id id)
{
    return blocks_.at(id);
}

void CFG::addEdge(Label from, Label to)
{
    successors_[from.getId()].insert(to.getId());
    predecessors_[to.getId()].insert(from.getId());
}

std::set<Label::Id> CFG::getSuccessors(Label::Id labelId)
{
    auto it = successors_.find(labelId);
    if (it != successors_.end())
        return it->second;

    return {};
}

std::set<Label::Id> CFG::getPredecessors(Label::Id labelId)
{
    auto it = predecessors_.find(labelId);
    if (it != predecessors_.end())
        return it->second;

    return {};
}

} // namespace ObfuscatorLib
