#pragma once

#include <map>
#include <set>
#include <vector>
#include <zasm/zasm.hpp>

namespace ObfuscatorLib
{

using namespace zasm;

struct BasicBlock
{
    uint64_t address = 0;
    Label    label;
    Node*    begin = nullptr;
    Node*    end   = nullptr;

    uint32_t regsUse     = 0;
    uint32_t regsDef     = 0;
    uint32_t regsLiveIn  = 0;
    uint32_t regsLiveOut = 0;

    uint32_t flagsUse     = 0;
    uint32_t flagsDef     = 0;
    uint32_t flagsLiveIn  = 0;
    uint32_t flagsLiveOut = 0;
};

class CFG
{
  public:
    CFG();

    bool create(Program& program, Label entryLabel);
    void computeLiveness();

    std::map<Label::Id, BasicBlock>& getBasicBlocks();

    void printResults(Program& program);
    void printDot(Program& program);

  private:
    BasicBlock&         getBlock(Label label, LabelData& data);
    BasicBlock&         getBlock(Label::Id id);
    void                addEdge(Label from, Label to);
    std::set<Label::Id> getSuccessors(Label::Id labelId);
    std::set<Label::Id> getPredecessors(Label::Id labelId);

  private:
    std::map<Label::Id, BasicBlock>          blocks_;
    std::map<Label::Id, std::set<Label::Id>> predecessors_;
    std::map<Label::Id, std::set<Label::Id>> successors_;
    std::set<Label::Id>                      exits_;
    Label::Id                                entry_;
};

} // namespace ObfuscatorLib
