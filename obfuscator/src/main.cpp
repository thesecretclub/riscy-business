#include <iostream>
#include <cstdlib>
#include <vector>
#include <deque>
#include <queue>
#include <map>
#include <set>
#include <fstream>
#include <stack>

#include "linux-pe/linuxpe"
#include "linux-pe/nt/directories/dir_exceptions.hpp"
#include "linux-pe/nt/directories/dir_export.hpp"
#include "linux-pe/nt/nt_headers.hpp"
#include "linux-pe/nt/optional_header.hpp"

#ifndef _WIN32
template <size_t Count, class... Args> int sprintf_s(char (&Dest)[Count], const char* fmt, Args... args)
{
    return snprintf(Dest, Count, fmt, args...);
}

inline size_t strcpy_s(char* dst, size_t size, const char* src)
{
    return strlcpy(dst, src, size);
}

inline int fopen_s(FILE** fp, const char* filename, const char* mode)
{
    *fp = fopen(filename, mode);
    return errno;
}

static void __debugbreak()
{
    __builtin_debugtrap();
}
#endif // _WIN32

namespace vm
{
#define CUSTOM_SYSCALLS
#include "../../riscvm/riscvm.h"
} // namespace vm

#include <zasm/zasm.hpp>
#include <zasm/formatter/formatter.hpp>
#include <string.h>

using namespace zasm;

static bool loadFile(const char* path, std::vector<uint8_t>& data)
{
    FILE* file = nullptr;
    fopen_s(&file, path, "rb");
    if (!file)
    {
        return false;
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file);

    data.resize(size);
    fread(data.data(), 1, size, file);
    fclose(file);

    return true;
}

static bool findRiscvmRun(const std::vector<uint8_t>& pe, uint64_t& address, std::vector<uint8_t>& functionCode)
{
    // Iterate export directory and look for 'riscvm_run'
    auto pdh = (win::dos_header_t*)pe.data();
    if (pdh->e_magic != win::DOS_HDR_MAGIC)
    {
        puts("Invalid DOS header.");
        return false;
    }

    auto pnth = (win::nt_headers_x64_t*)((uint8_t*)pe.data() + pdh->e_lfanew);
    if (pnth->signature != win::NT_HDR_MAGIC)
    {
        puts("Invalid NT header.");
        return false;
    }

    auto poh = &pnth->optional_header;
    if (poh->magic != win::OPT_HDR64_MAGIC)
    {
        puts("Invalid optional header.");
        return false;
    }

    auto rva2offset = [&](uint32_t rva) -> uint32_t
    {
        for (const auto& section : pnth->sections())
        {
            if (rva >= section.virtual_address && rva < section.virtual_address + section.virtual_size)
            {
                return rva - section.virtual_address + section.ptr_raw_data;
            }
        }
        return 0;
    };

    // Print all exports and the function rva
    uint32_t riscvmRunRva  = 0;
    auto     dataDirExport = poh->data_directories.export_directory;
    auto     exportDir     = (win::export_directory_t*)((uint8_t*)pe.data() + rva2offset(dataDirExport.rva));
    for (uint32_t i = 0; i < exportDir->num_names; i++)
    {
        auto addressOfNames = (uint32_t*)((uint8_t*)pe.data() + rva2offset(exportDir->rva_names));
        auto name           = (const char*)((uint8_t*)pe.data() + rva2offset(addressOfNames[i]));

        auto addressOfNameOrdinals = (uint16_t*)((uint8_t*)pe.data() + rva2offset(exportDir->rva_name_ordinals));
        auto nameOrdinal = addressOfNameOrdinals[i];

        auto addressOfFunctions = (uint32_t*)((uint8_t*)pe.data() + rva2offset(exportDir->rva_functions));
        auto functionAddress    = addressOfFunctions[nameOrdinal];

        if (strcmp(name, "riscvm_run") == 0)
        {
            riscvmRunRva = functionAddress;
            break;
        }
    }

    if (riscvmRunRva == 0)
    {
        puts("Failed to find riscvm_run export.");
        return false;
    }

    // Get function range from RUNTIME_FUNCTION
    auto dataDirException = poh->data_directories.exception_directory;
    auto exceptionDir = (win::runtime_function_t*)((uint8_t*)pe.data() + rva2offset(dataDirException.rva));
    for (int i = 0; i < dataDirException.size / sizeof(win::runtime_function_t); i++)
    {
        auto runtimeFunction = &exceptionDir[i];
        if (runtimeFunction->rva_begin == riscvmRunRva)
        {
            auto size = runtimeFunction->rva_end - runtimeFunction->rva_begin;

            address = poh->image_base + riscvmRunRva;
            functionCode.resize(size);

            auto offset = rva2offset(riscvmRunRva);
            memcpy(functionCode.data(), pe.data() + offset, size);

            return true;
        }
    }

    return false;
}

static std::string formatFlagsMask(uint32_t mask)
{
    std::string result;
#define FLAG(x)   \
    if (mask & x) \
    result += (&(#x)[14]), result += " "
    FLAG(ZYDIS_CPUFLAG_CF);
    FLAG(ZYDIS_CPUFLAG_PF);
    FLAG(ZYDIS_CPUFLAG_AF);
    FLAG(ZYDIS_CPUFLAG_ZF);
    FLAG(ZYDIS_CPUFLAG_SF);
    FLAG(ZYDIS_CPUFLAG_TF);
    FLAG(ZYDIS_CPUFLAG_IF);
    FLAG(ZYDIS_CPUFLAG_DF);
    FLAG(ZYDIS_CPUFLAG_OF);
    FLAG(ZYDIS_CPUFLAG_NT);
    FLAG(ZYDIS_CPUFLAG_RF);
    FLAG(ZYDIS_CPUFLAG_VM);
    FLAG(ZYDIS_CPUFLAG_AC);
    FLAG(ZYDIS_CPUFLAG_VIF);
    FLAG(ZYDIS_CPUFLAG_VIP);
    FLAG(ZYDIS_CPUFLAG_ID);
#undef FLAG
    if (!result.empty())
        result.pop_back();
    return "(" + result + ")";
}

static std::string formatRegsMask(uint64_t mask)
{
    std::string result;
#define REG(x)                                     \
    if (mask & (1ULL << (x - ZYDIS_REGISTER_RAX))) \
    result += (&(#x)[15]), result += " "
    REG(ZYDIS_REGISTER_RAX);
    REG(ZYDIS_REGISTER_RBX);
    REG(ZYDIS_REGISTER_RCX);
    REG(ZYDIS_REGISTER_RDX);
    REG(ZYDIS_REGISTER_RSP);
    REG(ZYDIS_REGISTER_RBP);
    REG(ZYDIS_REGISTER_RSI);
    REG(ZYDIS_REGISTER_RDI);
    REG(ZYDIS_REGISTER_R8);
    REG(ZYDIS_REGISTER_R9);
    REG(ZYDIS_REGISTER_R10);
    REG(ZYDIS_REGISTER_R11);
    REG(ZYDIS_REGISTER_R12);
    REG(ZYDIS_REGISTER_R13);
    REG(ZYDIS_REGISTER_R14);
    REG(ZYDIS_REGISTER_R15);
#undef REG
    if (!result.empty())
        result.pop_back();
    return "(" + result + ")";
}

static std::vector<x86::Gp> maskToRegs(uint64_t mask)
{
    std::vector<x86::Gp> result;
#define REG(x)                                     \
    if (mask & (1ULL << (x - ZYDIS_REGISTER_RAX))) \
        result.emplace_back(static_cast<Reg::Id>(x));
    REG(ZYDIS_REGISTER_RAX);
    REG(ZYDIS_REGISTER_RBX);
    REG(ZYDIS_REGISTER_RCX);
    REG(ZYDIS_REGISTER_RDX);
    REG(ZYDIS_REGISTER_RSP);
    REG(ZYDIS_REGISTER_RBP);
    REG(ZYDIS_REGISTER_RSI);
    REG(ZYDIS_REGISTER_RDI);
    REG(ZYDIS_REGISTER_R8);
    REG(ZYDIS_REGISTER_R9);
    REG(ZYDIS_REGISTER_R10);
    REG(ZYDIS_REGISTER_R11);
    REG(ZYDIS_REGISTER_R12);
    REG(ZYDIS_REGISTER_R13);
    REG(ZYDIS_REGISTER_R14);
    REG(ZYDIS_REGISTER_R15);
#undef REG
    return result;
}

static uint32_t regMask(const Reg& reg)
{
    if (!reg.isValid() || reg == x86::rip || reg == x86::rflags)
    {
        return 0;
    }

    if (!reg.isGp())
    {
        auto regText = formatter::toString(reg);
        printf("\tunsupported register type %s\n", regText.c_str());
        return 0;
    }

    auto mask = 1u << reg.getIndex();
#ifdef _DEBUG
    auto maskText = formatRegsMask(mask);
    auto regText  = formatter::toString(reg);
    for (auto& ch : regText)
        ch = std::toupper(ch);
    regText = "(" + regText + ")";
    if (maskText != regText)
        __debugbreak();
#endif
    return mask;
}

struct InstructionData
{
    uint64_t          address = 0;
    InstructionDetail detail;
    uint32_t          flagsModified = 0;
    uint32_t          flagsTested   = 0;
    uint32_t          regsWritten   = 0;
    uint32_t          regsRead      = 0;

    uint32_t regsLive  = 0;
    uint32_t flagsLive = 0;
};

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

struct CFG
{
    Program&                                 program;
    std::map<Label::Id, BasicBlock>          blocks;
    std::map<Label::Id, std::set<Label::Id>> predecessors;
    std::map<Label::Id, std::set<Label::Id>> successors;
    std::set<Label::Id>                      exits;
    Label::Id                                entry;
    bool                                     _verbose = false;

    explicit CFG(Program& program) : program(program)
    {
    }

    bool createCFG()
    {
        std::stack<Label>   toVisit;
        std::set<Label::Id> visited;

        toVisit.push(program.getEntryPoint());

        while (!toVisit.empty())
        {
            auto label = toVisit.top();
            toVisit.pop();

            // Skip if already visited
            //
            if (!visited.insert(label.getId()).second)
                continue;

            auto&       block     = getBlock(label);
            const auto& labelData = *program.getLabelData(label);
            auto        node      = labelData.node->getNext();

            bool finished = false;
            while (!finished)
            {
                auto instr = node->getIf<Instruction>();
                // If the node is a label, add it to the visit list and create an edge
                //
                if (!instr)
                {
                    if (auto labelNode = node->getIf<Label>())
                    {
                        toVisit.push(*labelNode);
                        addEdge(block.label, *labelNode);
                    }
                    break;
                }

                auto data = node->getUserData<InstructionData>();
                auto info = *instr->getDetail(program.getMode());

                // Handle control flow instructions and add edges to the CFG
                //
                switch (info.getCategory())
                {
                case x86::Category::UncondBR:
                {
                    auto target = instr->getOperand<Label>(0);
                    toVisit.push(target);
                    addEdge(block.label, target);
                    finished = true;
                    break;
                }
                case x86::Category::CondBr:
                {
                    auto tbranch = instr->getOperand<Label>(0);
                    auto fbranch = node->getNext()->get<Label>();
                    toVisit.push(tbranch);
                    toVisit.push(fbranch);
                    addEdge(block.label, tbranch);
                    addEdge(block.label, fbranch);
                    finished = true;
                    break;
                }
                case x86::Category::Ret:
                    finished = true;
                    exits.insert(block.label.getId());
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

    bool computeLiveness()
    {
        // Perform liveness analysis on the control flow graph
        // https://en.wikipedia.org/wiki/Live-variable_analysis

        // TODO: confirm this statement
        // water: "Dominator tree would not work for this, because it
        // does not take into account the next iteration of the loop"
        //
        // mishap: "this is correct, the complete method is to itterate
        // until live sets stabilize"

        std::deque<Label::Id> queue;

        // Initialize the queue with exit blocks
        for (const auto& exit : exits)
            queue.push_back(exit);

        while (!queue.empty())
        {
            Label::Id labelId = queue.front();
            queue.pop_front();

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
                    BasicBlock& predBlock = getBlock(pred);
                    predBlock.regsLiveOut |= regsLiveIn;
                    predBlock.flagsLiveOut |= flagsLiveIn;
                    queue.push_back(pred);
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

                    // Store liveness info in instruction data
                    data->regsLive  = regsLive;
                    data->flagsLive = flagsLive;

                    // Clear registers and flags that are written but not read/tested
                    // TODO: Can this always be applied or only if regs are written?
                    regsLive &= ~(data->regsWritten & ~data->regsRead);
                    flagsLive &= ~(data->flagsModified & ~data->flagsTested);
                }
            }
        }

        return true;
    }

    BasicBlock& getBlock(Label label)
    {
        auto it = blocks.find(label.getId());
        if (it != blocks.end())
            return it->second;

        auto labelData = program.getLabelData(label);

        BasicBlock block{};
        block.label   = label;
        block.address = labelData->node->getUserData<InstructionData>()->address;
        block.begin   = labelData->node->getNext();
        if (!block.begin)
        {
            puts("empty block!");
            __debugbreak();
        }
        return blocks[label.getId()] = block;
    }

    BasicBlock& getBlock(Label::Id id)
    {
        return blocks.at(id);
    }

    void addEdge(Label from, Label to)
    {
        successors[from.getId()].insert(to.getId());
        predecessors[to.getId()].insert(from.getId());
    }

    std::set<Label::Id> getSuccessors(Label::Id labelId)
    {
        auto it = successors.find(labelId);
        if (it != successors.end())
            return it->second;

        return {};
    }

    std::set<Label::Id> getPredecessors(Label::Id labelId)
    {
        auto it = predecessors.find(labelId);
        if (it != predecessors.end())
            return it->second;

        return {};
    }

    void printResults()
    {
        std::string script;
        for (const auto& [label, block] : blocks)
        {
            printf("Results for block 0x%llX\n==========\n", block.address);
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

        puts(dot.c_str());
    }
};

struct Context
{
    Program& program;
    CFG      cfg;

    explicit Context(Program& program) : program(program), cfg(program)
    {
    }

    InstructionData*
    addInstructionData(Node* node, uint64_t address, MachineMode mode, const InstructionDetail& detail)
    {
        auto data = node->getUserData<InstructionData>();
        if (data == nullptr)
        {
            instructionDataPool.emplace_back();
            data          = &instructionDataPool.back();
            data->address = address;
            data->detail  = detail;

            // Populate the registers read and written by the instruction
            for (size_t i = 0; i < detail.getOperandCount(); i++)
            {
                const auto& operand = detail.getOperand(i);
                if (auto reg = operand.getIf<Reg>())
                {
                    auto access = detail.getOperandAccess(i);
                    if ((uint8_t)(access & Operand::Access::MaskRead))
                    {
                        data->regsRead |= regMask(reg->getRoot(mode));
                    }
                    if ((uint8_t)(access & Operand::Access::MaskWrite))
                    {
                        // mov al, 66 does not kill rax
                        if (reg->isGp32() || reg->isGp64())
                        {
                            data->regsWritten |= regMask(reg->getRoot(mode));
                        }
                    }
                }
                else if (auto mem = operand.getIf<Mem>())
                {
                    data->regsRead |= regMask(mem->getBase().getRoot(mode));
                    data->regsRead |= regMask(mem->getIndex().getRoot(mode));
                }
            }

            // Populate the flags modified and tested by the instruction
            const auto& flags   = detail.getCPUFlags();
            data->flagsModified = uint32_t(flags.set0 | flags.set1 | flags.modified | flags.undefined);
            data->flagsTested   = uint32_t(flags.tested);

            // Special handling for call and ret instructions to properly support the calling conventions
            // https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-170#x64-register-usage
            switch (detail.getCategory())
            {
            case x86::Category::Call:
            {
                // The call instruction clobbers all volatile registers
                data->regsWritten = regMask(x86::rax) | regMask(x86::rcx) | regMask(x86::rdx)
                                  | regMask(x86::r8) | regMask(x86::r9) | regMask(x86::r10) | regMask(x86::r11);
                // The call instruction reads the first 4 arguments from rcx, rdx, r8, r9 (and rsp because mishap said so)
                data->regsRead = regMask(x86::rcx) | regMask(x86::rdx) | regMask(x86::r8) | regMask(x86::r9)
                               | regMask(x86::rsp);
            }
            break;

            case x86::Category::Ret:
            {
                // The ret instruction 'reads' all nonvolatile registers and the return value
                data->regsRead = regMask(x86::rsp) | regMask(x86::rbx) | regMask(x86::rbp) | regMask(x86::rsi)
                               | regMask(x86::rdi) | regMask(x86::r12) | regMask(x86::r13) | regMask(x86::r14)
                               | regMask(x86::r15) | regMask(x86::rax);
            }
            break;
            }

            node->setUserData(data);
        }
        return data;
    }

  private:
    std::deque<InstructionData> instructionDataPool;
};

static bool disassembleRiscvmRun(
    Context& ctx, const uint64_t functionStart, const std::vector<uint8_t>& code, bool verbose = false
)
{
    Program& program = ctx.program;
    auto     mode    = program.getMode();

    if (verbose)
        puts("=== DISASSEMBLE ===");
    zasm::Decoder  decoder(mode);
    x86::Assembler assembler(program);

    auto entryLabel = assembler.createLabel("riscvm_run");
    assembler.bind(entryLabel);
    ctx.addInstructionData(assembler.getCursor(), functionStart, mode, {});
    program.setEntryPoint(entryLabel);

    std::map<uint64_t, Node*> nodes;
    std::map<uint64_t, Label> labels;

    size_t offset = 0;
    while (offset < code.size())
    {
        auto curAddress = functionStart + offset;
        auto decoderRes = decoder.decode(code.data() + offset, code.size() - offset, curAddress);
        if (!decoderRes)
        {
            std::cout << "Failed to decode at " << std::hex << curAddress << ", "
                      << decoderRes.error().getErrorName() << "\n";
            return false;
        }

        nodes.emplace(curAddress, assembler.getCursor());

        const auto& detail = *decoderRes;
        const auto  instr  = detail.getInstruction();
        auto        length = detail.getLength();
        offset += length;

        auto str = formatter::toString(&instr, formatter::Options::HexImmediates);
        if (verbose)
            printf("0x%llX|%s\n", curAddress, str.c_str());

        auto emit = [&]
        {
            if (auto res = assembler.emit(instr); res != zasm::ErrorCode::None)
            {
                std::cout << "Failed to emit instruction " << std::hex << curAddress << ", "
                          << res.getErrorName() << "\n";
                return false;
            }
            ctx.addInstructionData(assembler.getCursor(), curAddress, mode, detail);
            return true;
        };

        auto createLabel = [&](uint64_t dest)
        {
            auto itr = labels.find(dest);
            if (itr == labels.end())
            {
                char name[64] = "";
                sprintf_s(name, "label_%llX", dest);
                auto label = assembler.createLabel(name);
                itr        = labels.emplace(dest, label).first;
            }
            return itr->second;
        };

        switch (detail.getCategory())
        {
        case x86::Category::UncondBR:
        {
            auto dest = detail.getOperand<Imm>(0).value<uint64_t>();
            if (verbose)
                printf("UncondBR: 0x%llX\n", dest);
            assembler.emit(detail.getMnemonic(), createLabel(dest));
            ctx.addInstructionData(assembler.getCursor(), curAddress, mode, detail);
        }
        break;

        case x86::Category::CondBr:
        {
            auto brtrue  = detail.getOperand<Imm>(0).value<uint64_t>();
            auto brfalse = offset + functionStart;
            createLabel(brfalse);
            if (verbose)
                printf("CondBr: 0x%llX, 0x%llX\n", brtrue, brfalse);
            assembler.emit(detail.getMnemonic(), createLabel(brtrue));
            ctx.addInstructionData(assembler.getCursor(), curAddress, mode, detail);
        }
        break;

        case x86::Category::Call:
        {
            auto dest = detail.getOperand(0);
            if (dest.getIf<Imm>() != nullptr)
            {
                printf("unsupported call imm 0x%llX\n", curAddress);
                return false;
            }

            if (!emit())
            {
                return false;
            }
        }
        break;

        case x86::Category::Ret:
        {
            if (!emit())
            {
                return false;
            }
        }
        break;

        default:
        {
            if (!emit())
            {
                return false;
            }
        }
        break;
        }
    }

    for (const auto& [address, label] : labels)
    {
        auto node = nodes.at(address);
        assembler.setCursor(node);
        assembler.bind(label);
        auto detail = *node->get<Instruction>().getDetail(mode);
        ctx.addInstructionData(assembler.getCursor(), address, mode, detail);
    }

    assembler.setCursor(program.getTail());
    assembler.bind(assembler.createLabel("end"));

    if (verbose)
    {
        puts("");
        std::string text = formatter::toString(program);
        puts(text.c_str());
    }

    return true;
}

static bool analyzeRiscvmRun(Context& ctx, bool verbose = false)
{
    CFG& cfg = ctx.cfg;

    if (verbose)
    {
        puts("=== ANALYZE ===");
        cfg._verbose = verbose;
    }

    if (!cfg.createCFG())
    {
        puts("failed!");
        return false;
    }

    if (!cfg.computeLiveness())
    {
        puts("failed!");
        return false;
    }

    if (verbose)
    {
        cfg.printResults();
    }

    return true;
}

static bool obfuscateRiscvmRun(Context& ctx, bool verbose = false)
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

    puts("=== OBFUSCATE === ");
    srand(1337);
    auto entryNode = const_cast<Node*>(program.getLabelData(program.getEntryPoint()).value().node);
    for (auto node = entryNode; node != nullptr;)
    {
        auto prev = node->getPrev();
        auto next = node->getNext();
        if (auto instr = node->getIf<Instruction>(); instr != nullptr)
        {
            auto data   = node->getUserData<InstructionData>();
            auto detail = data->detail;

            auto regsDeadMask = ~data->regsLive;
            auto regsDead     = maskToRegs(regsDeadMask);

            assembler.setCursor(prev);

            switch (detail.getCategory())
            {
            case x86::Category::UncondBR:
            {
                // Example: if unconditional branch, replace with call/pop
                if (regsDeadMask & regMask(x86::rax))
                {
                    assembler.call(instr->getOperand<Label>(0));
                    assembler.pop(x86::rax);

                    program.destroy(node); // remove the unconditional branch

                    if (verbose)
                    {
                        printf("0x%llX: replaced unconditional branch with call pop\n", data->address);
                    }
                }
            }
            break;
            default:
                {
                    for (auto deadReg : regsDead)
                    {
                        assembler.mov(deadReg, Imm(rand()));
                    }
                }
                break;
            }
        }

        node = next;
    }
    return true;
}

#ifdef _WIN32

namespace vm
{
#include "../../riscvm/riscvm-code.h"
} // namespace vm

typedef void (*riscvm_run_t)(vm::riscvm*);

#include <Windows.h>
#include "../../riscvm/isa-tests/data.h"

static bool runIsaTests(riscvm_run_t riscvmRun, const std::vector<std::string>& filter = {})
{
    using namespace vm;

    auto total      = 0;
    auto successful = 0;
    for (const auto& test : tests)
    {
        if (!filter.empty())
        {
            auto allowed = false;
            for (const auto& white : filter)
            {
                if (white == test.name)
                {
                    allowed = true;
                    break;
                }
            }
            if (!allowed)
                continue;
        }

        printf("[%s] ", test.name);
        if (test.size > sizeof(g_code))
        {
            printf("ERROR (too big)\n");
            continue;
        }
        total++;

        memset(g_code, 0, sizeof(g_code));
        memcpy(g_code, test.data, test.size);
        riscvm vm         = {};
        vm.handle_syscall = [](vm::riscvm*, uint64_t, uint64_t*)
        {
            return false;
        };
        auto self = &vm;
        reg_write(reg_sp, (uint64_t)&g_stack[sizeof(g_stack) - 0x10]);
        self->pc = (int64_t)g_code + test.offset;
        riscvmRun(self);

        auto status = (int)reg_read(reg_a0);
        if (status != 0)
        {
            printf("FAILURE (status: %d)\n", status);
        }
        else
        {
            successful++;
            printf("SUCCESS\n");
        }
    }
    printf("\n%d/%d tests successful (%.2f%%)\n", successful, total, successful * 1.0f / total * 100);
    return successful == total;
}

static bool riscvm_handle_syscall(vm::riscvm* self, uint64_t code, uint64_t* result)
{
    switch (code)
    {
    case 10000: // exit
    {
        return false;
    }

    case 20000: // host_call
    {
        uint64_t  func_addr = reg_read(vm::reg_a0);
        uint64_t* args      = (uint64_t*)riscvm_getptr(self, reg_read(vm::reg_a1));

        using syscall_fn = uint64_t (*)(
            uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t
        );

        syscall_fn fn = (syscall_fn)func_addr;
        *result =
            fn(args[0],
               args[1],
               args[2],
               args[3],
               args[4],
               args[5],
               args[6],
               args[7],
               args[8],
               args[9],
               args[10],
               args[11],
               args[12]);
        break;
    }

    case 20001: // get_peb
    {
        *result = __readgsqword(0x60);
        break;
    }

    default:
    {
        panic("illegal system call %llu (0x%llX)\n", code, code);
        return false;
    }
    }
    return true;
}

#endif // _WIN32

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        puts("Usage: obfuscator riscvm.exe [payload.bin]");
        return EXIT_FAILURE;
    }

    std::vector<uint8_t> pe;
    if (!loadFile(argv[1], pe))
    {
        puts("Failed to load the executable.");
        return EXIT_FAILURE;
    }

    uint64_t             riscvmRunAddress = 0;
    std::vector<uint8_t> riscvmRunCode;
    if (!findRiscvmRun(pe, riscvmRunAddress, riscvmRunCode))
    {
        puts("Failed to find riscvm_run function.");
        return EXIT_FAILURE;
    }

    printf("riscvm_run address: 0x%llX, size: 0x%zX\n", riscvmRunAddress, riscvmRunCode.size());

    Program program(MachineMode::AMD64);
    Context ctx(program);
    if (!disassembleRiscvmRun(ctx, riscvmRunAddress, riscvmRunCode))
    {
        puts("Failed to disassemble riscvm_run function.");
        return EXIT_FAILURE;
    }

    if (!analyzeRiscvmRun(ctx, true))
    {
        puts("Failed to analyze the riscvm_run function.");
        return EXIT_FAILURE;
    }

    if (!obfuscateRiscvmRun(ctx, true))
    {
        puts("Failed to obfuscate riscvm_run function.");
        return EXIT_FAILURE;
    }

    puts("");
    std::string text = formatter::toString(program);
    puts(text.c_str());

    // Serialize the obfuscated function
    uint64_t   shellcodeBase = 0;
    Serializer serializer;
    if (auto res = serializer.serialize(program, shellcodeBase); res != zasm::ErrorCode::None)
    {
        std::cout << "Failed to serialize program at " << std::hex << shellcodeBase << ", "
                  << res.getErrorName() << "\n";
        return EXIT_FAILURE;
    }

    auto ptr  = serializer.getCode();
    auto size = serializer.getCodeSize();

    // Save the obfuscated code to disk
    {
        std::ofstream ofs("riscvm_run_obfuscated.bin", std::ios::binary);
        ofs.write((char*)ptr, size);
    }

    // Run the ISA tests (Windows only)
#ifdef _WIN32
    auto shellcode = VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (shellcode == nullptr)
    {
        puts("Failed to allocate memory for shellcode.");
        return EXIT_FAILURE;
    }

    memcpy(shellcode, ptr, size);
    auto riscvmRun = (riscvm_run_t)shellcode;

    if (!runIsaTests(riscvmRun))
        __debugbreak();

    // Run the payload if specified on the command line
    if (argc > 2)
    {
        std::vector<uint8_t> payload;
        if (!loadFile(argv[2], payload))
        {
            puts("Failed to load the payload.");
            return EXIT_FAILURE;
        }

        using namespace vm;
        vm::riscvm self;
        self.handle_syscall     = riscvm_handle_syscall;
        self.pc                 = (int64_t)payload.data();
        self.regs[vm::reg_zero] = 0;
        self.regs[vm::reg_sp]   = (uint64_t)(uint64_t)&g_stack[sizeof(g_stack) - 0x10];
        riscvmRun(&self);
    }
#endif

    return EXIT_SUCCESS;
}
