#include <iostream>
#include <cstdlib>
#include <vector>
#include <deque>
#include <map>
#include <set>

namespace vm
{
#include "../../riscvm/riscvm.h"
} // namespace vm

#include <zasm/zasm.hpp>
#include <zasm/formatter/formatter.hpp>

#include <phnt.h>

using namespace zasm;

static bool load_file(const char* path, std::vector<uint8_t>& data)
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

static bool find_riscvm_run(const std::vector<uint8_t>& pe, uint64_t& address, std::vector<uint8_t>& function_code)
{
    // Iterate export directory and look for 'riscvm_run'
    auto pdh = (IMAGE_DOS_HEADER*)pe.data();
    if (pdh->e_magic != IMAGE_DOS_SIGNATURE)
    {
        puts("Invalid DOS header.");
        return false;
    }

    auto pnth = (IMAGE_NT_HEADERS*)((uint8_t*)pe.data() + pdh->e_lfanew);
    if (pnth->Signature != IMAGE_NT_SIGNATURE)
    {
        puts("Invalid NT header.");
        return false;
    }

    auto poh = &pnth->OptionalHeader;
    if (poh->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        puts("Invalid optional header.");
        return false;
    }

    auto export_dir = poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    auto rva2offset = [&](uint32_t rva) -> uint32_t
    {
        auto section = IMAGE_FIRST_SECTION(pnth);
        for (int i = 0; i < pnth->FileHeader.NumberOfSections; i++)
        {
            if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize)
            {
                return rva - section->VirtualAddress + section->PointerToRawData;
            }

            section++;
        }

        return 0;
    };

    // Print all exports and the function rva
    uint32_t riscvm_run_rva = 0;
    auto pexport_dir = (IMAGE_EXPORT_DIRECTORY*)((uint8_t*)pe.data() + rva2offset(export_dir.VirtualAddress));
    for (DWORD i = 0; i < pexport_dir->NumberOfNames; i++)
    {
        auto pnames = (uint32_t*)((uint8_t*)pe.data() + rva2offset(pexport_dir->AddressOfNames));
        auto pname  = (const char*)((uint8_t*)pe.data() + rva2offset(pnames[i]));

        auto pordinals = (uint16_t*)((uint8_t*)pe.data() + rva2offset(pexport_dir->AddressOfNameOrdinals));
        auto pordinal  = pordinals[i];

        auto pfunctions = (uint32_t*)((uint8_t*)pe.data() + rva2offset(pexport_dir->AddressOfFunctions));
        auto pfunction  = pfunctions[pordinal];

        // printf("Export: %s, RVA: 0x%X\n", pname, pfunction);
        if (strcmp(pname, "riscvm_run") == 0)
        {
            riscvm_run_rva = pfunction;
            break;
        }
    }

    if (riscvm_run_rva == 0)
    {
        puts("Failed to find riscvm_run export.");
        return false;
    }

    // Get function range from RUNTIME_FUNCTION
    auto pexception_dir = poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    auto pexception =
        (IMAGE_RUNTIME_FUNCTION_ENTRY*)((uint8_t*)pe.data() + rva2offset(pexception_dir.VirtualAddress));
    for (int i = 0; i < pexception_dir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY); i++)
    {
        auto pfunction = &pexception[i];
        // printf("Function: 0x%X - 0x%X\n", pfunction->BeginAddress, pfunction->EndAddress);
        if (pfunction->BeginAddress == riscvm_run_rva)
        {
            auto size = pfunction->EndAddress - pfunction->BeginAddress;

            address = poh->ImageBase + riscvm_run_rva;
            function_code.resize(size);

            auto offset = rva2offset(riscvm_run_rva);
            memcpy(function_code.data(), pe.data() + offset, size);

            return true;
        }
    }

    return false;
}

static std::string format_flags_mask(uint32_t mask)
{
    std::string result;
#define FLAG(x)   \
    if (mask & x) \
    result += (#x + 14), result += " "
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

static std::string format_regs_mask(uint64_t mask)
{
    std::string result;
#define REG(x)                                     \
    if (mask & (1ULL << (x - ZYDIS_REGISTER_RAX))) \
    result += (#x + 15), result += " "
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

struct InstructionData
{
    uint64_t          address = 0;
    InstructionDetail detail;
    uint32_t          flags_modified = 0;
    uint32_t          flags_tested   = 0;
    uint32_t          flags_live     = 0;
    uint32_t          regs_written   = 0;
    uint32_t          regs_read      = 0;
    uint32_t          regs_live      = 0;
};

struct Context
{
    Program& program;

    explicit Context(Program& program) : program(program)
    {
    }

    InstructionData* add_instruction_data(Node* node, uint64_t address, const InstructionDetail& detail)
    {
        auto instructionData = node->getUserData<InstructionData>();
        if (instructionData == nullptr)
        {
            instructionDataPool.emplace_back();
            instructionData          = &instructionDataPool.back();
            instructionData->address = address;
            instructionData->detail  = detail;
            node->setUserData(instructionData);
        }
        return instructionData;
    }

  private:
    std::deque<InstructionData> instructionDataPool;
};

static bool analyze_riscvm_run(Context& ctx)
{
    Program& program = ctx.program;
    auto     mode    = program.getMode();
    puts("=== ANALYZE ===");
    std::vector<Label> queue;
    queue.push_back(program.getEntryPoint());
    std::set<Label::Id> visisted;

    // References:
    // - https://en.wikipedia.org/wiki/Live-variable_analysis
    // - https://en.wikipedia.org/wiki/Dominator_(graph_theory)

    struct BasicBlock
    {
        uint64_t           address = 0;
        Label              label;
        Node*              begin = nullptr;
        Node*              end   = nullptr;
        std::vector<Label> successors;
    };

    std::map<uint64_t, BasicBlock> blocks;

    while (!queue.empty())
    {
        auto block_start_label = queue.back();
        queue.pop_back();

        if (visisted.count(block_start_label.getId()))
        {
            continue;
        }
        visisted.insert(block_start_label.getId());

        const auto& label_data    = *program.getLabelData(block_start_label);
        auto        block_address = label_data.node->getUserData<InstructionData>()->address;

        BasicBlock bb;
        bb.address = block_address;
        bb.label   = block_start_label;
        bb.begin   = label_data.node->getNext();
        if (bb.begin == nullptr)
        {
            puts("empty block!");
            __debugbreak();
        }
        printf("<==> Disassembling block: %s (0x%llX)\n", label_data.name, block_address);

        auto node     = label_data.node->getNext();
        bool finished = false;
        while (!finished)
        {
            auto instr = node->getIf<Instruction>();
            if (instr == nullptr)
            {
                auto label = node->getIf<Label>();
                queue.push_back(*label);
                bb.successors.push_back(*label);
                puts("not instr!");
                break;
            }

            auto instruction_data = node->getUserData<InstructionData>();

            auto str = formatter::toString(program, instr, formatter::Options::HexImmediates);
            printf("0x%llX|%s\n", instruction_data->address, str.c_str());

            auto info = *instr->getDetail(mode);
            switch (info.getCategory())
            {
            case x86::Category::UncondBR:
            {
                auto dest = instr->getOperand<Label>(0);
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
                    printf("unsupported call imm\n");
                    return false;
                }
            }
            break;

            case x86::Category::Ret:
            {
                finished = true;
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

    std::map<uint64_t, std::set<uint64_t>> successors;
    std::map<uint64_t, std::set<uint64_t>> predecessors;
    for (const auto& [address, block] : blocks)
    {
        for (const auto& successor : block.successors)
        {
            auto instruction_data = program.getLabelData(successor).value().node->getUserData<InstructionData>();
            auto successor_address = instruction_data->address;
            successors[address].insert(successor_address);
            predecessors[successor_address].insert(address);
        }
    }

    for (auto& [address, block] : blocks)
    {
        auto str = formatter::toString(program, block.begin, block.end, formatter::Options::HexImmediates);
        printf("Analyzing block 0x%llX\n==========\n%s\n==========\n", address, str.c_str());

        InstrCPUFlags flags_live = 0;
        uint32_t      regs_live  = 0;
        for (auto node = block.end->getPrev(); node != block.begin->getPrev(); node = node->getPrev())
        {
            auto  data   = node->getUserData<InstructionData>();
            auto& detail = data->detail;

            auto instrText = formatter::toString(program, node, formatter::Options::HexImmediates);
            printf("0x%llX|%s\n", data->address, instrText.c_str());

            auto reg_mask = [](const Reg& reg) -> uint64_t
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

                auto mask = 1ULL << reg.getIndex();
#ifdef _DEBUG
                auto maskText = format_regs_mask(mask);
                auto regText  = formatter::toString(reg);
                for (auto& ch : regText)
                    ch = std::toupper(ch);
                regText = "(" + regText + ")";
                if (maskText != regText)
                    __debugbreak();
#endif
                return mask;
            };

            uint32_t regs_read    = 0;
            uint32_t regs_written = 0;
            for (size_t i = 0; i < detail.getOperandCount(); i++)
            {
                const auto& operand = detail.getOperand(i);
                if (auto reg = operand.getIf<Reg>())
                {
                    auto access = detail.getOperandAccess(i);
                    if ((uint8_t)(access & Operand::Access::MaskRead))
                    {
                        regs_read |= reg_mask(reg->getRoot(mode));
                    }
                    if ((uint8_t)(access & Operand::Access::MaskWrite))
                    {
                        regs_written |= reg_mask(reg->getRoot(mode));
                    }
                }
                else if (auto mem = operand.getIf<Mem>())
                {
                    regs_read |= reg_mask(mem->getBase().getRoot(mode));
                    regs_read |= reg_mask(mem->getIndex().getRoot(mode));
                }
            }
            data->regs_read    = regs_read;
            data->regs_written = regs_written;

            const auto& flags          = detail.getCPUFlags();
            auto        flags_modified = flags.set0 | flags.set1 | flags.modified | flags.undefined;
            auto        flags_tested   = flags.tested;
            printf("\tflags modified: %s\n", format_flags_mask(flags_modified).c_str());
            printf("\tflags tested: %s\n", format_flags_mask(flags_tested).c_str());
            printf("\tregs read: %s\n", format_regs_mask(regs_read).c_str());
            printf("\tregs written: %s\n", format_regs_mask(regs_written).c_str());
            data->flags_modified = flags_modified;
            data->flags_tested   = flags_tested;

            if (flags_modified & flags_live)
            {
                printf("\tlive flags are modified: %s\n", format_flags_mask(flags_modified & flags_live).c_str());
            }

            if (flags_tested & flags_live)
            {
                printf("\tlive flags are tested: %s\n", format_flags_mask(flags_tested & flags_live).c_str());
            }

            // If the flag is tested, it becomes live
            if (flags_tested)
            {
                flags_live = flags_live | flags_tested;
                printf("\tnew live flags: %s\n", format_flags_mask(flags_live).c_str());
            }

            if (regs_read)
            {
                regs_live = regs_live | regs_read;
                printf("\tnew live regs: %s\n", format_regs_mask(regs_live).c_str());
            }

            // Store the liveness state for the instruction
            data->flags_live = flags_live;
            data->regs_live  = regs_live;

            if (flags_modified)
            {
                // If the flag is modified, it becomes dead
                flags_live = flags_live & ~flags_modified;
            }

            if (regs_written)
            {
                // If the register is written, it becomes dead
                regs_live = regs_live & ~regs_written;
            }

            printf("\tfinal live flags: %s\n", format_flags_mask(data->flags_live).c_str());
            printf("\tfinal live regs: %s\n", format_regs_mask(data->regs_live).c_str());
        }
    }

    auto to_hex = [](uint64_t value)
    {
        char buffer[64] = "";
        sprintf_s(buffer, "\"0x%llX\"", value);
        return std::string(buffer);
    };

    std::string dot = "digraph G {\n";
    for (const auto& [address, block] : blocks)
    {
        dot += to_hex(address) + " [label=\"" + program.getLabelData(block.label).value().name + "\"];\n";
        for (const auto& successor : block.successors)
        {
            auto data = program.getLabelData(successor).value().node->getUserData<InstructionData>();
            auto successor_address = data->address;
            dot += to_hex(address) + " -> " + to_hex(successor_address) + ";\n";
        }
    }

    dot += "}";

    puts(dot.c_str());

    return true;
}

static bool disassemble_riscvm_run(Context& ctx, const uint64_t function_start, const std::vector<uint8_t>& code)
{
    Program& program = ctx.program;

    puts("=== DISASSEMBLE ===");
    zasm::Decoder  decoder(program.getMode());
    x86::Assembler assembler(program);

    auto entry_label = assembler.createLabel("riscvm_run");
    assembler.bind(entry_label);
    ctx.add_instruction_data(assembler.getCursor(), function_start, {});
    program.setEntryPoint(entry_label);

    std::map<uint64_t, Node*> nodes;
    std::map<uint64_t, Label> labels;

    size_t offset = 0;
    while (offset < code.size())
    {
        auto cur_address = function_start + offset;
        auto decoder_res = decoder.decode(code.data() + offset, code.size() - offset, cur_address);
        if (!decoder_res)
        {
            std::cout << "Failed to decode at " << std::hex << cur_address << ", "
                      << decoder_res.error().getErrorName() << "\n";
            return false;
        }

        nodes.emplace(cur_address, assembler.getCursor());

        const auto& detail = *decoder_res;
        const auto  instr  = detail.getInstruction();
        auto        length = detail.getLength();
        offset += length;

        auto str = formatter::toString(&instr, formatter::Options::HexImmediates);
        printf("0x%llX|%s\n", cur_address, str.c_str());

        auto emit = [&]
        {
            if (auto res = assembler.emit(instr); res != zasm::ErrorCode::None)
            {
                std::cout << "Failed to emit instruction " << std::hex << cur_address << ", "
                          << res.getErrorName() << "\n";
                return false;
            }
            ctx.add_instruction_data(assembler.getCursor(), cur_address, detail);
            return true;
        };

        auto create_label = [&](uint64_t dest)
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
            printf("UncondBR: 0x%llX\n", dest);
            assembler.emit(detail.getMnemonic(), create_label(dest));
            ctx.add_instruction_data(assembler.getCursor(), cur_address, detail);
        }
        break;

        case x86::Category::CondBr:
        {
            auto brtrue  = detail.getOperand<Imm>(0).value<uint64_t>();
            auto brfalse = offset + function_start;
            create_label(brfalse);
            printf("CondBr: 0x%llX, 0x%llX\n", brtrue, brfalse);
            assembler.emit(detail.getMnemonic(), create_label(brtrue));
            ctx.add_instruction_data(assembler.getCursor(), cur_address, detail);
        }
        break;

        case x86::Category::Call:
        {
            auto dest = detail.getOperand(0);
            if (dest.getIf<Imm>() != nullptr)
            {
                printf("unsupported call imm\n");
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
        auto detail = *node->get<Instruction>().getDetail(program.getMode());
        ctx.add_instruction_data(assembler.getCursor(), address, detail);
    }

    assembler.setCursor(program.getTail());
    assembler.bind(assembler.createLabel("end"));

    puts("");
    std::string text = formatter::toString(program);
    puts(text.c_str());

    return true;
}

static bool obfuscate_riscvm_run(Context& ctx)
{
    Program&       program = ctx.program;
    x86::Assembler assembler(program);

    puts("=== OBFUSCATE === ");
    auto entry_node = program.getLabelData(program.getEntryPoint()).value().node;
    for (auto node = entry_node; node != nullptr;)
    {
        auto next = node->getNext();
        if (auto instr = node->getIf<Instruction>(); instr != nullptr)
        {
            assembler.setCursor(node->getPrev());
            // TODO: actual obfuscation
            assembler.nop();
        }
        puts(formatter::toString(program, node).c_str());
        node = next;
    }
    return true;
}

namespace vm
{
#ifdef _WIN32
#pragma section(".vmcode", read, write)
__declspec(align(4096)) uint8_t g_code[0x10000];
#pragma section(".vmstack", read, write)
__declspec(align(4096)) uint8_t g_stack[0x10000];
#else
uint8_t g_code[0x10000] __attribute__((aligned(0x1000)));
uint8_t g_stack[0x10000] __attribute__((aligned(0x1000)));
#endif // _WIN32
} // namespace vm

typedef void (*riscvm_run_t)(vm::riscvm*);

#include "../../riscvm/isa-tests/data.h"

static bool run_isa_tests(riscvm_run_t riscvm_run, const std::vector<std::string>& filter = {})
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
        riscvm vm   = {};
        auto   self = &vm;
        reg_write(reg_sp, (uint64_t)&g_stack[sizeof(g_stack) - 0x10]);
        self->pc = (int64_t)g_code + test.offset;
        riscvm_run(self);

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
    return successful == total ? EXIT_SUCCESS : EXIT_FAILURE;
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        puts("Usage: obfuscator riscvm.exe payload.bin");
        return EXIT_FAILURE;
    }

    std::vector<uint8_t> pe;
    if (!load_file(argv[1], pe))
    {
        puts("Failed to load the executable.");
        return EXIT_FAILURE;
    }

    std::vector<uint8_t> payload;
    if (!load_file(argv[2], payload))
    {
        puts("Failed to load the payload.");
        return EXIT_FAILURE;
    }

    uint64_t             riscvm_run_address = 0;
    std::vector<uint8_t> riscvm_run_code;
    if (!find_riscvm_run(pe, riscvm_run_address, riscvm_run_code))
    {
        puts("Failed to find riscvm_run function.");
        return EXIT_FAILURE;
    }

    printf("riscvm_run address: 0x%llX, size: 0x%zX\n", riscvm_run_address, riscvm_run_code.size());

#if 0
    for (size_t i = 0; i < riscvm_run_code.size(); i++)
    {
        if (i > 0 && i % 32 == 0)
            puts("");
        printf("%02X ", riscvm_run_code[i]);
    }
    puts("");
#endif

    Program program(MachineMode::AMD64);
    Context ctx(program);
    if (!disassemble_riscvm_run(ctx, riscvm_run_address, riscvm_run_code))
    {
        puts("Failed to disassemble riscvm_run function.");
        return EXIT_FAILURE;
    }

    if (!analyze_riscvm_run(ctx))
    {
        puts("Failed to analyze the riscvm_run function.");
        return false;
    }

    if (!obfuscate_riscvm_run(ctx))
    {
        puts("Failed to obfuscate riscvm_run function.");
        return EXIT_FAILURE;
    }

    puts("");
    std::string text = formatter::toString(program);
    puts(text.c_str());

    auto shellcode = VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (shellcode == nullptr)
    {
        puts("Failed to allocate memory for shellcode.");
        return EXIT_FAILURE;
    }

    Serializer serializer;
    if (auto res = serializer.serialize(program, (uint64_t)shellcode); res != zasm::ErrorCode::None)
    {
        std::cout << "Failed to serialize program at " << std::hex << (uint64_t)shellcode << ", "
                  << res.getErrorName() << "\n";
        return EXIT_FAILURE;
    }

    auto ptr  = serializer.getCode();
    auto size = serializer.getCodeSize();

    memcpy(shellcode, ptr, size);
    auto riscvm_run = (riscvm_run_t)shellcode;

    run_isa_tests(riscvm_run);

    // Execute the full payload
    {
        using namespace vm;
        riscvm vm       = {0};
        vm.pc           = (int64_t)payload.data();
        vm.regs[reg_sp] = (uint64_t)(uint64_t)&g_stack[sizeof(g_stack) - 0x10];
        riscvm_run(&vm);
    }

    return EXIT_SUCCESS;
}
