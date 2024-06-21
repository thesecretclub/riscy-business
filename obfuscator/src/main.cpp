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

static bool analyze_riscvm_run(Program& program)
{
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
        auto        block_address = label_data.node->getUserDataU64();

        BasicBlock bb;
        bb.address = block_address;
        bb.label   = block_start_label;
        bb.begin   = label_data.node->getNext();

        printf("<==> Disassembling block: %s (0x%llX)\n", label_data.name, block_address);

        uint32_t live_flags = 0;

        auto format_flags = [](uint32_t mask)
        {
            std::string result;
#define FLAG(x)   \
    if (mask & x) \
        result += (#x + 14), result += " ";
            FLAG(ZYDIS_CPUFLAG_CF);
            FLAG(ZYDIS_CPUFLAG_PF);
            FLAG(ZYDIS_CPUFLAG_AF);
            FLAG(ZYDIS_CPUFLAG_ZF);
            FLAG(ZYDIS_CPUFLAG_SF);
            FLAG(ZYDIS_CPUFLAG_TF);
            FLAG(ZYDIS_CPUFLAG_IF);
            FLAG(ZYDIS_CPUFLAG_DF);
            FLAG(ZYDIS_CPUFLAG_OF);
            FLAG(ZYDIS_CPUFLAG_IOPL);
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
        };

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

            auto user_data = node->getUserDataU64();

            auto str = formatter::toString(program, instr, formatter::Options::HexImmediates);
            printf("0x%llX|%s|live=%s\n", user_data, str.c_str(), format_flags(live_flags).c_str());

            // TODO: why isn't all this stored in the Instruction?
            auto info = *instr->getDetail(program.getMode());

            const auto& flags         = info.getCPUFlags();
            auto        modified_mask = flags.set0 | flags.set1 | flags.modified | flags.undefined;
            printf(
                "\tset0: %s, set1: %s, modified: %s, undefined: %s\n",
                format_flags(flags.set0.value()).c_str(),
                format_flags(flags.set1.value()).c_str(),
                format_flags(flags.modified.value()).c_str(),
                format_flags(flags.undefined.value()).c_str()
            );
            printf("\tall_modified: %s\n", format_flags(modified_mask).c_str());
            printf("\ttested: %s\n", format_flags(flags.tested.value()).c_str());

            if (flags.tested.value() & live_flags)
            {
                printf("Live flags are tested: %s\n", format_flags(flags.tested.value() & live_flags).c_str());
            }

            if (modified_mask.value() != 0)
            {
                live_flags = modified_mask;
            }

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
                // TODO: update flag liveness
            }
            break;
            }

            node = node->getNext();
        }

        bb.end = node;

        blocks.emplace(bb.address, bb);
    }

    std::map<uint64_t, std::set<uint64_t>> successors;
    std::map<uint64_t, std::set<uint64_t>> predecessors;
    for (const auto& [address, block] : blocks)
    {
        for (const auto& successor : block.successors)
        {
            auto successor_address = program.getLabelData(successor).value().node->getUserDataU64();
            successors[address].insert(successor_address);
            predecessors[successor_address].insert(address);
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
            auto successor_address = program.getLabelData(successor).value().node->getUserDataU64();
            dot += to_hex(address) + " -> " + to_hex(successor_address) + ";\n";
        }
    }

    dot += "}";

    puts(dot.c_str());

    return true;
}

static bool disassemble_riscvm_run(Program& program, const uint64_t function_start, const std::vector<uint8_t>& code)
{
    puts("=== DISASSEMBLE ===");
    zasm::Decoder  decoder(program.getMode());
    x86::Assembler assembler(program);

    auto entry_label = assembler.createLabel("riscvm_run");
    assembler.bind(entry_label);
    assembler.getCursor()->setUserData(function_start);
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

        const auto& info   = *decoder_res;
        const auto  instr  = info.getInstruction();
        auto        length = info.getLength();
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
            assembler.getCursor()->setUserData(cur_address);
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

        switch (info.getCategory())
        {
        case x86::Category::UncondBR:
        {
            auto dest = info.getOperand<Imm>(0).value<uint64_t>();
            printf("UncondBR: 0x%llX\n", dest);
            assembler.emit(info.getMnemonic(), create_label(dest));
            assembler.getCursor()->setUserData(cur_address);
        }
        break;

        case x86::Category::CondBr:
        {
            auto brtrue  = info.getOperand<Imm>(0).value<uint64_t>();
            auto brfalse = offset + function_start;
            create_label(brfalse);
            printf("CondBr: 0x%llX, 0x%llX\n", brtrue, brfalse);
            assembler.emit(info.getMnemonic(), create_label(brtrue));
            assembler.getCursor()->setUserData(cur_address);
        }
        break;

        case x86::Category::Call:
        {
            auto dest = info.getOperand(0);
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
        assembler.getCursor()->setUserData(address);
    }

    puts("");
    std::string text = formatter::toString(program);
    puts(text.c_str());

    return true;
}

static bool obfuscate_riscvm_run(Program& program)
{
    if (!analyze_riscvm_run(program))
    {
        return false;
    }

    return true;

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
    if (!disassemble_riscvm_run(program, riscvm_run_address, riscvm_run_code))
    {
        puts("Failed to disassemble riscvm_run function.");
        return EXIT_FAILURE;
    }

    if (!obfuscate_riscvm_run(program))
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
