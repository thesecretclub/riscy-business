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

static bool
disassemble_riscvm_run_analyze(Program& program, const uint64_t function_start, const std::vector<uint8_t>& code)
{
    zasm::Decoder  decoder(program.getMode());
    x86::Assembler assembler(program);

    std::vector<uint64_t> queue;
    queue.push_back(function_start);
    std::map<uint64_t, Node*> nodes;
    std::map<uint64_t, Label> labels;
    std::set<uint64_t>        visisted;

    while (!queue.empty())
    {
        auto block_start = queue.back();
        queue.pop_back();

        if (visisted.count(block_start))
        {
            continue;
        }
        visisted.insert(block_start);

        printf("<==> Disassembling block: 0x%llX\n", block_start);

        uint64_t offset   = block_start - function_start;
        bool     finished = false;
        while (!finished)
        {
            if (offset >= code.size())
            {
                printf("offset out of bounds: 0x%llX\n", offset);
                return false;
            }

            uint8_t data[15] = {};
            memcpy(data, code.data() + offset, sizeof(data));

            auto cur_address = function_start + offset;
            auto decoder_res = decoder.decode(data, sizeof(data), cur_address);
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
                return true;
            };

            switch (info.getCategory())
            {
            case x86::Category::UncondBR:
            {
                auto dest = info.getOperand<Imm>(0).value<uint64_t>();
                printf("UncondBR: 0x%llX\n", dest);
                queue.push_back(dest);
                auto itr = labels.find(dest);
                if (itr == labels.end())
                {
                    char name[64] = "";
                    sprintf_s(name, "label_%llX", dest);
                    auto label = assembler.createLabel(name);
                    itr        = labels.emplace(dest, label).first;
                }
                assembler.emit(info.getMnemonic(), itr->second);
                finished = true;
            }
            break;

            case x86::Category::CondBr:
            {
                auto brtrue  = info.getOperand<Imm>(0).value<uint64_t>();
                auto brfalse = offset + function_start;
                printf("CondBr: 0x%llX, 0x%llX\n", brtrue, brfalse);
                queue.push_back(brfalse);
                queue.push_back(brtrue);
                auto itr = labels.find(brtrue);
                if (itr == labels.end())
                {
                    char name[64] = "";
                    sprintf_s(name, "label_%llX", brtrue);
                    auto label = assembler.createLabel(name);
                    itr        = labels.emplace(brtrue, label).first;
                }
                assembler.emit(info.getMnemonic(), itr->second);
                finished = true;
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
                finished = true;
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
    }

    for (const auto& [address, label] : labels)
    {
        auto node = nodes.at(address);
        if (node == nullptr)
        {
            puts("oh nein");
            __debugbreak();
        }
        assembler.setCursor(node);
        assembler.bind(label);
    }

    puts("");
    std::string text = formatter::toString(program);
    puts(text.c_str());

    return true;
}

static bool disassemble_riscvm_run(Program& program, const uint64_t function_start, const std::vector<uint8_t>& code)
{
    zasm::Decoder  decoder(program.getMode());
    x86::Assembler assembler(program);

    auto entry_label = assembler.createLabel("riscvm_run");
    assembler.bind(entry_label);
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
            return true;
        };

        switch (info.getCategory())
        {
        case x86::Category::UncondBR:
        {
            auto dest = info.getOperand<Imm>(0).value<uint64_t>();
            printf("UncondBR: 0x%llX\n", dest);
            auto itr = labels.find(dest);
            if (itr == labels.end())
            {
                char name[64] = "";
                sprintf_s(name, "label_%llX", dest);
                auto label = assembler.createLabel(name);
                itr        = labels.emplace(dest, label).first;
            }
            assembler.emit(info.getMnemonic(), itr->second);
        }
        break;

        case x86::Category::CondBr:
        {
            auto brtrue  = info.getOperand<Imm>(0).value<uint64_t>();
            auto brfalse = offset + function_start;
            printf("CondBr: 0x%llX, 0x%llX\n", brtrue, brfalse);
            auto itr = labels.find(brtrue);
            if (itr == labels.end())
            {
                char name[64] = "";
                sprintf_s(name, "label_%llX", brtrue);
                auto label = assembler.createLabel(name);
                itr        = labels.emplace(brtrue, label).first;
            }
            assembler.emit(info.getMnemonic(), itr->second);
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
    }

    puts("");
    std::string text = formatter::toString(program);
    puts(text.c_str());

    return true;
}

static bool obfuscate_riscvm_run(Program& program)
{
    x86::Assembler assembler(program);

    puts("OBFUSCATE");
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