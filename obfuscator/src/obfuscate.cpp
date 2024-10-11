#include <fstream>
#include <iostream>
#include <cstdlib>
#include <vector>

#include <obfuscator/msvc-secure.hpp>
#include <obfuscator/utility.hpp>

#include <zasm/zasm.hpp>
#include <zasm/formatter/formatter.hpp>

using namespace zasm;
using namespace obfuscator;

#include <obfuscator/context.hpp>
#include <obfuscator/disassemble.hpp>
#include <obfuscator/analyze.hpp>
#include <obfuscator/obfuscate.hpp>

#ifdef _WIN32

namespace vm
{
#define CUSTOM_SYSCALLS
#include "../../riscvm/riscvm.h"
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
    if (!findFunction(pe, "riscvm_run", riscvmRunAddress, riscvmRunCode))
    {
        puts("Failed to find riscvm_run function.");
        return EXIT_FAILURE;
    }

    printf("riscvm_run address: 0x%llX, size: 0x%zX\n", riscvmRunAddress, riscvmRunCode.size());

    Program program(MachineMode::AMD64);
    Context ctx(program);
    if (!disassemble(ctx, riscvmRunAddress, riscvmRunCode))
    {
        puts("Failed to disassemble riscvm_run function.");
        return EXIT_FAILURE;
    }

    if (!analyze(ctx, true))
    {
        puts("Failed to analyze the riscvm_run function.");
        return EXIT_FAILURE;
    }

    if (!obfuscate(ctx))
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
