#include <cstdint>
#include <intrin.h>

namespace vm
{
#define SILENT_PANIC
#define CUSTOM_SYSCALLS
#include <riscvm.h>
} // namespace vm

static bool riscvm_handle_syscall(vm::riscvm* self, uint64_t code, uint64_t* result)
{
    switch (code)
    {
    case 93:    // RISC-V exit syscall
    case 10000: // vm exit
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
        throw std::runtime_error("Unknown syscall: " + std::to_string(code));
    }
    }
    return true;
}
