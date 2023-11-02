#include <stdio.h>
#include <stdint.h>
#include <intrin.h>

// NOTE: This is a host-only implementation of the syscalls exposed by riscvm (crt0.c)

#define RISCVM_SYSCALL extern "C" __declspec(dllexport)

RISCVM_SYSCALL uintptr_t riscvm_host_call(uintptr_t address, uintptr_t args[13])
{
#ifdef _DEBUG
    printf("riscvm_host_call(0x%p, 0x%p)\n", (void*)address, args);
#endif // _DEBUG

    using syscall_fn = uint64_t(__fastcall*)(
        uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t
    );

    syscall_fn fn = (syscall_fn)address;
    return fn(
        args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12]
    );
}

RISCVM_SYSCALL uintptr_t riscvm_get_peb()
{
#ifdef _DEBUG
    printf("riscvm_get_peb()\n");
#endif // _DEBUG

#ifdef _WIN64
    return __readgsqword(0x60);
#else
    return __readfsdword(0x30);
#endif // _WIN64
}
