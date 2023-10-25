#include "../riscvm_lib2/syscalls.hpp"

extern "C" void* memset(void* vdest, int ch, uint64_t size)
{
    return sys_memset(vdest, ch, size);
}

extern "C" void* memcpy(void* vdest, const void* vsrc, uint64_t size)
{
    return sys_memcpy(vdest, vsrc, size);
}

extern "C" void* memmove(void* vdest, const void* vsrc, uint64_t size)
{
    return sys_memmove(vdest, vsrc, size);
}

extern "C" int memcmp(const void* vdest, const void* vsrc, uint64_t size)
{
    return sys_memcmp(vdest, vsrc, size);
}