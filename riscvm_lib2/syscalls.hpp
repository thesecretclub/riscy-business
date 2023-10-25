#pragma once
#include "common.hpp"

enum class e_syscall : uint32_t
{
    exit  = 10000,
    abort = 10001,

    // malloc    = 10002,
    // calloc    = 10003,
    // realloc   = 10004,
    // free      = 10005,

    memcpy  = 10006,
    memset  = 10007,
    memmove = 10008,
    memcmp  = 10009,

    print_wstring = 10100,
    print_string = 10101,
    print_int = 10102,
    print_hex = 10103,
    print_tag_hex = 10104,

    windows_syscall = 20000,
    get_peb = 20001,
};

namespace detail
{
ALWAYS_INLINE inline uint64_t syscall_stub(uint64_t code)
{
    register uint64_t syscall_id asm("a7") = code;
    register uint64_t _a0 asm("a0")        = 0;
    asm volatile("scall" : "+r"(_a0) : "r"(syscall_id));
    return _a0;
}

template <class T0> ALWAYS_INLINE inline uint64_t syscall_stub(uint64_t code, T0 _0)
{
    register uint64_t syscall_id asm("a7") = code;
    register uint64_t _a0 asm("a0")        = _0;
    asm volatile("scall" : "+r"(_a0) : "r"(syscall_id));
    return _a0;
}

template <class T0, class T1> inline ALWAYS_INLINE uint64_t syscall_stub(uint64_t code, T0 _0, T1 _1)
{
    register uint64_t syscall_id asm("a7") = code;
    register uint64_t _a0 asm("a0")        = _0;
    register uint64_t _a1 asm("a1")        = _1;
    asm volatile("scall" : "+r"(_a0) : "r"(_a1), "r"(syscall_id));
    return _a0;
}

template <class T0, class T1, class T2>
ALWAYS_INLINE inline uint64_t syscall_stub(uint64_t code, T0 _0, T1 _1, T2 _2)
{
    register uint64_t syscall_id asm("a7") = code;
    register uint64_t _a0 asm("a0")        = _0;
    register uint64_t _a1 asm("a1")        = _1;
    register uint64_t _a2 asm("a2")        = _2;
    asm volatile("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(syscall_id));
    return _a0;
}

template <class T0, class T1, class T2, class T3>
ALWAYS_INLINE inline uint64_t syscall_stub(uint64_t code, T0 _0, T1 _1, T2 _2, T3 _3)
{
    register uint64_t syscall_id asm("a7") = code;
    register uint64_t _a0 asm("a0")        = _0;
    register uint64_t _a1 asm("a1")        = _1;
    register uint64_t _a2 asm("a2")        = _2;
    register uint64_t _a3 asm("a3")        = _3;
    asm volatile("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a3), "r"(syscall_id));
    return _a0;
}

template <class T0, class T1, class T2, class T3, class T4>
ALWAYS_INLINE inline uint64_t syscall_stub(uint64_t code, T0 _0, T1 _1, T2 _2, T3 _3, T4 _4)
{
    register uint64_t syscall_id asm("a7") = code;
    register uint64_t _a0 asm("a0")        = _0;
    register uint64_t _a1 asm("a1")        = _1;
    register uint64_t _a2 asm("a2")        = _2;
    register uint64_t _a3 asm("a3")        = _3;
    register uint64_t _a4 asm("a4")        = _4;
    asm volatile("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(syscall_id));
    return _a0;
}

template <class T0, class T1, class T2, class T3, class T4, class T5>
ALWAYS_INLINE inline uint64_t syscall_stub(uint64_t code, T0 _0, T1 _1, T2 _2, T3 _3, T4 _4, T5 _5)
{
    register uint64_t syscall_id asm("a7") = code;
    register uint64_t _a0 asm("a0")        = _0;
    register uint64_t _a1 asm("a1")        = _1;
    register uint64_t _a2 asm("a2")        = _2;
    register uint64_t _a3 asm("a3")        = _3;
    register uint64_t _a4 asm("a4")        = _4;
    register uint64_t _a5 asm("a5")        = _5;
    asm volatile("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5), "r"(syscall_id));
    return _a0;
}

template <class... Ts> ALWAYS_INLINE inline uint64_t invoke_syscall_stub(e_syscall code, Ts... args)
{
    return syscall_stub((uint64_t)code, (uint64_t)(args)...);
}

} // namespace detail

template <class... Ts>
ALWAYS_INLINE inline uint64_t syscall(e_syscall code, Ts... args)
{
    return detail::invoke_syscall_stub(code, args...);
}

static inline void* sys_memset(void* vdest, int ch, uint64_t size)
{
    return (void*)(uintptr_t)syscall(e_syscall::memset, (long)vdest, ch, (long)size);
}

static inline void* sys_memcpy(void* vdest, const void* vsrc, uint64_t size)
{
    return (void*)(uintptr_t)syscall(e_syscall::memcpy, (long)vdest, (long)vsrc, (long)size);
}

static inline void* sys_memmove(void* vdest, const void* vsrc, uint64_t size)
{
    return (void*)(uintptr_t)syscall(e_syscall::memmove, (long)vdest, (long)vsrc, (long)size);
}

static inline int sys_memcmp(const void* vdest, const void* vsrc, uint64_t size)
{
    return syscall(e_syscall::memcmp, (long)vdest, (long)vsrc, (long)size);
}