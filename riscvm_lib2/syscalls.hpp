#pragma once
#include "common.hpp"

enum {
  SYSCALL_EXIT      = 10000,
  SYSCALL_ABORT     = 10001,

  // SYSCALL_MALLOC    = 10002,
  // SYSCALL_CALLOC    = 10003,
  // SYSCALL_REALLOC   = 10004,
  // SYSCALL_FREE      = 10005,

  SYSCALL_MEMCPY    = 10006,
  SYSCALL_MEMSET    = 10007,
  SYSCALL_MEMMOVE   = 10008,
  SYSCALL_MEMCMP    = 10009,

  SYSCALL_PRINTS    = 10101,
  SYSCALL_PRINTI    = 10102,
};

namespace detail
{
    template <class... Ts> ALWAYS_INLINE uint32_t invoke_windows_syscall(uint32_t id, Ts... args)
    {
        constexpr auto num_args = sizeof...(args);

        uint64_t arg_array[num_args] = {(uint64_t)(args)...};

        register uint64_t syscall_id asm("a7") = 20000;

        register uint64_t _a0 asm("a0") = (uint64_t)id;
        register uint64_t _a1 asm("a1") = (uint64_t)&arg_array;
        register uint64_t _a2 asm("a2") = (uint64_t)num_args;

        asm volatile ("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(syscall_id));
        return _a0;
    }

    

    ALWAYS_INLINE uint64_t syscall_stub(uint64_t code)
    {
        register auto syscall_id asm("a7") = code;
        register auto _a0 asm("a0") = 0;
        asm volatile ("scall" : "+r"(_a0) : "r"(syscall_id));
        return _a0;
    }

    template<class T0>
    ALWAYS_INLINE uint64_t syscall_stub(uint64_t code, T0 _0)
    {
        register auto syscall_id asm("a7") = code;
        register auto _a0 asm("a0") = _0;
        asm volatile ("scall" : "+r"(_a0) : "r"(syscall_id));
        return _a0;
    }

    template<class T0, class T1>
    ALWAYS_INLINE uint64_t syscall_stub(uint64_t code, T0 _0, T1 _1)
    {
        register auto syscall_id asm("a7") = code;
        register auto _a0 asm("a0") = _0;
        register auto _a1 asm("a1") = _1;
        asm volatile ("scall" : "+r"(_a0) : "r"(_a1), "r"(syscall_id));
        return _a0;
    }

    template<class T0, class T1, class T2>
    ALWAYS_INLINE uint64_t syscall_stub(uint64_t code, T0 _0, T1 _1, T2 _2)
    {
        register auto syscall_id asm("a7") = code;
        register auto _a0 asm("a0") = _0;
        register auto _a1 asm("a1") = _1;
        register auto _a2 asm("a2") = _2;
        asm volatile ("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(syscall_id));
        return _a0;
    }

    template<class T0, class T1, class T2, class T3>
    ALWAYS_INLINE uint64_t syscall_stub(uint64_t code, T0 _0, T1 _1, T2 _2, T3 _3)
    {
        register auto syscall_id asm("a7") = code;
        register auto _a0 asm("a0") = _0;
        register auto _a1 asm("a1") = _1;
        register auto _a2 asm("a2") = _2;
        register auto _a3 asm("a3") = _3;
        asm volatile ("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a3),"r"(syscall_id));
        return _a0;
    }

    template<class T0, class T1, class T2, class T3, class T4>
    ALWAYS_INLINE uint64_t syscall_stub(uint64_t code, T0 _0, T1 _1, T2 _2, T3 _3, T4 _4)
    {
        register auto syscall_id asm("a7") = code;
        register auto _a0 asm("a0") = _0;
        register auto _a1 asm("a1") = _1;
        register auto _a2 asm("a2") = _2;
        register auto _a3 asm("a3") = _3;
        register auto _a4 asm("a4") = _4;
        asm volatile ("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(syscall_id));
        return _a0;
    }

    template<class T0, class T1, class T2, class T3, class T4, class T5>
    ALWAYS_INLINE uint64_t syscall_stub(uint64_t code, T0 _0, T1 _1, T2 _2, T3 _3, T4 _4, T5 _5)
    {
        register auto syscall_id asm("a7") = code;
        register auto _a0 asm("a0") = _0;
        register auto _a1 asm("a1") = _1;
        register auto _a2 asm("a2") = _2;
        register auto _a3 asm("a3") = _3;
        register auto _a4 asm("a4") = _4;
        register auto _a5 asm("a5") = _5;
        asm volatile ("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5),"r"(syscall_id));
        return _a0;
    }

    template<class... Ts> ALWAYS_INLINE uint64_t invoke_syscall_stub(uint64_t code, Ts... args)
    {
        return syscall_stub(code, (uint64_t)(args)...);
    }
}

#define WIN_SYSCALL(id, ...) detail::invoke_windows_syscall(id, __VA_ARGS__)
#define SYSCALL(id, ...) detail::invoke_syscall_stub(id, __VA_ARGS__)
