#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

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

  WIN_SYSCALL_0     = 20000,
  WIN_SYSCALL_1     = 20001,
  WIN_SYSCALL_2     = 20002,
  WIN_SYSCALL_3     = 20003,
  WIN_SYSCALL_4     = 20004,
  WIN_SYSCALL_5     = 20005,
  WIN_SYSCALL_6     = 20006,
  WIN_SYSCALL_7     = 20007,
  WIN_SYSCALL_8     = 20008,
  WIN_SYSCALL_9     = 20009,
  WIN_SYSCALL_10    = 20010,
  WIN_SYSCALL_11    = 20011,
  WIN_SYSCALL_12    = 20012,
  WIN_SYSCALL_13    = 20013,
};

static inline int32_t win_syscall0(int32_t id)
{
  register long syscall_id asm("s10") = WIN_SYSCALL_0;
  register int32_t windows_id asm("s11") = id;

  register uint64_t _a0 asm("a0") = 0;
  
  asm volatile ("scall" : "+r"(windows_id) : "r"(syscall_id));
  return _a0;
}

static inline int32_t win_syscall1(int32_t id, uint64_t a0)
{
  register long syscall_id asm("s10") = WIN_SYSCALL_1;
  register int32_t windows_id asm("s11") = id;
  register uint64_t _a0 asm("a0") = a0;
  asm volatile ("scall" : "+r"(_a0) : "r"(syscall_id), "r"(windows_id));
  return _a0;
}

static inline int32_t win_syscall2(int32_t id, uint64_t a0, uint64_t a1)
{
  register long syscall_id asm("s10") = WIN_SYSCALL_2;
  register int32_t windows_id asm("s11") = id;

  register uint64_t _a0 asm("a0") = a0;
  register uint64_t _a1 asm("a1") = a1;

  asm volatile ("scall" : "+r"(_a0) : "r"(_a1), "r"(windows_id), "r"(syscall_id));
  return _a0;
}

static inline int32_t win_syscall3(int32_t id, uint64_t a0, uint64_t a1, uint64_t a2)
{
  register long syscall_id asm("s10") = WIN_SYSCALL_3;
  register int32_t windows_id asm("s11") = id;

  register uint64_t _a0 asm("a0") = a0;
  register uint64_t _a1 asm("a1") = a1;
  register uint64_t _a2 asm("a2") = a2;

  asm volatile ("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(windows_id), "r"(syscall_id));
  return _a0;
}

static inline int32_t win_syscall4(int32_t id, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
  register long syscall_id asm("s10") = WIN_SYSCALL_4;
  register int32_t windows_id asm("s11") = id;

  register uint64_t _a0 asm("a0") = a0;
  register uint64_t _a1 asm("a1") = a1;
  register uint64_t _a2 asm("a2") = a2;
  register uint64_t _a3 asm("a3") = a3;

  asm volatile ("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a3), "r"(windows_id), "r"(syscall_id));
  return _a0;
}

static inline int32_t win_syscall5(int32_t id, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
  register long syscall_id asm("s10") = WIN_SYSCALL_5;
  register int32_t windows_id asm("s11") = id;

  register uint64_t _a0 asm("a0") = a0;
  register uint64_t _a1 asm("a1") = a1;
  register uint64_t _a2 asm("a2") = a2;
  register uint64_t _a3 asm("a3") = a3;
  register uint64_t _a4 asm("a4") = a4;

  asm volatile ("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(windows_id), "r"(syscall_id));
  return _a0;
}

static inline int32_t win_syscall6(int32_t id, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5)
{
  register long syscall_id asm("s10") = WIN_SYSCALL_6;
  register int32_t windows_id asm("s11") = id;

  register uint64_t _a0 asm("a0") = a0;
  register uint64_t _a1 asm("a1") = a1;
  register uint64_t _a2 asm("a2") = a2;
  register uint64_t _a3 asm("a3") = a3;
  register uint64_t _a4 asm("a4") = a4;
  register uint64_t _a5 asm("a5") = a5;

  asm volatile ("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5), "r"(windows_id), "r"(syscall_id));
  return _a0;
}

static inline int32_t win_syscall7(int32_t id, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6)
{
  register long syscall_id asm("s10") = WIN_SYSCALL_7;
  register int32_t windows_id asm("s11") = id;

  register uint64_t _a0 asm("a0") = a0;
  register uint64_t _a1 asm("a1") = a1;
  register uint64_t _a2 asm("a2") = a2;
  register uint64_t _a3 asm("a3") = a3;
  register uint64_t _a4 asm("a4") = a4;
  register uint64_t _a5 asm("a5") = a5;
  register uint64_t _a6 asm("a6") = a6;

  asm volatile ("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5), "r"(_a6), "r"(windows_id), "r"(syscall_id));
  return _a0;
}

static inline int32_t win_syscall8(int32_t id, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7)
{
  register long syscall_id asm("s10") = WIN_SYSCALL_8;
  register int32_t windows_id asm("s11") = id;

  register uint64_t _a0 asm("a0") = a0;
  register uint64_t _a1 asm("a1") = a1;
  register uint64_t _a2 asm("a2") = a2;
  register uint64_t _a3 asm("a3") = a3;
  register uint64_t _a4 asm("a4") = a4;
  register uint64_t _a5 asm("a5") = a5;
  register uint64_t _a6 asm("a6") = a6;
  register uint64_t _a7 asm("a7") = a7;

  asm volatile ("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5), "r"(_a6), "r"(_a7), "r"(windows_id), "r"(syscall_id));
  return _a0;
}

static inline int32_t win_syscall9(int32_t id, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8)
{
  register long syscall_id asm("s10") = WIN_SYSCALL_9;
  register int32_t windows_id asm("s11") = id;

  register uint64_t _a0 asm("a0") = a0;
  register uint64_t _a1 asm("a1") = a1;
  register uint64_t _a2 asm("a2") = a2;
  register uint64_t _a3 asm("a3") = a3;
  register uint64_t _a4 asm("a4") = a4;
  register uint64_t _a5 asm("a5") = a5;
  register uint64_t _a6 asm("a6") = a6;
  register uint64_t _a7 asm("a7") = a7;
  register uint64_t _a8 asm("s2") = a8;

  asm volatile ("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5), "r"(_a6), "r"(_a7), "r"(_a8), "r"(windows_id), "r"(syscall_id));
  return _a0;
}

static inline int32_t win_syscall10(int32_t id, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8, uint64_t a9)
{
  register long syscall_id asm("s10") = WIN_SYSCALL_10;
  register int32_t windows_id asm("s11") = id;

  register uint64_t _a0 asm("a0") = a0;
  register uint64_t _a1 asm("a1") = a1;
  register uint64_t _a2 asm("a2") = a2;
  register uint64_t _a3 asm("a3") = a3;
  register uint64_t _a4 asm("a4") = a4;
  register uint64_t _a5 asm("a5") = a5;
  register uint64_t _a6 asm("a6") = a6;
  register uint64_t _a7 asm("a7") = a7;
  register uint64_t _a8 asm("s2") = a8;
  register uint64_t _a9 asm("s3") = a9;

  asm volatile ("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5), "r"(_a6), "r"(_a7), "r"(_a8), "r"(_a9), "r"(windows_id), "r"(syscall_id));
  return _a0;
}

static inline int32_t win_syscall11(int32_t id, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8, uint64_t a9, uint64_t a10)
{
  register long syscall_id asm("s10") = WIN_SYSCALL_11;
  register int32_t windows_id asm("s11") = id;

  register uint64_t _a0 asm("a0") = a0;
  register uint64_t _a1 asm("a1") = a1;
  register uint64_t _a2 asm("a2") = a2;
  register uint64_t _a3 asm("a3") = a3;
  register uint64_t _a4 asm("a4") = a4;
  register uint64_t _a5 asm("a5") = a5;
  register uint64_t _a6 asm("a6") = a6;
  register uint64_t _a7 asm("a7") = a7;
  register uint64_t _a8 asm("s2") = a8;
  register uint64_t _a9 asm("s3") = a9;
  register uint64_t _a10 asm("s4") = a10;

  asm volatile ("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5), "r"(_a6), "r"(_a7), "r"(_a8), "r"(_a9), "r"(_a10), "r"(windows_id), "r"(syscall_id));
  return _a0;
}

static inline int32_t win_syscall12(int32_t id, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8, uint64_t a9, uint64_t a10, uint64_t a11)
{
  register long syscall_id asm("s10") = WIN_SYSCALL_12;
  register int32_t windows_id asm("s11") = id;

  register uint64_t _a0 asm("a0") = a0;
  register uint64_t _a1 asm("a1") = a1;
  register uint64_t _a2 asm("a2") = a2;
  register uint64_t _a3 asm("a3") = a3;
  register uint64_t _a4 asm("a4") = a4;
  register uint64_t _a5 asm("a5") = a5;
  register uint64_t _a6 asm("a6") = a6;
  register uint64_t _a7 asm("a7") = a7;
  register uint64_t _a8 asm("s2") = a8;
  register uint64_t _a9 asm("s3") = a9;
  register uint64_t _a10 asm("s4") = a10;
  register uint64_t _a11 asm("s5") = a11;

  asm volatile ("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5), "r"(_a6), "r"(_a7), "r"(_a8), "r"(_a9), "r"(_a10), "r"(_a11), "r"(windows_id), "r"(syscall_id));
  return _a0;
}

static inline int32_t win_syscall13(int32_t id, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8, uint64_t a9, uint64_t a10, uint64_t a11, uint64_t a12)
{
  register long syscall_id asm("s10") = WIN_SYSCALL_13;
  register int32_t windows_id asm("s11") = id;

  register uint64_t _a0 asm("a0") = a0;
  register uint64_t _a1 asm("a1") = a1;
  register uint64_t _a2 asm("a2") = a2;
  register uint64_t _a3 asm("a3") = a3;
  register uint64_t _a4 asm("a4") = a4;
  register uint64_t _a5 asm("a5") = a5;
  register uint64_t _a6 asm("a6") = a6;
  register uint64_t _a7 asm("a7") = a7;
  register uint64_t _a8 asm("s2") = a8;
  register uint64_t _a9 asm("s3") = a9;
  register uint64_t _a10 asm("s4") = a10;
  register uint64_t _a11 asm("s5") = a11;
  register uint64_t _a12 asm("s6") = a12;

  asm volatile ("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5), "r"(_a6), "r"(_a7), "r"(_a8), "r"(_a9), "r"(_a10), "r"(_a11), "r"(_a12), "r"(windows_id), "r"(syscall_id));
  return _a0;
}


static inline long syscall0(long n) {
  register long syscall_id asm("s10") = n;

  register long a0 asm("a0") = 0;
  
  asm volatile ("scall" : "+r"(a0) : "r"(syscall_id));
  return a0;
}

static inline long syscall1(long n, long arg0) {
  register long syscall_id asm("s10") = n;

  register long a0 asm("a0") = arg0;

  asm volatile ("scall" : "+r"(a0) : "r"(syscall_id));
  return a0;
}

static inline long syscall3(long n, long arg0, long arg1, long arg2) {
  register long syscall_id asm("s10") = n;

  register long a0 asm("a0") = arg0;
  register long a1 asm("a1") = arg1;
  register long a2 asm("a2") = arg2;

  asm volatile ("scall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(syscall_id));
  return a0;
}

static inline long syscall4(long n, long arg0, long arg1, long arg2, long arg3) {
  register long syscall_id asm("s10") = n;

  register long a0 asm("a0") = arg0;
  register long a1 asm("a1") = arg1;
  register long a2 asm("a2") = arg2;
  register long a3 asm("a3") = arg3;

  asm volatile ("scall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a3), "r"(syscall_id));
  return a0;
}

static inline void sys_exit(long status) { syscall1(SYSCALL_EXIT, status); }
static inline void sys_abort() { syscall0(SYSCALL_ABORT);}

static inline void sys_prints(const char* s) { syscall1(SYSCALL_PRINTS, (long)(s)); }
static inline void sys_printi(long i) { syscall1(SYSCALL_PRINTI, i); }

static inline void* sys_memset(void* vdest, int ch, size_t size) { return (void*)(uintptr_t)syscall3(SYSCALL_MEMSET, (long)vdest, ch, (long)size); }
static inline void* sys_memcpy(void* vdest, const void* vsrc, size_t size) { return (void*)(uintptr_t)syscall3(SYSCALL_MEMCPY, (long)vdest, (long)vsrc, (long)size); }
static inline void* sys_memmove(void* vdest, const void* vsrc, size_t size) { return (void*)(uintptr_t)syscall3(SYSCALL_MEMMOVE, (long)vdest, (long)vsrc, (long)size); }
static inline int sys_memcmp(const void* vdest, const void* vsrc, size_t size) { return syscall3(SYSCALL_MEMCMP, (long)vdest, (long)vsrc, (long)size); }

#define sys_assert(expr) { \
    if(!(expr)) { \
        sys_prints("assertion failed: (" #expr ")"); \
        sys_abort(); \
    }}
