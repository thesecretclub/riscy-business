#include "syscalls.h"

void* memset(void* vdest, int ch, size_t size) {
  return sys_memset(vdest, ch, size);
}

__attribute__((noreturn)) void exit(int code) {
  sys_exit(code);
  __builtin_unreachable();
}
