#include "syscalls.h"

void* memset(void* vdest, int ch, size_t size) {
  return sys_memset(vdest, ch, size);
}

void* memcpy(void* vdest, const void* vsrc, size_t size) {
  return sys_memcpy(vdest, vsrc, size);
}

void* memmove(void* vdest, const void* vsrc, size_t size) {
  return sys_memmove(vdest, vsrc, size);
}

int memcmp(const void* vdest, const void* vsrc, size_t size) {
  return sys_memcmp(vdest, vsrc, size);
}

__attribute__((noreturn)) void exit(int code) {
  sys_exit(code);
  __builtin_unreachable();
}
