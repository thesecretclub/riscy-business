#include "syscalls.h"

static unsigned long fib(unsigned long n) {
  unsigned long a = 0;
  unsigned long b = 1;
  for(unsigned long i = 1; i <= n; i += 1) {
    unsigned long nb = a + b;
    a = b;
    b = nb;
  }
  return a;
}

int main() {
  unsigned long res = fib(20);
  sys_prints("fib result:");
  sys_printi(res);
  sys_assert(res == 6765);
  return 0;
}
