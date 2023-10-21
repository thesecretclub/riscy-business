#include "syscalls.h"

static long ack(long m, long n) {
  if(m == 0) {
    return n + 1;
  }
  if(n == 0) {
    return ack(m - 1, 1);
  }
  return ack(m - 1, ack(m, n - 1));
}

int main() {
  long res = ack(3, 10);
  sys_prints("ack result:");
  sys_printi(res);
  sys_assert(res == 8189);
  return 0;
}
