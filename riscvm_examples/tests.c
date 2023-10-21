#include "syscalls.h"
#include <stdint.h>
typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

void test_mul() {
  volatile int64_t a = 5, b = 7;
  sys_assert((a * b) == 35);
}

void test_mulhu() {
  volatile int128_t a = -5;
  volatile int128_t b = -7;
  sys_assert((a * b) == 35);
}

void test_div() {
  volatile int64_t a = 37, b = 7;
  sys_assert((a / b) == 5);
  b = 0; sys_assert((a / b) == -1); // divide by zero
  a = 0x8000000000000000; b = -1; sys_assert((a / b) == a); // divide overflow
}

void test_divu() {
  volatile uint64_t a = 37, b = 7;
  sys_assert((a / b) == 5); // divide
  b = 0; sys_assert((a / b) == 0xffffffffffffffff); // divide by zero
}

void test_rem() {
  volatile int64_t a = 37, b = 7;
  sys_assert((a % b) == 2);
  b = 0; sys_assert((a % b) == a); // divide by zero
  a = 0x8000000000000000; b = -1; sys_assert((a % b) == 0); // divide overflow
}

void test_remu() {
  volatile uint64_t a = 37, b = 7;
  sys_assert((a % b) == 2);
  b = 0; sys_assert((a % b) == a); // divide by zero
}

void test_mulw() {
  volatile int32_t a = 5, b = 7;
  sys_assert((a * b) == 35);
}

void test_divw() {
  volatile int32_t a = 37, b = 7;
  sys_assert((a / b) == 5); // divide
  b = 0; sys_assert((a / b) == -1); // divide by zero
  a = 0x80000000; b = -1; sys_assert((a / b) == a); // divide overflow
}

void test_divuw() {
  volatile uint32_t a = 37, b = 7;
  sys_assert((a / b) == 5); // divide
  b = 0; sys_assert((a / b) == 0xffffffff); // divide by zero
}

void test_remw() {
  volatile int32_t a = 37, b = 7;
  sys_assert((a % b) == 2);
  b = 0; sys_assert((a % b) == a); // divide by zero
  a = 0x80000000; b = -1; sys_assert((a % b) == 0); // divide overflow
}

void test_remuw() {
  volatile uint32_t a = 37, b = 7;
  sys_assert((a % b) == 2);
  b = 0; sys_assert((a % b) == a); // divide by zero
}

int main() {
  test_mul();
  test_mulhu();
  test_div();
  test_divu();
  test_rem();
  test_remu();

  test_mulw();
  test_divw();
  test_divuw();
  test_remw();
  test_remuw();
  return 0;
}
