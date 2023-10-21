#include "syscalls.h"

bool is_prime[10000000+1];

static int64_t sieve(int64_t N) {
  is_prime[1] = false;
  for(int64_t n = 2; n <= N; n += 1) {
    is_prime[n] = true;
  }
  int64_t nprimes = 0;
  for(int64_t n = 2; n <= N; n += 1) {
    if(is_prime[n]) {
      nprimes = nprimes + 1;
      for(int64_t m = n + n; m <= N; m += n) {
        is_prime[m] = false;
      }
    }
  }
  return nprimes;
}

int main() {
  int64_t res = sieve(10000000);
  sys_prints("sieve result:");
  sys_printi(res);
  sys_assert(res == 664579);
  return 0;
}
