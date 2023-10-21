#include "syscalls.h"

#define NtQueryInformationProcess 0x19

typedef unsigned int NTSTATUS;

typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    uintptr_t PebBaseAddress;
    uintptr_t AffinityMask;
    long BasePriority;
    uintptr_t UniqueProcessId;
    uintptr_t InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

int _start() {
  PROCESS_BASIC_INFORMATION pbi;

  int32_t status = win_syscall5(
    NtQueryInformationProcess, 
    -1,
    0,
    (uint64_t)&pbi,
    sizeof(pbi),
    (uint64_t)NULL
  );

  sys_printi(pbi.UniqueProcessId);
  sys_printi(status);
  return status;
}
