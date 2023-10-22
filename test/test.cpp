#include "../riscvm_lib2/syscalls.hpp"

struct Blah2
{
    int x;
    int y;
    Blah2(int x, int y) : x(x), y(y) {

    }
};

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

static Blah2 blah = Blah2(12, 34);
static Blah2 blah2 = Blah2(56, 78);

int get_proc_id()
{
    PROCESS_BASIC_INFORMATION pbi;

    int32_t status = WIN_SYSCALL(
        NtQueryInformationProcess, 
        -1,
        0,
        &pbi,
        sizeof(pbi),
        0
    );
    return status;
}

extern "C" int bb() { 
    SYSCALL(SYSCALL_PRINTS, "Hello, world!\n");
    SYSCALL(SYSCALL_PRINTI, get_proc_id());
    return blah.x + blah2.y;
}