#include "../lib/syscalls.hpp"
#include "../lib/windows.hpp"

struct Blah2
{
    int x;
    int y;

    Blah2(int x, int y) : x(x), y(y)
    {
    }
};

static Blah2 blah  = Blah2(34, 12);
static Blah2 blah2 = Blah2(78, 56);

#define NtQueryInformationProcess 0x19

typedef unsigned int NTSTATUS;

typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS  ExitStatus;
    uintptr_t PebBaseAddress;
    uintptr_t AffinityMask;
    long      BasePriority;
    uintptr_t UniqueProcessId;
    uintptr_t InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

int get_proc_id()
{
    PROCESS_BASIC_INFORMATION pbi;

    int32_t status = WIN_SYSCALL(ZwQueryInformationProcess, -1, 0, &pbi, sizeof(pbi), 0);
    if (status != 0)
        return status;
    return pbi.UniqueProcessId;
}

extern "C" int bb()
{
    win::init_syscalls();
    (void)syscall(e_syscall::print_string, "Hello, world!");
    (void)syscall(e_syscall::print_int, get_proc_id());
    return blah.x + blah2.y;
}
