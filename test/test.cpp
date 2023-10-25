#include "../riscvm_lib2/syscalls.hpp"
#include "../riscvm_lib2/windows.hpp"
#include "../riscvm_lib2/ldr.hpp"

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
    auto peb = (win::PEB_T*)syscall(e_syscall::get_peb);
    (void)syscall(e_syscall::print_tag_hex, "peb", peb);
    auto ntdll = ldr::find_ntdll(peb);
    (void)syscall(e_syscall::print_tag_hex, "ntdll", ntdll);
    win::init_syscalls(ntdll);
    (void)syscall(e_syscall::print_string, "Hello, world!");
    (void)syscall(e_syscall::print_int, get_proc_id());
    return blah.x + blah2.y;
}
