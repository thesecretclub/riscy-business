#include "phnt.h"

#define RISCVM_SYSCALL extern "C" __declspec(dllimport)

RISCVM_SYSCALL uintptr_t riscvm_host_call(uintptr_t address, uintptr_t args[13]);
RISCVM_SYSCALL uintptr_t riscvm_get_peb();

#undef NtCurrentPeb
#define NtCurrentPeb() (PPEB) riscvm_get_peb()

static LDR_DATA_TABLE_ENTRY* FindNtdll(PEB* peb)
{
    auto ldrLock = (ULONG_PTR)peb->LoaderLock;
    auto begin   = &peb->Ldr->InLoadOrderModuleList;
    for (auto itr = begin->Flink; itr != begin; itr = itr->Flink)
    {
        auto entry = CONTAINING_RECORD(itr, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        auto base  = (ULONG_PTR)entry->DllBase;
        if (ldrLock >= base && ldrLock < base + entry->SizeOfImage)
        {
            return entry;
        }
    }
    return nullptr;
}

int main(int argc, char** argv)
{
    auto ntdll = FindNtdll(NtCurrentPeb());
    MessageBoxW(0, ntdll->FullDllName.Buffer, L"ntdll", MB_SYSTEMMODAL);
    return 0;
}
