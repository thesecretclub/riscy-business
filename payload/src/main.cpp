#include "phnt.h"

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
    auto ntdll = FindNtdll(RtlGetCurrentPeb());
    MessageBoxW(0, ntdll->FullDllName.Buffer, L"ntdll", MB_SYSTEMMODAL);
    return 0;
}
