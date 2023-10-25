#pragma once

#include "common.hpp"
#include "windows.hpp"

#define CONTAINING_RECORD(address, type, field) (\
    (type *)((char*)(address) -(unsigned long)(&((type *)0)->field)))

namespace ldr
{
static uintptr_t find_ntdll(win::PEB_T* peb)
{
    auto begin = &peb->Ldr->InLoadOrderModuleList;
    for (auto itr = begin->Flink; itr != begin; itr = itr->Flink)
    {
        auto entry = CONTAINING_RECORD(itr, win::LDR_DATA_TABLE_ENTRY_T, InLoadOrderLinks);
        auto base = (uintptr_t)entry->DllBase;
        if ((uintptr_t)begin >= base && (uintptr_t)begin < base + entry->SizeOfImage)
        {
            return (uintptr_t)entry->DllBase;
        }
    }
    return 0;
} 
} // namespace ldr