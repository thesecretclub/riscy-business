#pragma once
#include "common.hpp"
#include "syscalls.hpp"

// ty magic <3
// https://github.com/JustasMasiulis/lazy_importer/blob/master/include/lazy_importer.hpp

#define CONTAINING_RECORD(address, type, field) (\
    (type *)((char*)(address) -(unsigned long)(&((type *)0)->field)))

namespace win
{

struct LIST_ENTRY_T
{
    const LIST_ENTRY_T* Flink;
    const LIST_ENTRY_T* Blink;
};

struct UNICODE_STRING_T
{
    uint16_t Length;
    uint16_t MaximumLength;
    wchar_t* Buffer;
};

struct PEB_LDR_DATA_T
{
    uint32_t     Length;
    uint32_t     Initialized;
    const char*  SsHandle;
    LIST_ENTRY_T InLoadOrderModuleList;
};

struct PEB_T
{
    uint8_t         Reserved1[2];
    uint8_t         BeingDebugged;
    uint8_t         Reserved2[1];
    const char*     Reserved3[2];
    PEB_LDR_DATA_T* Ldr;
};

struct LDR_DATA_TABLE_ENTRY_T
{
    LIST_ENTRY_T InLoadOrderLinks;
    LIST_ENTRY_T InMemoryOrderLinks;
    LIST_ENTRY_T InInitializationOrderLinks;
    const char*  DllBase;
    const char*  EntryPoint;
    union
    {
        uint32_t    SizeOfImage;
        const char* _dummy;
    };
    UNICODE_STRING_T FullDllName;
    UNICODE_STRING_T BaseDllName;

    ALWAYS_INLINE const LDR_DATA_TABLE_ENTRY_T* load_order_next() const noexcept
    {
        return reinterpret_cast<const LDR_DATA_TABLE_ENTRY_T*>(InLoadOrderLinks.Flink);
    }
};

#pragma pack(push, 1)
struct IMAGE_DOS_HEADER
{                        // DOS .EXE header
    uint16_t e_magic;    // Magic number
    uint16_t e_cblp;     // Bytes on last page of file
    uint16_t e_cp;       // Pages in file
    uint16_t e_crlc;     // Relocations
    uint16_t e_cparhdr;  // Size of header in paragraphs
    uint16_t e_minalloc; // Minimum extra paragraphs needed
    uint16_t e_maxalloc; // Maximum extra paragraphs needed
    uint16_t e_ss;       // Initial (relative) SS value
    uint16_t e_sp;       // Initial SP value
    uint16_t e_csum;     // Checksum
    uint16_t e_ip;       // Initial IP value
    uint16_t e_cs;       // Initial (relative) CS value
    uint16_t e_lfarlc;   // File address of relocation table
    uint16_t e_ovno;     // Overlay number
    uint16_t e_res[4];   // Reserved words
    uint16_t e_oemid;    // OEM identifier (for e_oeminfo)
    uint16_t e_oeminfo;  // OEM information; e_oemid specific
    uint16_t e_res2[10]; // Reserved words
    uint32_t e_lfanew;   // File address of new exe header
};

struct IMAGE_FILE_HEADER
{
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct IMAGE_EXPORT_DIRECTORY
{
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;    // RVA from base of image
    uint32_t AddressOfNames;        // RVA from base of image
    uint32_t AddressOfNameOrdinals; // RVA from base of image
};

struct IMAGE_DATA_DIRECTORY
{
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct IMAGE_OPTIONAL_HEADER64
{
    uint16_t             Magic;
    uint8_t              MajorLinkerVersion;
    uint8_t              MinorLinkerVersion;
    uint32_t             SizeOfCode;
    uint32_t             SizeOfInitializedData;
    uint32_t             SizeOfUninitializedData;
    uint32_t             AddressOfEntryPoint;
    uint32_t             BaseOfCode;
    uint64_t             ImageBase;
    uint32_t             SectionAlignment;
    uint32_t             FileAlignment;
    uint16_t             MajorOperatingSystemVersion;
    uint16_t             MinorOperatingSystemVersion;
    uint16_t             MajorImageVersion;
    uint16_t             MinorImageVersion;
    uint16_t             MajorSubsystemVersion;
    uint16_t             MinorSubsystemVersion;
    uint32_t             Win32VersionValue;
    uint32_t             SizeOfImage;
    uint32_t             SizeOfHeaders;
    uint32_t             CheckSum;
    uint16_t             Subsystem;
    uint16_t             DllCharacteristics;
    uint64_t             SizeOfStackReserve;
    uint64_t             SizeOfStackCommit;
    uint64_t             SizeOfHeapReserve;
    uint64_t             SizeOfHeapCommit;
    uint32_t             LoaderFlags;
    uint32_t             NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_OPTIONAL_HEADER32
{
    uint16_t             Magic;
    uint8_t              MajorLinkerVersion;
    uint8_t              MinorLinkerVersion;
    uint32_t             SizeOfCode;
    uint32_t             SizeOfInitializedData;
    uint32_t             SizeOfUninitializedData;
    uint32_t             AddressOfEntryPoint;
    uint32_t             BaseOfCode;
    uint32_t             BaseOfData;
    uint32_t             ImageBase;
    uint32_t             SectionAlignment;
    uint32_t             FileAlignment;
    uint16_t             MajorOperatingSystemVersion;
    uint16_t             MinorOperatingSystemVersion;
    uint16_t             MajorImageVersion;
    uint16_t             MinorImageVersion;
    uint16_t             MajorSubsystemVersion;
    uint16_t             MinorSubsystemVersion;
    uint32_t             Win32VersionValue;
    uint32_t             SizeOfImage;
    uint32_t             SizeOfHeaders;
    uint32_t             CheckSum;
    uint16_t             Subsystem;
    uint16_t             DllCharacteristics;
    uint32_t             SizeOfStackReserve;
    uint32_t             SizeOfStackCommit;
    uint32_t             SizeOfHeapReserve;
    uint32_t             SizeOfHeapCommit;
    uint32_t             LoaderFlags;
    uint32_t             NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_NT_HEADERS
{
    uint32_t          Signature;
    IMAGE_FILE_HEADER FileHeader;

    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};
#pragma pack(pop)
} // namespace win

namespace win
{
namespace detail
{
// TODO: better hashing algo
ALWAYS_INLINE_CXND uint32_t hash(const char* str)
{
    uint32_t hash = 0x811c9dc5;
    while (*str)
    {
        hash ^= *str++;
        hash *= 0x1000193;
    }
    return hash;
}

template <auto NameHash> struct syscall_holder
{
    uintptr_t func_address;

    ALWAYS_INLINE void init(const char* name, uintptr_t addr)
    {
        if (NameHash == hash(name))
        {
            func_address = addr;
        }
    }
};

template <class F> ALWAYS_INLINE inline void enum_syscalls(const uintptr_t image, F callback)
{
    auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    auto nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS*>(image + dos_header->e_lfanew);
    auto export_dir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
        image + nt_headers->OptionalHeader.DataDirectory[0].VirtualAddress
    );

    auto names = reinterpret_cast<const uint32_t*>(image + export_dir->AddressOfNames);
    auto funcs = reinterpret_cast<const uint32_t*>(image + export_dir->AddressOfFunctions);
    auto ords  = reinterpret_cast<const uint16_t*>(image + export_dir->AddressOfNameOrdinals);

    for (uint32_t i = 0; i < export_dir->NumberOfNames; ++i)
    {
        auto name = reinterpret_cast<const char*>(image + names[i]);
        auto func = reinterpret_cast<const uintptr_t>(image + funcs[ords[i]]);

        callback(name, func);
    }
}

ALWAYS_INLINE inline PEB_T* get_peb()
{
    return reinterpret_cast<PEB_T*>(syscall(e_syscall::get_peb));
}

} // namespace detail

ALWAYS_INLINE inline uintptr_t find_ntdll(win::PEB_T* peb)
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

} // namespace win

#define DEFINE_SYSCALL(name)  inline win::detail::syscall_holder<win::detail::hash(#name)> _##name##_holder;
#define INIT_SYSCALL(syscall) _##syscall##_holder.init(name, func);

DEFINE_SYSCALL(ZwQueryInformationProcess);
DEFINE_SYSCALL(ZwCreateFile);
DEFINE_SYSCALL(ZwWriteFile);
DEFINE_SYSCALL(ZwClose);

namespace win
{

ALWAYS_INLINE inline void init_syscalls()
{
    auto image = find_ntdll(win::detail::get_peb());
    detail::enum_syscalls(
        image,
        [&](const char* name, const uintptr_t func)
        {
            INIT_SYSCALL(ZwQueryInformationProcess);
            INIT_SYSCALL(ZwCreateFile);
            INIT_SYSCALL(ZwWriteFile);
            INIT_SYSCALL(ZwClose);
        }
    );
}

namespace detail
{

template <class... Ts> ALWAYS_INLINE inline uint32_t invoke_syscall(uintptr_t func_addr, Ts... args)
{
    uint64_t arg_array[13] = {(uint64_t)(args)...};

    register uint64_t syscall_id asm("a7") = (uint64_t)e_syscall::windows_syscall;

    register uint64_t _a0 asm("a0") = (uint64_t)func_addr;
    register uint64_t _a1 asm("a1") = (uint64_t)&arg_array;

    asm volatile("scall" : "+r"(_a0) : "r"(_a1), "r"(syscall_id));
    return _a0;
}

} // namespace detail
} // namespace win

#undef DEFINE_SYSCALL
#undef INIT_SYSCALL

#define WIN_SYSCALL(name, ...) win::detail::invoke_syscall((_##name##_holder).func_address, __VA_ARGS__)
