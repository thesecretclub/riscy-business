static void exit(int exit_code);
static void riscvm_relocs();
void        riscvm_imports() __attribute__((weak));
static void riscvm_init_arrays();
extern int __attribute((noinline)) main();

// NOTE: This function has to be first in the file
void _start()
{
    riscvm_relocs();
    riscvm_imports();
    riscvm_init_arrays();
    exit(main());
    asm volatile("ebreak");
}

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

static __attribute((noinline)) void exit(int exit_code)
{
    register uintptr_t a0 asm("a0") = exit_code;
    register uintptr_t a7 asm("a7") = 10000;
    asm volatile("scall" : "+r"(a0) : "r"(a7) : "memory");
}

typedef struct
{
    uint8_t  type;
    uint32_t offset;
    int64_t  addend;
} __attribute__((packed)) Relocation;

extern uint8_t __base[];
extern uint8_t __relocs_start[];

#define LINK_BASE    0x8000000
#define R_RISCV_NONE 0
#define R_RISCV_64   2

static __attribute((noinline)) void riscvm_relocs()
{
    if (*(uint32_t*)__relocs_start != 'ALER')
    {
        asm volatile("ebreak");
    }

    uintptr_t load_base = (uintptr_t)__base;

    for (Relocation* itr = (Relocation*)(__relocs_start + sizeof(uint32_t)); itr->type != R_RISCV_NONE; itr++)
    {
        if (itr->type == R_RISCV_64)
        {
            uint64_t* ptr = (uint64_t*)((uintptr_t)itr->offset - LINK_BASE + load_base);
            *ptr -= LINK_BASE;
            *ptr += load_base;
        }
        else
        {
            asm volatile("ebreak");
        }
    }
}

typedef void (*InitFunction)();
extern InitFunction __init_array_start;
extern InitFunction __init_array_end;

static __attribute((optnone)) void riscvm_init_arrays()
{
    for (InitFunction* itr = &__init_array_start; itr != &__init_array_end; itr++)
    {
        (*itr)();
    }
}

uintptr_t riscvm_host_call(uintptr_t address, uintptr_t args[13])
{
    register uintptr_t a0 asm("a0") = address;
    register uintptr_t a1 asm("a1") = (uintptr_t)args;
    register uintptr_t a7 asm("a7") = 20000;
    asm volatile("scall" : "+r"(a0) : "r"(a1), "r"(a7));
    return a0;
}

uintptr_t riscvm_get_peb()
{
    register uintptr_t a0 asm("a0") = 0;
    register uintptr_t a7 asm("a7") = 20001;
    asm volatile("scall" : "+r"(a0) : "r"(a7) : "memory");
    return a0;
}

typedef struct _LIST_ENTRY
{
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
} LIST_ENTRY;

typedef struct _UNICODE_STRING
{
    uint16_t Length;
    uint16_t MaximumLength;
    wchar_t* Buffer;
} UNICODE_STRING;

typedef struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE* Children[2];
        struct
        {
            struct _RTL_BALANCED_NODE* Left;
            struct _RTL_BALANCED_NODE* Right;
        };
    };
    union
    {
        uint8_t   Red     : 1;
        uint8_t   Balance : 2;
        uintptr_t ParentValue;
    };
} RTL_BALANCED_NODE;

typedef struct _PEB_LDR_DATA
{
    uint32_t   Length;
    uint32_t   Initialized;
    uintptr_t  SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA;

typedef struct _PEB
{
    uint8_t       Reserved1[2];
    uint8_t       BeingDebugged;
    uint8_t       Reserved2[1];
    const char*   Reserved3[2];
    PEB_LDR_DATA* Ldr;
} PEB;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY                  InLoadOrderLinks;
    LIST_ENTRY                  InMemoryOrderLinks;
    LIST_ENTRY                  InInitializationOrderLinks;
    uintptr_t                   DllBase;
    uintptr_t                   EntryPoint;
    uint32_t                    SizeOfImage;
    UNICODE_STRING              FullDllName;
    UNICODE_STRING              BaseDllName;
    uint32_t                    Flags;
    uint16_t                    ObsoleteLoadCount;
    uint16_t                    TlsIndex;
    LIST_ENTRY                  HashLinks;
    uint32_t                    TimeDateStamp;
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
    uintptr_t                   Lock;
    uintptr_t                   DdagNode;
    LIST_ENTRY                  NodeModuleLink;
    struct _LDRP_LOAD_CONTEXT*  LoadContext;
    uintptr_t                   ParentDllBase;
    uintptr_t                   SwitchBackContext;
    RTL_BALANCED_NODE           BaseAddressIndexNode;
    RTL_BALANCED_NODE           MappingInfoIndexNode;
    uintptr_t                   OriginalBase;
    uint64_t                    LoadTime;
    uint32_t                    BaseNameHashValue;
} LDR_DATA_TABLE_ENTRY;

#define CONTAINING_RECORD(address, type, field) \
    ((type*)((char*)(address) - (unsigned long)(&((type*)0)->field)))

uintptr_t riscvm_resolve_dll(uint32_t module_hash)
{
    static PEB* peb = 0;
    if (!peb)
    {
        peb = (PEB*)riscvm_get_peb();
    }
    LIST_ENTRY* begin = &peb->Ldr->InLoadOrderModuleList;
    for (LIST_ENTRY* itr = begin->Flink; itr != begin; itr = itr->Flink)
    {
        LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(itr, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (entry->BaseNameHashValue == module_hash)
        {
            return (uintptr_t)entry->DllBase;
        }
    }
    return 0;
}

__attribute__((always_inline)) static uint32_t hash_x65599(const char* buffer, bool case_sensitive)
{
    uint32_t hash = 0;
    for (; *buffer != '\0'; buffer++)
    {
        char ch = *buffer;
        if (!case_sensitive && ch >= L'a')
        {
            if (ch <= L'z')
            {
                ch -= L' ';
            }
        }
        hash = ch + 65599 * hash;
    }
    return hash;
}

#pragma pack(push, 1)
typedef struct _IMAGE_DOS_HEADER
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
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER
{
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct _IMAGE_EXPORT_DIRECTORY
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
} IMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_DATA_DIRECTORY
{
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64
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
} IMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_OPTIONAL_HEADER32
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
} IMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_NT_HEADERS
{
    uint32_t          Signature;
    IMAGE_FILE_HEADER FileHeader;

    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS;
#pragma pack(pop)

uintptr_t riscvm_resolve_import(uintptr_t image, uint32_t export_hash)
{
    IMAGE_DOS_HEADER*       dos_header      = (IMAGE_DOS_HEADER*)image;
    IMAGE_NT_HEADERS*       nt_headers      = (IMAGE_NT_HEADERS*)(image + dos_header->e_lfanew);
    uint32_t                export_dir_size = nt_headers->OptionalHeader.DataDirectory[0].Size;
    IMAGE_EXPORT_DIRECTORY* export_dir =
        (IMAGE_EXPORT_DIRECTORY*)(image + nt_headers->OptionalHeader.DataDirectory[0].VirtualAddress);
    uint32_t* names = (uint32_t*)(image + export_dir->AddressOfNames);
    uint32_t* funcs = (uint32_t*)(image + export_dir->AddressOfFunctions);
    uint16_t* ords  = (uint16_t*)(image + export_dir->AddressOfNameOrdinals);

    for (uint32_t i = 0; i < export_dir->NumberOfNames; ++i)
    {
        char*     name = (char*)(image + names[i]);
        uintptr_t func = (uintptr_t)(image + funcs[ords[i]]);
        // Ignore forwarded exports (TODO: handle properly?)
        if (func >= (uintptr_t)export_dir && func < (uintptr_t)export_dir + export_dir_size)
            continue;
        uint32_t hash = hash_x65599(name, true);
        if (hash == export_hash)
        {
            return func;
        }
    }

    return 0;
}

void riscvm_imports()
{
}

void* memset(void* dest, int ch, uintptr_t count)
{
    for (uintptr_t i = 0; i < count; i++)
    {
        ((uint8_t*)dest)[i] = ch;
    }
    return dest;
}
