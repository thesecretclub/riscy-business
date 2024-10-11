#include <obfuscator/utility.hpp>
#include <obfuscator/msvc-secure.hpp>

#include <linuxpe>

#include <cstdio>

namespace obfuscator
{

bool loadFile(const std::string& path, std::vector<uint8_t>& data)
{
    FILE* file = nullptr;
    fopen_s(&file, path.c_str(), "rb");
    if (!file)
    {
        return false;
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file);

    data.resize(size);
    fread(data.data(), 1, size, file);
    fclose(file);

    return true;
}

bool findFunction(const std::span<uint8_t>& pe, std::string_view name, uint64_t& address, std::vector<uint8_t>& code)
{
    // Iterate export directory and look for 'riscvm_run'
    auto pdh = (win::dos_header_t*)pe.data();
    if (pdh->e_magic != win::DOS_HDR_MAGIC)
    {
        puts("Invalid DOS header.");
        return false;
    }

    auto pnth = (win::nt_headers_x64_t*)((uint8_t*)pe.data() + pdh->e_lfanew);
    if (pnth->signature != win::NT_HDR_MAGIC)
    {
        puts("Invalid NT header.");
        return false;
    }

    auto poh = &pnth->optional_header;
    if (poh->magic != win::OPT_HDR64_MAGIC)
    {
        puts("Invalid optional header.");
        return false;
    }

    auto rva2offset = [&](uint32_t rva) -> uint32_t
    {
        for (const auto& section : pnth->sections())
        {
            if (rva >= section.virtual_address && rva < section.virtual_address + section.virtual_size)
            {
                return rva - section.virtual_address + section.ptr_raw_data;
            }
        }
        return 0;
    };

    // Print all exports and the function rva
    uint32_t riscvmRunRva  = 0;
    auto     dataDirExport = poh->data_directories.export_directory;
    auto     exportDir     = (win::export_directory_t*)((uint8_t*)pe.data() + rva2offset(dataDirExport.rva));
    for (uint32_t i = 0; i < exportDir->num_names; i++)
    {
        auto addressOfNames = (uint32_t*)((uint8_t*)pe.data() + rva2offset(exportDir->rva_names));
        auto name           = (const char*)((uint8_t*)pe.data() + rva2offset(addressOfNames[i]));

        auto addressOfNameOrdinals = (uint16_t*)((uint8_t*)pe.data() + rva2offset(exportDir->rva_name_ordinals));
        auto nameOrdinal = addressOfNameOrdinals[i];

        auto addressOfFunctions = (uint32_t*)((uint8_t*)pe.data() + rva2offset(exportDir->rva_functions));
        auto functionAddress    = addressOfFunctions[nameOrdinal];

        if (strcmp(name, "riscvm_run") == 0)
        {
            riscvmRunRva = functionAddress;
            break;
        }
    }

    if (riscvmRunRva == 0)
    {
        puts("Failed to find riscvm_run export.");
        return false;
    }

    // Get function range from RUNTIME_FUNCTION
    auto dataDirException = poh->data_directories.exception_directory;
    auto exceptionDir = (win::runtime_function_t*)((uint8_t*)pe.data() + rva2offset(dataDirException.rva));
    for (int i = 0; i < dataDirException.size / sizeof(win::runtime_function_t); i++)
    {
        auto runtimeFunction = &exceptionDir[i];
        if (runtimeFunction->rva_begin == riscvmRunRva)
        {
            auto size = runtimeFunction->rva_end - runtimeFunction->rva_begin;

            address = poh->image_base + riscvmRunRva;
            code.resize(size);

            auto offset = rva2offset(riscvmRunRva);
            memcpy(code.data(), pe.data() + offset, size);

            return true;
        }
    }

    return false;
}

} // namespace obfuscator
