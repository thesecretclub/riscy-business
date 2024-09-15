#include "pe_loader.hpp"
#include "logger.hpp"
#include <fstream>
#include <string.h>
#include <linux-pe/linuxpe>
#include <linux-pe/nt/directories/dir_exceptions.hpp>
#include <linux-pe/nt/directories/dir_export.hpp>
#include <linux-pe/nt/nt_headers.hpp>
#include <linux-pe/nt/optional_header.hpp>

namespace ObfuscatorLib
{

PELoader::PELoader()
{
}

PELoader::~PELoader()
{
}

bool PELoader::loadFile(const std::string& filePath)
{
    std::ifstream file(filePath, std::ios::binary);
    if (!file)
    {
        Logger::logError("Failed to open file: %s", filePath.c_str());
        return false;
    }

    peData_ = std::vector<uint8_t>(std::istreambuf_iterator<char>(file), {});
    return true;
}

bool PELoader::extractFunction(const std::string& functionName, uint64_t& address, std::vector<uint8_t>& functionCode)
{
    using namespace win;

    auto pdh = reinterpret_cast<const dos_header_t*>(peData_.data());
    if (pdh->e_magic != DOS_HDR_MAGIC)
    {
        Logger::logError("Invalid DOS header.");
        return false;
    }

    auto pnth = reinterpret_cast<const nt_headers_x64_t*>(peData_.data() + pdh->e_lfanew);
    if (pnth->signature != NT_HDR_MAGIC)
    {
        Logger::logError("Invalid NT header.");
        return false;
    }

    auto poh = &pnth->optional_header;
    if (poh->magic != OPT_HDR64_MAGIC)
    {
        Logger::logError("Invalid optional header.");
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

    uint32_t functionRva   = 0;
    auto     dataDirExport = poh->data_directories.export_directory;
    auto     exportDir     = (export_directory_t*)(peData_.data() + rva2offset(dataDirExport.rva));

    for (uint32_t i = 0; i < exportDir->num_names; i++)
    {
        auto addressOfNames = (uint32_t*)(peData_.data() + rva2offset(exportDir->rva_names));
        auto name           = (const char*)(peData_.data() + rva2offset(addressOfNames[i]));

        auto addressOfNameOrdinals = (uint16_t*)(peData_.data() + rva2offset(exportDir->rva_name_ordinals));
        auto nameOrdinal           = addressOfNameOrdinals[i];

        auto addressOfFunctions = (uint32_t*)(peData_.data() + rva2offset(exportDir->rva_functions));
        auto functionAddress    = addressOfFunctions[nameOrdinal];

        if (functionName == name)
        {
            functionRva = functionAddress;
            break;
        }
    }

    if (functionRva == 0)
    {
        Logger::logError("Failed to find function: %s", functionName.c_str());
        return false;
    }

    auto dataDirException = poh->data_directories.exception_directory;
    auto exceptionDir     = (runtime_function_t*)(peData_.data() + rva2offset(dataDirException.rva));
    for (int i = 0; i < dataDirException.size / sizeof(runtime_function_t); i++)
    {
        auto runtimeFunction = &exceptionDir[i];
        if (runtimeFunction->rva_begin == functionRva)
        {
            auto size = runtimeFunction->rva_end - runtimeFunction->rva_begin;

            address = poh->image_base + functionRva;
            functionCode.resize(size);

            auto offset = rva2offset(functionRva);
            auto first  = peData_.data() + offset;
            auto last   = first + size;
            std::copy(first, last, functionCode.data());

            return true;
        }
    }

    Logger::logError("Failed to find function: %s", functionName.c_str());
    return false;
}

} // namespace ObfuscatorLib
