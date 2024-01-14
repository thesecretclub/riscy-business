from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import os

def parse_test_elf(file):
    with open(file, "rb") as f:
        elf = ELFFile(f)
        # Enumerate the SymbolTableSection
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for i in range(section.num_symbols()):
                    symbol = section.get_symbol(i)
                    if symbol.name:
                        if symbol.name.startswith("test_"):
                            address = symbol.entry.st_value
                            # Convert address to file offset
                            offset = list(elf.address_offsets(address))[0]
                            return address, offset
    return None, None


def main():
    code = "#pragma once\n\n"
    code += "#include <stdint.h>\n\n"
    tests = []
    directory = "isa-tests"
    for file in sorted(os.listdir(directory)):
        if file.startswith("rv64") and not file.endswith(".dump"):
            path = os.path.join(directory, file)
            address, offset = parse_test_elf(path)
            if offset is None:
                print(f"Failed to parse {file}")
                continue
            data = f"uint8_t {file.replace('-', '_')}_data[] = {{\n"
            with open(path, "rb") as f:
                # print the bytes in hex with max 32 bytes per line
                for i, byte in enumerate(f.read()):
                    data += f"0x{byte:02x}, "
                    if i % 16 == 15:
                        data += "\n"
            data += "\n};\n"
            code += data
            tests.append((file, address, offset))

    code += "\n"
    code += "struct Test {\n"
    code += "    const char* name;\n"
    code += "    uint8_t* data;\n"
    code += "    uint64_t size;\n"
    code += "    uint64_t address;\n"
    code += "    uint64_t offset;\n"
    code += "};\n\n"

    code += "static Test tests[] = {\n"
    for name, address, offset in tests:
        variable = f"{name.replace('-', '_')}_data"
        code += f"    {{ \"{name}\", {variable}, sizeof({variable}), {hex(address)}, {hex(offset)} }},\n"
    code += "\n};\n"

    with open("isa-tests/data.h", "wb") as f:
        f.write(code.encode("utf-8"))


if __name__ == "__main__":
    main()
