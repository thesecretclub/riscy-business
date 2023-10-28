import sys
import argparse
import struct
from dataclasses import dataclass
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection, Relocation

from enum import Enum

class RelocTypeRiscv(Enum):
    R_RISCV_NONE = 0
    R_RISCV_32 = 1
    R_RISCV_64 = 2
    R_RISCV_RELATIVE = 3
    R_RISCV_COPY = 4
    R_RISCV_JUMP_SLOT = 5
    R_RISCV_TLS_DTPMOD32 = 6
    R_RISCV_TLS_DTPMOD64 = 7
    R_RISCV_TLS_DTPREL32 = 8
    R_RISCV_TLS_DTPREL64 = 9
    R_RISCV_TLS_TPREL32 = 10
    R_RISCV_TLS_TPREL64 = 11
    R_RISCV_TLS_DESC = 12
    R_RISCV_BRANCH = 16
    R_RISCV_JAL = 17
    R_RISCV_CALL = 18
    R_RISCV_CALL_PLT = 19
    R_RISCV_GOT_HI20 = 20
    R_RISCV_TLS_GOT_HI20 = 21
    R_RISCV_TLS_GD_HI20 = 22
    R_RISCV_PCREL_HI20 = 23
    R_RISCV_PCREL_LO12_I = 24
    R_RISCV_PCREL_LO12_S = 25
    R_RISCV_HI20 = 26
    R_RISCV_LO12_I = 27
    R_RISCV_LO12_S = 28
    R_RISCV_TPREL_HI20 = 29
    R_RISCV_TPREL_LO12_I = 30
    R_RISCV_TPREL_LO12_S = 31
    R_RISCV_TPREL_ADD = 32
    R_RISCV_ADD8 = 33
    R_RISCV_ADD16 = 34
    R_RISCV_ADD32 = 35
    R_RISCV_ADD64 = 36
    R_RISCV_SUB8 = 37
    R_RISCV_SUB16 = 38
    R_RISCV_SUB32 = 39
    R_RISCV_SUB64 = 40
    R_RISCV_GNU_VTINHERIT = 41
    R_RISCV_GNU_VTENTRY = 42
    R_RISCV_ALIGN = 43
    R_RISCV_RVC_BRANCH = 44
    R_RISCV_RVC_JUMP = 45
    R_RISCV_RVC_LUI = 46
    R_RISCV_RELAX = 51
    R_RISCV_SUB6 = 52
    R_RISCV_SET6 = 53
    R_RISCV_SET8 = 54
    R_RISCV_SET16 = 55
    R_RISCV_SET32 = 56
    R_RISCV_32_PCREL = 57
    R_RISCV_IRELATIVE = 58
    R_RISCV_PLT32 = 59

dynamic_reloc_support = {
    RelocTypeRiscv.R_RISCV_32: False,
    RelocTypeRiscv.R_RISCV_64: True,
    RelocTypeRiscv.R_RISCV_RELATIVE: False,
    RelocTypeRiscv.R_RISCV_COPY: False,
    RelocTypeRiscv.R_RISCV_JUMP_SLOT: False,
    RelocTypeRiscv.R_RISCV_TLS_DTPMOD32: False,
    RelocTypeRiscv.R_RISCV_TLS_DTPMOD64: False,
    RelocTypeRiscv.R_RISCV_TLS_DTPREL32: False,
    RelocTypeRiscv.R_RISCV_TLS_DTPREL64: False,
    RelocTypeRiscv.R_RISCV_TLS_TPREL32: False,
    RelocTypeRiscv.R_RISCV_TLS_TPREL64: False,
    RelocTypeRiscv.R_RISCV_TLS_DESC: False,
    RelocTypeRiscv.R_RISCV_IRELATIVE: False,
}

@dataclass
class MyRelocation:
    type: RelocTypeRiscv
    offset: int
    addend: int

    def __bytes__(self):
        return struct.pack("<BIq", self.type.value, self.offset, self.addend)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="Input ELF binary")
    parser.add_argument("--output", "-o", help="Output relocation file")
    parser.add_argument("--binary", "-b", help="Input binary", required=False)
    args = parser.parse_args()
    input: str = args.input
    output: str = args.output
    binary: str = args.binary
    with open(input, "rb") as f:
        elf = ELFFile(f)
        arch = elf.get_machine_arch()
        if arch != "RISC-V":
            print(f"Unsupported architecture '{arch}', expected RISC-V")
            sys.exit(1)

        # Extract the dynamic relocations
        dynamic_relocations: list[MyRelocation] = []
        for section in elf.iter_sections():
            if isinstance(section, RelocationSection):
                for i, relocation in enumerate(section.iter_relocations()):
                    offset = relocation["r_offset"]
                    info = relocation["r_info"]
                    type = RelocTypeRiscv(relocation["r_info_type"])
                    addend = relocation["r_addend"]
                    if type in dynamic_reloc_support:
                        print(f"{section.name}[{i}] offset: {hex(offset)}, info: {hex(info)}, type: {type.name}, addend: {hex(addend)}")
                        if not dynamic_reloc_support[type]:
                            print(f"Unsupported relocation type: {type}")
                            sys.exit(1)
                        dynamic_relocations.append(MyRelocation(type, offset, addend))

    # Create the output file
    if binary is not None:
        with open(binary, "rb") as f:
            binary_data = f.read()
    else:
        print("WARNING: No binary specified, emitting only the relocation structure")
        binary_data = b""

    with open(output, "wb") as f:
        f.write(binary_data)
        f.write(b"YARA")
        for relocation in dynamic_relocations:
            f.write(bytes(relocation))
        f.write(b"\x00")

if __name__ == "__main__":
    main()
