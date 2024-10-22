import os
import sys
import pefile
import argparse
import subprocess
from glob import glob

from icicle import *

# Section flags
IMAGE_SCN_MEM_SHARED = 0x10000000
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

def page_align(size: int) -> int:
    return (size + 0xFFF) & ~0xFFF

class RISCVM:
    def __init__(self, *, stack_size = 0x50000, heap_size = 0x50000):
        self.emu = Icicle("x86_64", shadow_stack=False, jit=True)

        # Allocate the stack
        self.stack_begin = 0x10000
        self.stack_size = stack_size
        self.emu.mem_map(self.stack_begin, self.stack_size, MemoryProtection.ReadWrite)

        # Allocate the heap
        self.heap_begin = self.stack_begin + self.stack_size + 0x10000
        self.heap_size = heap_size
        self.emu.mem_map(self.heap_begin, self.heap_size, MemoryProtection.ReadWrite)

        self.coverage = []

    def run(self, riscvm_run_address: int, payload: bytes, *, get_coverage = False):
        # Reset instruction count
        self.emu.icount = 0

        # Zero stack and heap
        self.emu.mem_write(self.stack_begin, b"\x00" * self.stack_size)
        self.emu.mem_write(self.heap_begin, b"\x00" * self.heap_size)

        # Write VM bytecode
        vm_context = self.heap_begin
        vm_bytecode = self.heap_begin + 0x1000
        self.emu.mem_write(vm_bytecode, payload)

        # Write VM context
        a0_offset = 8 * 11
        self.emu.mem_write(vm_context, vm_bytecode.to_bytes(8, "little")) # riscvm.pc
        self.emu.mem_write(vm_context + a0_offset, b"\x11\x22\x33\x44\x55\x66\x77\x88") # riscvm.a0

        # Set up stack
        rsp = self.stack_begin + self.stack_size - 0x108
        fake_return = 0x1337
        self.emu.mem_write(rsp, fake_return.to_bytes(8, "little"))

        # Initialize registers
        def volatile(value):
            return (True, value)
        def preserved(value):
            return (False, value)

        regvalues = {
            "rax": volatile(0), # return value
            "rbx": preserved(0x1122334455667788),
            "rcx": volatile(vm_context), # arg 1
            "rdx": volatile(0), # arg 2
            "rsp": volatile(rsp),
            "rbp": preserved(0x2233445566778899),
            "rsi": preserved(0x33445566778899AA),
            "rdi": preserved(0x445566778899AABB),
            "r8": volatile(0), # arg 3
            "r9": volatile(0), # arg 4
            "r10": volatile(0),
            "r11": volatile(0),
            "r12": preserved(0x5566778899AABBCC),
            "r13": preserved(0x66778899AABBCCDD),
            "r14": preserved(0x778899AABBCCDDEE),
            "r15": preserved(0x8899AABBCCDDEEFF),
            "rip": volatile(riscvm_run_address),
        }
        for reg, (_, value) in regvalues.items():
            self.emu.reg_write(reg, value)

        # Run emulation
        if get_coverage:
            while True:
                rip = self.emu.reg_read("rip")
                if rip != fake_return:
                    self.coverage.append(rip)
                status = self.emu.step(1)
                if status != RunStatus.InstructionLimit:
                    break
        else:
            status = self.emu.run()
        rip = self.emu.reg_read("rip")
        if rip == fake_return:
            for reg, (skip, expected) in regvalues.items():
                if skip:
                    continue
                value = self.emu.reg_read(reg)
                if value != expected:
                    print(f"Expected value {hex(expected)} for non-volatile register {reg}, got {hex(value)}")

            a0 = int.from_bytes(self.emu.mem_read(vm_context + a0_offset, 8), "little") # riscvm.a0
            return a0
        print(f"status: {status}, exception: ({self.emu.exception_code}, {hex(self.emu.exception_value)})")
        print(f"RIP: {hex(rip)}")
        return -1

    def map_shellcode(self, address: int, shellcode: bytes):
        code_begin = address & ~0xFFF
        code_size = page_align(len(shellcode))
        self.emu.mem_map(code_begin, code_size, MemoryProtection.ExecuteRead)
        self.emu.mem_write(address, shellcode)
        return code_begin, code_size

    def map_image(self, pe: pefile.PE, *, image_base: int = 0):
        assert pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]

        image_size = pe.OPTIONAL_HEADER.SizeOfImage
        section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
        assert section_alignment == 0x1000, f"Unsupported section alignment {hex(section_alignment)}"

        if image_base == 0:
            image_base = pe.OPTIONAL_HEADER.ImageBase

        self.emu.mem_map(image_base, image_size, MemoryProtection.NoAccess)
        mapped_image = pe.get_memory_mapped_image(ImageBase=image_base)
        self.emu.mem_write(image_base, mapped_image)

        for section in pe.sections:
            name = section.Name.rstrip(b"\0")
            mask = section_alignment - 1
            rva = (section.VirtualAddress_adj + mask) & ~mask
            va = image_base + rva
            size = page_align(section.Misc_VirtualSize)
            flags = section.Characteristics
            assert flags & IMAGE_SCN_MEM_SHARED == 0, "Shared sections are not supported"
            assert flags & IMAGE_SCN_MEM_READ != 0, "Non-readable sections are not supported"
            execute = flags & IMAGE_SCN_MEM_EXECUTE
            write = flags & IMAGE_SCN_MEM_WRITE
            protect = MemoryProtection.ReadOnly
            if write:
                if execute:
                    protect = MemoryProtection.ExecuteReadWrite
                else:
                    protect = MemoryProtection.ReadWrite
            elif execute:
                protect = MemoryProtection.ExecuteRead
            self.emu.mem_protect(va, size, protect)
            print(f"Mapping section '{name.decode()}' {hex(rva)}[{hex(rva)}] -> {hex(va)} as {protect}")

        header_size = pe.sections[0].VirtualAddress_adj
        self.emu.mem_protect(image_base, header_size, MemoryProtection.ReadOnly)

        return image_base

def find_export(pe: pefile.PE, name: str) -> int:
    for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if symbol.name.decode() == name:
                return symbol.address
    raise ValueError(f"Could not find export: {name}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("riscvm", help="Path to riscvm.exe to obfuscate")
    parser.add_argument("--obfuscator", help="Path to the obfuscator binary", default="build/obfuscate")
    parser.add_argument("--no-transform", help="Disable transformations", action="store_true")
    parser.add_argument("--no-obfuscator", help="Directly map the executable, skipping obfuscation", action="store_true")
    parser.add_argument("--coverage", help="Output lighthouse coverage")
    args = parser.parse_args()

    riscvm = RISCVM()
    print(f"Stack: {hex(riscvm.stack_begin)}[{hex(riscvm.stack_size)}")
    print(f"Heap: {hex(riscvm.heap_begin)}[{hex(riscvm.heap_size)}]")

    if not os.path.exists(args.riscvm):
        raise FileNotFoundError(f"riscvm executable does not exist: {args.riscvm}")

    if args.no_obfuscator:
        pe = pefile.PE(args.riscvm)
        riscvm_run_rva = find_export(pe, "riscvm_run")
        image_base = riscvm.map_image(pe)
        riscvm_run_address = image_base + riscvm_run_rva
    else:
        if not os.path.exists(args.obfuscator):
            raise FileNotFoundError(f"Obfuscator does not exist: {args.obfuscator}")

        temp_dir = os.path.dirname(args.obfuscator)
        riscvm_run_clean = os.path.join(temp_dir, "test_riscvm_run.clean.bin")
        riscvm_run_obfuscated = os.path.join(temp_dir, "test_riscvm_run.obfuscated.bin")
        riscvm_run_path = os.path.join(temp_dir, "test_riscvm_run.bin")
        obfuscate_args = [
            args.obfuscator,
            args.riscvm,
            "-output", riscvm_run_obfuscated,
            "-clean-output", riscvm_run_clean
        ]
        riscvm_run_path = riscvm_run_clean if args.no_transform else riscvm_run_obfuscated

        p = subprocess.Popen(
            obfuscate_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        stdout, _ = p.communicate(0)
        exit_code = p.wait()
        if exit_code != 0:
            print(f"Obfuscation failed!\n{stdout.decode()}")
            sys.exit(1)

        with open(riscvm_run_path, "rb") as f:
            riscvm_run_data = f.read()
        riscvm_run_address = 0x140001104
        code_base, code_size = riscvm.map_shellcode(riscvm_run_address, riscvm_run_data)
        print(f"Shellcode: {hex(code_base)}[{hex(code_size)}]")

    total = 0
    success = 0
    for test in glob(os.path.join(os.path.dirname(__file__), "..", "riscvm", "isa-tests", "rv64*")):
        basename = os.path.basename(test)
        _, ext = os.path.splitext(basename)
        if ext != "":
            continue
        print(f"=== {basename} ===")
        with open(test, "rb") as f:
            f.seek(0x1190)
            payload = f.read()
        total += 1
        result = riscvm.run(riscvm_run_address, payload, get_coverage=args.coverage)
        if result == 0:
            print(f"    SUCCESS (icount: {riscvm.emu.icount})")
            success += 1
        else:
            print("    FAILURE")
    print(f"\n{success}/{total} ISA tests succeeded")
    if args.coverage:
        with open(args.coverage, "w") as f:
            for addr in riscvm.coverage:
                f.write(f"{hex(addr)}\n")
    sys.exit(0 if success == total else 1)

if __name__ == "__main__":
    main()
