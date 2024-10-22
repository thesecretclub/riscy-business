import os
import sys
import argparse
import subprocess
from glob import glob

from icicle import *

class RISCVM:
    def __init__(self, riscvm_run_address: int, riscvm_run_data: bytes, *, stack_size = 0x5000, heap_size = 0x5000):
        self.emu = Icicle("x86_64", shadow_stack=False, jit=True)

        # Allocate and write the riscvm_run function code
        self.riscvm_run_address = riscvm_run_address
        code_begin = riscvm_run_address & ~0xFFF
        code_size = len(riscvm_run_data) + 0x1000
        self.emu.mem_map(code_begin, code_size, MemoryProtection.ExecuteRead)
        self.emu.mem_write(riscvm_run_address, riscvm_run_data)

        # Allocate the stack
        self.stack_begin = 0x10000
        self.stack_size = stack_size
        self.emu.mem_map(self.stack_begin, self.stack_size, MemoryProtection.ReadWrite)

        # Allocate the heap
        self.heap_begin = 0x20000
        self.heap_size = heap_size
        self.emu.mem_map(self.heap_begin, self.heap_size, MemoryProtection.ReadWrite)

    def run(self, payload: bytes):
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
        rsp = self.stack_begin + self.stack_size - 0x18
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
            "rip": volatile(self.riscvm_run_address),
        }
        for reg, (_, value) in regvalues.items():
            self.emu.reg_write(reg, value)

        # Run emulation
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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("riscvm", help="Path to riscvm.exe to obfuscate")
    parser.add_argument("--obfuscator", help="Path to the obfuscator binary", default="build/obfuscate")
    parser.add_argument("--no-transform", help="Disable transformations", action="store_true")
    args = parser.parse_args()

    if not os.path.exists(args.riscvm):
        raise FileNotFoundError(f"riscvm executable does not exist: {args.riscvm}")

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
    riscvm = RISCVM(0x140001104, riscvm_run_data)

    total = 0
    success = 0
    for test in glob(os.path.join(os.path.dirname(__file__), "..", "riscvm", "isa-tests", "rv64*")):
        basename = os.path.basename(test)
        print(f"=== {basename} ===")
        with open(test, "rb") as f:
            f.seek(0x1190)
            payload = f.read()
        total += 1
        result = riscvm.run(payload)
        if result == 0:
            print(f"    SUCCESS (icount: {riscvm.emu.icount})")
            success += 1
        else:
            print("    FAILURE")
    print(f"\n{success}/{total} ISA tests succeeded")
    sys.exit(0 if success == total else 1)

if __name__ == "__main__":
    main()
