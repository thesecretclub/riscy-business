import os
import sys
from glob import glob

from icicle import *

class RISCVM:
    def __init__(self, riscvm_run_address: int, riscvm_run_data: bytes, *, stack_size = 0x5000, heap_size = 0x5000):
        self.emu = Icicle("x86_64")

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
        # Zero stack and heap
        self.emu.mem_write(self.stack_begin, b"\x00" * self.stack_size)
        self.emu.mem_write(self.heap_begin, b"\x00" * self.heap_size)

        # Write VM bytecode
        vm_context = self.heap_begin
        vm_bytecode = self.heap_begin + 0x1000
        self.emu.mem_write(vm_bytecode, payload)

        # Write VM context
        self.emu.mem_write(vm_context, vm_bytecode.to_bytes(8, "little")) # riscvm.pc
        self.emu.reg_write("rcx", vm_context)

        # Set up stack
        rsp = self.stack_begin + self.stack_size - 0x18
        fake_return = 0x1337
        self.emu.mem_write(rsp, fake_return.to_bytes(8, "little"))
        self.emu.reg_write("rsp", rsp)

        # Set RIP
        self.emu.reg_write("rip", self.riscvm_run_address)

        # Run emulation
        status = self.emu.run()
        rip = self.emu.reg_read("rip")
        if rip == fake_return:
            a0 = int.from_bytes(self.emu.mem_read(vm_context + 8 * 11, 8), "little") # riscvm.a0
            return a0
        print(f"status: {status}, exception: ({self.emu.exception_code}, {hex(self.emu.exception_value)})")
        print(f"RIP: {hex(rip)}")
        return -1

if __name__ == "__main__":
    with open("riscvm_run", "rb") as f:
        riscvm_run_data = f.read()
    riscvm = RISCVM(0x140001104, riscvm_run_data)

    total = 0
    success = 0
    for test in glob("../../riscvm/isa-tests/rv64*"):
        basename = os.path.basename(test)
        print(f"=== {basename} ===")
        with open(test, "rb") as f:
            f.seek(0x1190)
            payload = f.read()
        total += 1
        result = riscvm.run(payload)
        if result == 0:
            print("    SUCCESS")
            success += 1
        else:
            print("    FAILURE")
    print(f"\n{success}/{total} ISA tests succeeded")
    sys.exit(0 if success == total else 1)
