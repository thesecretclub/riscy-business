Tiny RISC-V virtual machine written in Nelua (and C as consequence).

This is a minimal and simple RISC-V ISA emulator
implementing a subset of RV64I instructions.

Only the instructions required to run a minimal
userspace virtual machine are implemented.

The emulator allows to run C files compiled with GCC to RISC-V
inside a minimal sandboxed virtual machine.
The virtual machine is able to call host functions through system calls.

This project has inspired by [libriscv](https://github.com/fwsGonzo/libriscv).

## What is interesting about this?

This is a minimal example on how to interpret C programs
inside a sandboxed virtual machine. One may use this
concept to run compiled programs with GCC on any system
that have the emulator, or to sandbox a C application
inside isolated environment, or to do any kind
of hot reloading in application on the fly
(usually done with scripting languages).

## Run examples

Run examples with Nelua:
```
nelua -r riscvm.nelua examples/fib.bin
nelua -r riscvm.nelua examples/ack.bin
nelua -r riscvm.nelua examples/sieve.bin
```

The examples were compiled from the respective C files into RV64I binary.

Alternatively if you don't have Nelua:
```
gcc -O2 -o riscvm riscvm.c
./riscvm examples/fib.bin
```

## Compiling an example

All the examples are already compiled to RV64I, but in case you
want to edit or run a new example,
then use for example `make EXAMPLE=fib.c` to compile `fib.c` into `fib.bin`,
this requires RISC-V elf toolchain.

## How it works?

0. An example is coded in freestanding C code,
functionality outside the sandboxed environment such as printing to terminal
is implemented through system calls in `lib/syscalls.h` and minimal
libc is implemented in `lib/tinyc.c`.
1. The C example is compiled to RISC-V elf binary,
using `lib/start.s` to initialize the properly the virtual machine state,
and using special link rules through `lib/link.ld` to adjust the instruction
addresses.
2. RISC-V bytecode is stripped from the compiled elf binary into a bytecode binary.
3. The bytecode binary is loaded and run through `riscvm`,
interpreting RV64I instructions.
4. While interpreting the virtual machine may
call the host through system calls.
5. The application stops once the `exit` system call is called or if any error occur.

## How this was implemented?

This was implemented by reading the [RISC-V specification](https://riscv.org/technical/specifications/)

## Benchmarks

Equivalent code was run with the Lua 5.4, riscvm and natively
in the same system for some examples,
from the experiments the interpreted code can be 10~20x slower
than native code:

| example |  lua 5.4 | riscvm | x86_64 |
|---------|----------|--------|--------|
| ack     |   1070ms | 1022ms |   47ms |
| sieve   |   1077ms |  716ms |   64ms |

NOTE: This VM does not do any kind of JIT and has a very simple implementation,
there are space for optimizations.

## Future improvements

These extensions are not implemented yet and would be useful:

* M extension - Multiply and division
* F extension - Floating point with single precision
* D extension - Floating point with double precision

Also more C functions such as malloc/free/memcpy could
be implemented yet as system calls.