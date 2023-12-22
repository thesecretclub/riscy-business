# riscy-business

![logo](.github/logo.png)

## Prerequisites

- Visual Studio 2022 with the `C++ Clang Compiler for Windows (16.0.5)` component
- CMake 3.26 (earlier may work, but not recommended)

## riscvm

This folder contains the VM host (`rv64i` interpreter).

To build:

```sh
cd riscvm
cmake -B build -T ClangCL
cmake --build build --config RelWithDebInfo
```

## transpiler

This folder contains the project responsible for changing making the LLVM Bitcode (.bc) files compatible for compilation with the `riscv64` target. This tool is the magic that allows us to build a regular Windows project with `clang-cl` and then convert that into a payload compatible with the `riscvm` host.

To build:

```sh
cd transpiler
cmake -B build -DCMAKE_PREFIX_PATH=c:/llvm-install
cmake --build build --config RelWithDebInfo
```

The `llvm-install` is a regular LLVM installation. This should match the version of Clang used by Visual Studio (sometimes it can be later). You can use a precompiled [llvm-17.0.2-win64.7z](https://github.com/thesecretclub/riscy-business/releases/download/transpiler-v0.3/llvm-17.0.2-win64.7z) if you want to save some time building LLVM.

## payload

This folder contains an example payload project.

To build:

```sh
cd payload
cmake -B build -T ClangCL
cmake --build build --config Release
```

This should give you a `payload.bin` that can be passed as an argument to `riscvm` to execute.
