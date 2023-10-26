# payload

This is an example project showcasing how you can build a payload with native Windows tooling and then cross-compile it for RISC-V.

## Building

First generate and build a Visual Studio solution with `clang-cl`:

```sh
cmake -B build -T ClangCL
cmake --build build --config Release
```

If everything went well, you should get `payload.bin` which you can load into riscvm.

## Bitcode Processing (TODO)

- Remove filename
- Understand and remove `target datalayout`
- Remove `target triple`
- Remove function `attributes`
  - `"target-cpu"="x86-64"`
  - `"target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87"`
  - `"tune-cpu"="generic"`
- Remove `!llvm.linker.options`
