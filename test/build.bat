@echo off
clang.exe -target riscv64 -march=rv64g -c start.c -o start.o
if not %ERRORLEVEL%==0 exit /b
clang.exe -target riscv64 -march=rv64g -c main.c -o main.o
if not %ERRORLEVEL%==0 exit /b
clang++.exe -target riscv64 -march=rv64g -c test.cpp -o test.o -fno-exceptions
if not %ERRORLEVEL%==0 exit /b
clang++.exe -target riscv64 -march=rv64g -c test2.cpp -o test2.o -fno-exceptions
if not %ERRORLEVEL%==0 exit /b
ld.lld.exe -o main.elf --oformat=elf -emit-relocs -T linker.ld --Map=main.map start.o main.o test.o test2.o
if not %ERRORLEVEL%==0 exit /b
llvm-objcopy -O binary main.elf main.pre.bin
if not %ERRORLEVEL%==0 exit /b
python ..\relocs.py main.elf --binary main.pre.bin --output main.bin
if not %ERRORLEVEL%==0 exit /b