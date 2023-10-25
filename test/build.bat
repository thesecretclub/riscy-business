@echo off
set FLAGS=-target riscv64 -march=rv64g -fno-exceptions -mcmodel=medany -Os
clang.exe %FLAGS% -c crt0.c -o crt0.o
if not %ERRORLEVEL%==0 exit /b
clang.exe %FLAGS% -c main.c -o main.o
if not %ERRORLEVEL%==0 exit /b
clang++.exe %FLAGS% -c tinyc.cpp -o tinyc.o
if not %ERRORLEVEL%==0 exit /b
clang++.exe %FLAGS% -c test.cpp -o test.o
if not %ERRORLEVEL%==0 exit /b
clang++.exe %FLAGS% -c test2.cpp -o test2.o
if not %ERRORLEVEL%==0 exit /b
ld.lld.exe -o main.elf --oformat=elf -emit-relocs -T linker.ld --Map=main.map crt0.o tinyc.o main.o test.o test2.o
if not %ERRORLEVEL%==0 exit /b
llvm-objcopy -O binary main.elf main.pre.bin
if not %ERRORLEVEL%==0 exit /b
python ..\relocs.py main.elf --binary main.pre.bin --output main.bin
if not %ERRORLEVEL%==0 exit /b