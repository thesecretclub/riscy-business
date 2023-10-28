@echo off
set FLAGS=-target riscv64 -march=rv64g -fno-exceptions -mcmodel=medany -fshort-wchar -Os
clang.exe %FLAGS% -c ..\lib\crt0.c -o crt0.o
if not %ERRORLEVEL%==0 exit /b
clang.exe %FLAGS% -c main.c -o main.o
if not %ERRORLEVEL%==0 exit /b
clang++.exe %FLAGS% -c tinyc.cpp -o tinyc.o
if not %ERRORLEVEL%==0 exit /b
clang++.exe %FLAGS% -c test.cpp -o test.o
if not %ERRORLEVEL%==0 exit /b
clang++.exe %FLAGS% -c test2.cpp -o test2.o
if not %ERRORLEVEL%==0 exit /b
ld.lld.exe -o main.elf --oformat=elf -emit-relocs -T ..\lib\linker.ld --Map=main.map crt0.o tinyc.o main.o test.o test2.o
if not %ERRORLEVEL%==0 exit /b
llvm-objcopy -O binary main.elf main.pre.bin
if not %ERRORLEVEL%==0 exit /b
echo Handling relocations...
python ..\relocs.py main.elf --binary main.pre.bin --output main.bin
if not %ERRORLEVEL%==0 exit /b
echo Encrypting binary...
python ..\encrypt.py --encrypt --shuffle --map main.map --shuffle-map ..\shuffled_opcodes.json main.bin --output main.enc.bin
if not %ERRORLEVEL%==0 exit /b