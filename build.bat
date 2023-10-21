clang.exe -target riscv64 -march=rv64g -c start.c -o start.o
clang.exe -target riscv64 -march=rv64g -c main.c -o main.o
clang++.exe -target riscv64 -march=rv64g -c test.cpp -o test.o -fno-exceptions
clang++.exe -target riscv64 -march=rv64g -c test2.cpp -o test2.o -fno-exceptions
ld.lld.exe -o main.elf --oformat=elf -emit-relocs -T linker.ld --Map=main.map start.o main.o test.o test2.o
llvm-objcopy -O binary main.elf main.bin
rem ld.lld.exe -o main.elf --oformat=elf -T linker.ld start.o main.o test.o
rem ld.lld.exe -o main.bin1 --oformat=binary -emit-relocs -T linker.ld --Map=main1.map start.o main.o test.o test2.o
rem ld.lld.exe -o main.elf --oformat=elf -emit-relocs --relocatable -T linker.ld --Map=main.map start.o main.o test.o test2.o
rem llvm-objcopy -O binary main.elf main.bin