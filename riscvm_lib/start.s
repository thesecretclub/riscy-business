.section .init, "ax"
.global _start
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    li  a1,0
    li  a0,0
    jal ra, main
    jal ra, exit
    .end
