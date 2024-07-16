#pragma once

#include <stdint.h>

#ifdef _WIN32
#pragma section(".vmcode", read, write)
__declspec(align(4096)) uint8_t g_code[0x10000];
#pragma section(".vmstack", read, write)
__declspec(align(4096)) uint8_t g_stack[0x10000];
#else
uint8_t g_code[0x10000] __attribute__((aligned(0x1000)));
uint8_t g_stack[0x10000] __attribute__((aligned(0x1000)));
#endif // _WIN32
