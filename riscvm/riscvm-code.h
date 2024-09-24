#pragma once

#include <stdint.h>

#ifdef _WIN32
#pragma section(".vmcode", read, write)
__declspec(align(4096)) static uint8_t g_code[0x10000];
#pragma section(".vmstack", read, write)
__declspec(align(4096)) static uint8_t g_stack[0x10000];
#else
static uint8_t g_code[0x10000] __attribute__((aligned(0x1000)));
static uint8_t g_stack[0x10000] __attribute__((aligned(0x1000)));
#endif // _WIN32
