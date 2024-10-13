#pragma once

#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#if defined(__APPLE__) && defined(__MACH__)
#define RISCVM_SECTION(name, decl) decl __attribute__((section("__DATA," name), aligned(0x1000)))
#else
#define RISCVM_SECTION(name, decl) decl __attribute__((section(name), aligned(0x1000)))
#endif // __APPLE__
#elif defined(_MSC_VER)
#define RISCVM_SECTION(name, decl) __pragma(section, name, read, write) __declspec(align(0x1000)) decl
#else
#warning Unsupported compiler
#define RISCVM_SECTION(name, decl) decl
#endif // __GNUC__

RISCVM_SECTION(".vmcode", static uint8_t g_code[0x10000]);
RISCVM_SECTION(".vmstack", static uint8_t g_stack[0x10000]);
