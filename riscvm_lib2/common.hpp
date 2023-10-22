#pragma once
#include <stdint.h>

#ifdef NDEBUG
#define ALWAYS_INLINE [[gnu::always_inline]]
#else
#define ALWAYS_INLINE
#endif