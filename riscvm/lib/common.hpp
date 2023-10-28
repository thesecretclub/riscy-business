#pragma once
#include <stdint.h>

#ifdef NDEBUG
#define ALWAYS_INLINE [[gnu::always_inline]]
#else
#define ALWAYS_INLINE
#endif

#define ALWAYS_INLINE_CX   [[gnu::always_inline]] constexpr
#define ALWAYS_INLINE_CXND [[gnu::always_inline, nodiscard]] constexpr