#pragma once

#include <cstring>
#include <cstdio>
#include <cerrno>

// NOTE: These are source-compatible stubs for some MSVC-specific functions.

#ifndef _WIN32
template <size_t Count, class... Args> int sprintf_s(char (&Dest)[Count], const char* fmt, Args... args)
{
    return snprintf(Dest, Count, fmt, args...);
}

inline size_t strcpy_s(char* dst, size_t size, const char* src)
{
    return strlcpy(dst, src, size);
}

inline int fopen_s(FILE** fp, const char* filename, const char* mode)
{
    *fp = fopen(filename, mode);
    return errno;
}

static void __debugbreak()
{
    __builtin_debugtrap();
}
#endif // _WIN32
