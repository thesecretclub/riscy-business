#include "logger.hpp"
#include <cstdarg>

namespace ObfuscatorLib
{

void Logger::log(const char* format, ...)
{
#ifdef ENABLE_LOGGING
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
#else
    (void)format;
#endif
}

void Logger::logLine(const char* format, ...)
{

#ifdef ENABLE_LOGGING
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    printf("\n");
    va_end(args);
#else
    (void)format;
#endif
}

void Logger::logInfo(const char* format, ...)
{
#ifdef ENABLE_LOGGING
    va_list args;
    va_start(args, format);
    std::fprintf(stdout, "[INFO] ");
    std::vfprintf(stdout, format, args);
    std::fprintf(stdout, "\n");
    va_end(args);
#else
    (void)format;
#endif
}

void Logger::logWarning(const char* format, ...)
{
#ifdef ENABLE_LOGGING
    va_list args;
    va_start(args, format);
    std::fprintf(stdout, "[WARNING] ");
    std::vfprintf(stdout, format, args);
    std::fprintf(stdout, "\n");
    va_end(args);
#else
    (void)format;
#endif
}

void Logger::logError(const char* format, ...)
{
#ifdef ENABLE_LOGGING
    va_list args;
    va_start(args, format);
    std::fprintf(stderr, "[ERROR] ");
    std::vfprintf(stderr, format, args);
    std::fprintf(stderr, "\n");
    va_end(args);
#else
    (void)format;
#endif
}

} // namespace ObfuscatorLib
