#pragma once

#include <cstdio>

namespace ObfuscatorLib
{

class Logger
{
  public:
    Logger();
    ~Logger();

    static void log(const char* format, ...);
    static void logLine(const char* format, ...);
    static void logError(const char* format, ...);
    static void logWarning(const char* format, ...);
    static void logInfo(const char* format, ...);
};

} // namespace ObfuscatorLib
