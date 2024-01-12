#include <phnt.h>
#include <stdlib.h>
#include <exception>

void* operator new(size_t size)
{
    return malloc(size);
}

void operator delete(void* p)
{
    free(p);
}

void* operator new[](size_t size)
{
    return malloc(size);
}

void operator delete[](void* p)
{
    free(p);
}

void operator delete(void* p, size_t sz)
{
    free(p);
}

namespace std
{

void __cdecl _Xbad_alloc()
{
    DebugBreak();
}

void __cdecl _Xinvalid_argument(_In_z_ const char* What)
{
    DebugBreak();
}

void __cdecl _Xlength_error(_In_z_ const char* What)
{
    DebugBreak();
}

void __cdecl _Xout_of_range(_In_z_ const char* What)
{
    DebugBreak();
}

void __cdecl _Xoverflow_error(_In_z_ const char* What)
{
    DebugBreak();
}

void __cdecl _Xruntime_error(_In_z_ const char* What)
{
    DebugBreak();
}

void __cdecl _Throw_Cpp_error(int Code)
{
    DebugBreak();
}

_Prhand _Raise_handler = [](const stdext::exception&)
{
    DebugBreak();
};

_Lockit::_Lockit() noexcept : _Locktype(0)
{
}

_Lockit::_Lockit(int _Kind) noexcept
{
}

_Lockit::~_Lockit() noexcept
{
}

} // namespace std
