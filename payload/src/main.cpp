#include "phnt.h"
#include <cstdint>
#include <cstdio>

void* operator new( size_t size )
{
    HANDLE heap = RtlGetCurrentPeb()->ProcessHeap;
    return RtlAllocateHeap(heap, HEAP_ZERO_MEMORY, size);
}

void* operator new[]( size_t size )
{
    HANDLE heap = RtlGetCurrentPeb()->ProcessHeap;
    return RtlAllocateHeap(heap, HEAP_ZERO_MEMORY, size);
}

void operator delete( void* ptr )
{
    HANDLE heap = RtlGetCurrentPeb()->ProcessHeap;
    RtlFreeHeap(heap, 0, ptr);
}

void operator delete[]( void* ptr )
{
    HANDLE heap = RtlGetCurrentPeb()->ProcessHeap;
    RtlFreeHeap(heap, 0, ptr);
}

int main(int argc, char** argv)
{
    auto test = new uint8_t[0x1000000];
    // use heap to allocate memory

    if (test)
    {
        memset(test, 0x41, 0x1000000);
        MessageBoxA(0, "Hello from riscvm", "1337", MB_SYSTEMMODAL | MB_RTLREADING);
    }
    else
    {
        MessageBoxA(0, "Uh-oh, RtlAllocateHeap failed", "1337", MB_SYSTEMMODAL | MB_RTLREADING);
    }

    delete[] test;
}
