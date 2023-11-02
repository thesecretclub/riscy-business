#include <phnt.h>

void* __cdecl malloc(size_t size)
{
    HANDLE heap = RtlGetCurrentPeb()->ProcessHeap;
    return RtlAllocateHeap(heap, HEAP_ZERO_MEMORY, size);
}

void* __cdecl _expand(void* block, size_t size)
{
    HANDLE heap = RtlGetCurrentPeb()->ProcessHeap;
    return RtlReAllocateHeap(heap, HEAP_ZERO_MEMORY, block, size);
}

void __cdecl free(void* block)
{
    HANDLE heap = RtlGetCurrentPeb()->ProcessHeap;
    RtlFreeHeap(heap, 0, block);
}

void* __cdecl calloc(size_t num, size_t size)
{
    return malloc(num * size);
}

void* __cdecl realloc(void* block, size_t size)
{
    return _expand(block, size);
}

int __cdecl puts(const char * s) {
    DWORD cbWritten;
    HANDLE hStdOut = GetStdHandle( STD_OUTPUT_HANDLE );
    WriteFile( hStdOut, s, lstrlen(s), &cbWritten, 0 );
    WriteFile( hStdOut, "\n", 1, &cbWritten, 0 );
    return (int)(cbWritten ? cbWritten : -1);
}
