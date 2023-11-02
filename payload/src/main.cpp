#include <phnt.h>
#include <cstdint>
#include <cstdio>

#include <vector.hpp>

void vector_test()
{
    itlib::pod_vector<const char*> test;

    test.push_back("hello");
    test.push_back("world");
    test.push_back("vector");
    test.push_back("is");
    test.push_back("working");
    test.push_back("!!!");

    for (auto& str : test)
    {
        puts(str);
    }
}

void message_box_test()
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

int main(int argc, char** argv)
{
    vector_test();
    message_box_test();
    return 1337;
}
