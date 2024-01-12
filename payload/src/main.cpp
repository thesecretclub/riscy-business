// https://github.com/jxy-s/stlkrn/pull/6
#define _XHASH_NO_FLOATING_POINT 1
#include "../crt/xhash"

#include <Windows.h>

#include <vector>
#include <string>
#include <unordered_map>

int main()
{
    const char* title = "riscvm";

    std::vector<char> v;
    for (size_t i = 0; i < strlen(title); i++)
    {
        v.push_back(title[i]);
    }
    v.push_back(0);

    std::string s;
    s = v.data();

    std::unordered_map<std::string, std::string> m;
    m["title"]   = s;
    m["message"] = "Hello from RISC-V!";

    MessageBoxA(0, m.at("message").c_str(), m.at("title").c_str(), 0);
}
