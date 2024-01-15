#include <cstddef>
#include <memory>
#include <vector>

#include "riscvm.h"
#include "isa-tests/data.h"

int main(int argc, char** argv)
{
    std::vector<const char*> filter;
    for (int i = 1; i < argc; i++)
    {
        filter.push_back(argv[i]);
    }
    auto total      = 0;
    auto successful = 0;
    for (const auto& test : tests)
    {
        if (!filter.empty())
        {
            auto allowed = false;
            for (const auto& white : filter)
            {
                if (strcmp(test.name, white) == 0)
                {
                    allowed = true;
                    break;
                }
            }
            if (!allowed)
                continue;
        }

        printf("[%s] ", test.name);
        if (test.size > sizeof(g_code))
        {
            printf("ERROR (too big)\n");
            continue;
        }
        total++;

        memset(g_code, 0, sizeof(g_code));
        memcpy(g_code, test.data, test.size);
        riscvm vm   = {};
        auto   self = &vm;
        reg_write(reg_sp, (uint64_t)&g_stack[sizeof(g_stack) - 0x10]);
        self->pc = (int64_t)g_code + test.offset;
#ifdef _DEBUG
        g_trace             = true;
        char tracename[256] = "";
        sprintf(tracename, "%s.trace", test.name);
        self->trace  = fopen(tracename, "w");
        self->rebase = -self->pc + test.address;
#endif // _DEBUG
        riscvm_run(self);
#ifdef _DEBUG
        fclose(self->trace);
#endif // _DEBUG
        auto status = (int)reg_read(reg_a0);
        if (status != 0)
        {
            printf("FAILURE (status: %d)\n", status);
        }
        else
        {
            successful++;
            printf("SUCCESS\n");
        }
    }
    printf("\n%d/%d tests successful (%.2f%%)\n", successful, total, successful * 1.0f / total * 100);
    return successful == total ? EXIT_SUCCESS : EXIT_FAILURE;
}
