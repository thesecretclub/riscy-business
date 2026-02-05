#include <cstring>
#include <cstddef>
#include <cstdlib>

#ifndef _WIN32
#include <strings.h>
#define _stricmp strcasecmp
#endif

#include "riscvm.h"

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        log("please supply a RV64I program to run!\n");
        return EXIT_FAILURE;
    }
    riscvm_ptr machine = (riscvm_ptr)malloc(sizeof(riscvm));
    memset(machine, 0, sizeof(riscvm));
    riscvm_loadfile(machine, argv[1]);

#ifdef _DEBUG
    g_trace = false;
    const char* trace_file = "trace.txt";
    for (int i = 2; i < argc; i++)
    {
        if (_stricmp(argv[i], "--trace") == 0)
        {
            g_trace = true;
        }
        else if (_stricmp(argv[i], "--trace-file") == 0 && i + 1 < argc)
        {
            trace_file = argv[++i];
        }
    }
    if (g_trace)
    {
        machine->trace = fopen(trace_file, "w");
        if (!machine->trace)
        {
            log("failed to open trace file: %s\n", trace_file);
            return EXIT_FAILURE;
        }
    }
#endif // _DEBUG

    riscvm_run(machine);
    exit((int)machine->regs[reg_a0]);

#ifdef _DEBUG
    if (g_trace)
    {
        fclose(machine->trace);
    }
#endif // _DEBUG

    return EXIT_SUCCESS;
}
