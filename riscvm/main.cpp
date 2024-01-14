#include <cstring>
#include <cstddef>
#include <cstdlib>

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
    g_trace = argc > 2 && _stricmp(argv[2], "--trace") == 0;
    if (g_trace)
    {
        // TODO: allow custom trace file location/name
        machine->trace = fopen("trace.txt", "w");
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
