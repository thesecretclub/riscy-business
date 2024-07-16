#include <cstring>
#include <cstddef>
#include <cstdlib>

#include "riscvm.h"
#include "riscvm-code.h"

void riscvm_loadfile(riscvm_ptr self, const char* filename)
{
    FILE* fp = fopen(filename, "rb");
    if ((!(fp != NULL)))
    {
        log("failed to open file\n");
    }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (size > sizeof(g_code))
    {
        log("loaded code too big!\n");
        exit(EXIT_FAILURE);
    }
    fread(g_code, size, 1, fp);
    fclose(fp);
    reg_write(reg_sp, (uint64_t)&g_stack[sizeof(g_stack) - 0x10]);
    self->pc = (int64_t)g_code;

#pragma pack(1)
    struct Features
    {
        uint32_t magic;
        struct
        {
            bool encrypted : 1;
            bool shuffled  : 1;
        };
        uint32_t key;
    };
    static_assert(sizeof(Features) == 9, "");

    auto features = (Features*)(g_code + size - sizeof(Features));
    if (features->magic != 'TAEF')
    {
        log("no features in the file (unencrypted payload?)\n");
#if defined(CODE_ENCRYPTION) || defined(OPCODE_SHUFFLING)
        exit(EXIT_FAILURE);
#else
        return;
#endif // CODE_ENCRYPTION || OPCODE_SHUFFLING
    }

#ifdef OPCODE_SHUFFLING
    if (!features->shuffled)
    {
        log("shuffling enabled on the host, disabled in the bytecode");
        exit(EXIT_FAILURE);
    }
#else
    if (features->shuffled)
    {
        log("shuffling disabled on the host, enabled in the bytecode");
        exit(EXIT_FAILURE);
    }
#endif // OPCODE_SHUFFLING

#ifdef CODE_ENCRYPTION
    if (!features->encrypted)
    {
        log("encryption enabled on the host, disabled in the bytecode");
        exit(EXIT_FAILURE);
    }
    self->base = self->pc;
    self->key  = features->key;
#else
    if (features->encrypted)
    {
        log("encryption disabled on the host, enabled in the bytecode");
        exit(EXIT_FAILURE);
    }
#endif // CODE_ENCRYPTION
}

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

#ifdef TRACING
    g_trace = argc > 2 && strcmp(argv[2], "--trace") == 0;
    if (g_trace)
    {
        // TODO: allow custom trace file location/name
        machine->trace = fopen("trace.txt", "w");
    }
#endif // TRACING

    riscvm_run(machine);
    exit((int)machine->regs[reg_a0]);

#ifdef TRACING
    if (g_trace)
    {
        fclose(machine->trace);
    }
#endif // TRACING

    return EXIT_SUCCESS;
}
