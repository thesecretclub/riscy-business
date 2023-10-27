#include <cstdlib>

#include "utility.hpp"

#include <llvm/Support/CommandLine.h>
#include <llvm/TargetParser/Triple.h>
#include <llvm/Demangle/Demangle.h>

using namespace llvm;

static cl::opt<std::string> g_input("input", cl::desc("Input bitcode"), cl::Required);
static cl::opt<std::string> g_output("output", cl::desc("Output bitcode"), cl::Required);

static void ProcessModule(Module& module)
{
    llvm::Triple triple(module.getTargetTriple());
    if (triple.getArch() != llvm::Triple::x86_64)
    {
        throw std::runtime_error("Unsupported architecture: " + triple.str());
    }

    /*
    x86_64 (e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128):
    e           + Little endian
    m:w         | Mangling: Windows COFF
    p270:32:32  | __ptr32 __sptr
    p271:32:32  | __ptr32 __uptr
    p272:64:64  | __ptr64
    i64:64      + sizeof(int64_t) == 8
    f80:128     | sizeof(long double) == 10
    n8:16:32:64 | native integer types
    S128        + stack alignment

    riscv64 (e-m:e-p:64:64-i64:64-i128:128-n32:64-S128):
    e           + Little endian
    m:e         | Mangling: ELF
    p:64:64     | pointers
    i64:64      + sizeof(int64_t) == 8
    i128:128    | sizeof(int128_t) == 16
    n32:64      | native integer types
    S128        + stack alignment
    */
    module.setDataLayout("e-m:e-p:64:64-i64:64-i128:128-n32:64-S128");
    module.setSourceFileName("transpiled.bc");
    module.setTargetTriple("riscv64-unknown-unknown");
    for (Function& function : module.functions())
    {
        // Remove x86-specific function attributes
        function.removeFnAttr("target-cpu");
        function.removeFnAttr("target-features");
        function.removeFnAttr("tune-cpu");
        function.removeFnAttr("stack-protector-buffer-size");

        // Remove dllimport/dllexport specifier
        function.setDLLStorageClass(GlobalValue::DefaultStorageClass);

        // Handle PEB access
        for (BasicBlock& block : function)
        {
            for (Instruction& instruction : block)
            {
                if (auto load = dyn_cast<LoadInst>(&instruction))
                {
                    auto addressSpace = load->getPointerAddressSpace();
                    if (addressSpace != 0)
                    {
                        throw std::runtime_error(
                            "Unsupported address space: " + std::to_string(addressSpace) + " (use RtlGetCurrentPeb)"
                        );
                    }
                }
                else if (auto store = dyn_cast<StoreInst>(&instruction))
                {
                    auto addressSpace = store->getPointerAddressSpace();
                    if (addressSpace != 0)
                    {
                        throw std::runtime_error(
                            "Unsupported address space: " + std::to_string(addressSpace) + " (use RtlGetCurrentPeb)"
                        );
                    }
                }
            }
        }
    }

    for (GlobalVariable& global : module.globals())
    {
        auto demangledName = demangle(global.getName());
        if (global.getName() != demangledName)
        {
            // TODO: re-mangle name possible?
        }
    }

    auto& comdatTable = module.getComdatSymbolTable();
    for (const auto& name : comdatTable.keys())
    {
        const llvm::Comdat& comdat = comdatTable.at(name);
        // TODO: match the demangled name
    }

    auto meta = module.getNamedMetadata("llvm.linker.options");
    if (meta != nullptr)
    {
        module.eraseNamedMetadata(meta);
    }
}

int main(int argc, char** argv)
{
    // Parse command line
    cl::ParseCommandLineOptions(argc, argv);

    // Load module
    LLVMContext context;
    auto        module = LoadModule(context, g_input);

    // Process module
    try
    {
        ProcessModule(*module);
    }
    catch (const std::exception& x)
    {
        outs() << x.what() << "\n";
        return EXIT_FAILURE;
    }

    // Save module
    SaveModule(module.get(), g_output);

    return EXIT_SUCCESS;
}
