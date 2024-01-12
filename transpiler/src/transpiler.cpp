#include <cstdlib>
#include <fstream>
#include <vector>
#include <unordered_set>
#include <unordered_map>

#include "utility.hpp"

#include <llvm/Support/CommandLine.h>
#include <llvm/TargetParser/Triple.h>
#include <llvm/Demangle/Demangle.h>
#include <llvm/IR/Verifier.h>

using namespace llvm;

static cl::opt<std::string> g_input("input", cl::desc("Input bitcode"), cl::Required);
static cl::opt<std::string> g_importmap("importmap", cl::desc("Import map"));
static cl::opt<std::string> g_output("output", cl::desc("Output bitcode"), cl::Required);

constexpr uint32_t hash_x65599(const char* buffer, bool case_sensitive)
{
    uint32_t hash = 0;
    for (; *buffer != '\0'; buffer++)
    {
        char ch = *buffer;
        if (!case_sensitive && ch >= L'a')
        {
            if (ch <= L'z')
            {
                ch -= L' ';
            }
        }
        hash = ch + 65599 * hash;
    }
    return hash;
}

#define hash_module(name) hash_x65599(name, false)
#define hash_import(name) hash_x65599(name, true)

using ImportMap = std::unordered_map<std::string, std::string>;

class HostCall
{
    IRBuilder<>&        builder;
    const size_t        hostCallArgCount = 13;
    Function*           hostCallFn       = nullptr;
    std::vector<Value*> hostCallArgPtrs;
    AllocaInst*         hostCallArr;

  public:
    HostCall(IRBuilder<>& builder, Function* hostCallFn) : builder(builder), hostCallFn(hostCallFn)
    {
        hostCallArr = builder.CreateAlloca(
            PointerType::get(builder.getContext(), 0),
            ConstantInt::get(Type::getInt32Ty(builder.getContext()), hostCallArgCount),
            "args"
        );
    }

    Value* CreateCall(Value* address, std::vector<Value*> args, const Twine& name)
    {
        for (size_t i = 0; i < args.size(); i++)
        {
            if (i >= hostCallArgCount)
                throw std::runtime_error("Illegal riscvm_host_call");

            if (i >= hostCallArgPtrs.size())
            {
                hostCallArgPtrs.push_back(builder.CreateGEP(
                    PointerType::get(builder.getContext(), 0),
                    hostCallArr,
                    {ConstantInt::get(Type::getInt32Ty(builder.getContext()), i)},
                    "arg" + std::to_string(i) + "_ptr"
                ));
            }
            builder.CreateStore(args[i], hostCallArgPtrs[i]);
        }
        return builder.CreateCall(hostCallFn, {address, hostCallArr}, name);
    }
};

static void HandleImports(Module& module, const std::vector<Function*> importedFunctions, const ImportMap& importmap)
{
    if (importedFunctions.empty())
    {
        // Nothing to do
        return;
    }

    auto reservedFunction = [&](const std::string& name, FunctionType* functionTy)
    {
        if (module.getFunction(name) != nullptr)
        {
            throw std::runtime_error("Reserved function " + name + " already defined");
        }
        return Function::Create(functionTy, GlobalValue::ExternalLinkage, name, module);
    };

    auto& context = module.getContext();

    auto ptrTy     = PointerType::get(context, 0);
    auto ptrSize   = module.getDataLayout().getPointerSizeInBits();
    auto uintptrTy = IntegerType::get(context, ptrSize);
    auto int32Ty   = Type::getInt32Ty(context);

    auto resolveDllTy = FunctionType::get(ptrTy, {int32Ty}, false);
    auto resolveDllFn = reservedFunction("riscvm_resolve_dll", resolveDllTy);

    auto resolveImportTy = FunctionType::get(ptrTy, {ptrTy, int32Ty}, false);
    auto resolveImportFn = reservedFunction("riscvm_resolve_import", resolveImportTy);

    auto hostCallTy = FunctionType::get(ptrTy, {ptrTy, ptrTy}, false);
    auto hostCallFn = reservedFunction("riscvm_host_call", hostCallTy);

    auto importsTy = FunctionType::get(Type::getVoidTy(context), false);
    auto importsFn = reservedFunction("riscvm_imports", importsTy);

    IRBuilder<> resolveBuilder(BasicBlock::Create(context, "entry", importsFn));
    HostCall    hostCallRoot(resolveBuilder, hostCallFn);

    Value*                               ptrLoadLibraryA = nullptr;
    std::unordered_map<uint32_t, Value*> baseValues;

    auto loadLibrary = [&](const std::string& name) -> Value*
    {
        auto hash = hash_module(name.c_str());
        auto itr  = baseValues.find(hash);
        if (itr != baseValues.end())
        {
            return itr->second;
        }

        static std::unordered_set<uint32_t> alwaysLoadedHashes = {
            hash_module("ntdll.dll"),
            hash_module("kernel32.dll"),
            hash_module("kernelbase.dll"),
        };

        auto valueName = name + "_base";
        if (alwaysLoadedHashes.count(hash))
        {
            auto base = resolveBuilder.CreateCall(
                resolveDllFn, {ConstantInt::get(int32Ty, hash_module(name.c_str()))}, valueName
            );
            baseValues.emplace(hash, base);
            return base;
        }

        if (ptrLoadLibraryA == nullptr)
        {
            itr = baseValues.find(hash_module("kernel32.dll"));
            if (itr == baseValues.end())
            {
                throw std::runtime_error("Trying to load library " + name + " without kernel32 base");
            }

            ptrLoadLibraryA = resolveBuilder.CreateCall(
                resolveImportFn, {itr->second, ConstantInt::get(int32Ty, hash_import("LoadLibraryA"))}, "import_LoadLibraryA"
            );
        }

        auto dllNameConst  = ConstantDataArray::getString(context, name);
        auto dllNameGlobal = new GlobalVariable(
            module, dllNameConst->getType(), true, GlobalValue::PrivateLinkage, dllNameConst, "str_" + name
        );
        auto base = hostCallRoot.CreateCall(ptrLoadLibraryA, {dllNameGlobal}, valueName);
        baseValues.emplace(hash, base);
        return base;
    };

    auto kernel32_base = loadLibrary("kernel32.dll");

    for (auto function : importedFunctions)
    {
        if (importmap.empty())
        {
            throw std::runtime_error("dllimport function found, but no -importmap specified");
        }

        auto importName = function->getName().str();
        if (importmap.count(importName) == 0)
        {
            throw std::runtime_error("Imported function not found in import map: " + importName);
        }

        auto importDll = importmap.at(importName);
        if (function->getDLLStorageClass() != GlobalValue::DefaultStorageClass)
        {
            function->setDLLStorageClass(GlobalValue::DefaultStorageClass);
            outs() << "[Import] ";
        }
        else
        {
            outs() << "[MSVCRT] ";
        }
        outs() << importDll << ":" << importName << "\n";

        if (function->isVarArg())
        {
            throw std::runtime_error("Unsupported vararg import " + importName);
        }

        auto base = loadLibrary(importDll);
        auto ptr  = resolveBuilder.CreateCall(
            resolveImportFn, {base, ConstantInt::get(int32Ty, hash_import(importName.c_str()))}, "import_" + importName
        );

        auto importGlobal = new GlobalVariable(
            module,
            ptrTy,
            false,
            GlobalValue::PrivateLinkage,
            ConstantPointerNull::get(PointerType::get(context, 0)),
            "import_" + importName
        );

        // Store the resolved address in the global
        resolveBuilder.CreateStore(ptr, importGlobal);

        // Create the import host call stub
        IRBuilder<>         builder(BasicBlock::Create(module.getContext(), "entry", function));
        HostCall            hostCall(builder, hostCallFn);
        std::vector<Value*> args;

        for (size_t i = 0; i < function->arg_size(); i++)
        {
            Value* arg     = function->getArg(i);
            auto   argTy   = arg->getType();
            auto   argName = "arg" + std::to_string(i);

            if (argTy->isPointerTy())
            {
                args.push_back(arg);
            }
            else if (argTy->isIntegerTy())
            {
                // outs() << "  arg[" << i << "]: " << size << " <> " << ptrSize << "\n";
                auto size = argTy->getPrimitiveSizeInBits().getFixedValue();
                if (size > ptrSize)
                {
                    throw std::runtime_error(
                        "Parameter type size bigger than pointer size: " + std::to_string(size)
                    );
                }
                else if (size < ptrSize)
                {
                    arg = builder.CreateZExt(arg, uintptrTy, argName + "_zext");
                }

                auto castValue = builder.CreateIntToPtr(arg, ptrTy, argName + "_cast");
                args.push_back(castValue);
            }
            else
            {
                throw std::runtime_error("Unsupported import argument type");
            }
        }

        auto address  = builder.CreateLoad(ptrTy, importGlobal, "import_address");
        auto retValue = hostCall.CreateCall(address, args, "return");

        // TODO: cast that shit
        auto returnTy = function->getReturnType();
        if (returnTy->isVoidTy())
        {
            builder.CreateRetVoid();
        }
        else if (returnTy->isPointerTy())
        {
            builder.CreateRet(retValue);
        }
        else if (returnTy->isIntegerTy())
        {
            auto retCast = builder.CreatePtrToInt(retValue, uintptrTy, "return_cast");
            auto size    = returnTy->getPrimitiveSizeInBits().getFixedValue();
            if (size > ptrSize)
            {
                throw std::runtime_error("Return type size bigger than pointer size: " + std::to_string(size));
            }
            else if (size < ptrSize)
            {
                auto retTrunc = builder.CreateTrunc(retCast, returnTy, "return_trunc");
                builder.CreateRet(retTrunc);
            }
            else
            {
                builder.CreateRet(retCast);
            }
        }
        else
        {
            throw std::runtime_error("Unsupported return type");
        }

        // Prevent the import stub from being inlined
        function->addFnAttr(Attribute::NoInline);
    }

    resolveBuilder.CreateRetVoid();
}

static void ProcessModule(Module& module, const ImportMap& importmap)
{
    Triple triple(module.getTargetTriple());
    if (triple.getArch() != Triple::x86_64)
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

    std::vector<Function*> importedFunctions;
    for (Function& function : module.functions())
    {
        // Remove x86-specific function attributes
        function.removeFnAttr("target-cpu");
        function.removeFnAttr("target-features");
        function.removeFnAttr("tune-cpu");
        function.removeFnAttr("stack-protector-buffer-size");

        // Collect imported functions
        auto name = function.getName();
        if (function.hasDLLImportStorageClass() && !name.startswith("riscvm_"))
        {
            importedFunctions.push_back(&function);
        }
        else if (function.isDeclaration() && importmap.count(name.str()) != 0)
        {
            importedFunctions.push_back(&function);
        }
        else
        {
            function.setDLLStorageClass(GlobalValue::DefaultStorageClass);
        }

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
                else if (isa<InvokeInst>(&instruction))
                {
                    throw std::runtime_error("C++ exceptions are not supported!");
                }
            }
        }
    }

    HandleImports(module, importedFunctions, importmap);

    // NOTE: enable if encountered
#if 0
    auto imageBase = module.getGlobalVariable("__ImageBase");
    if (imageBase != nullptr)
    {
        for (const Use& use : imageBase->uses())
        {
            auto user = use.getUser();
            if (auto op = dyn_cast<ConcreteOperator<Operator, Instruction::PtrToInt>>(user))
            {
                user->replaceAllUsesWith(llvm::ConstantInt::get(user->getType(), 0x8000000));
            }
            else
            {
                llvm::outs() << "UNSUPPORTED: " << *user << "\n";
                throw std::runtime_error("Unsupported user of __ImageBase");
            }
        }
    }
#endif

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
        const Comdat& comdat = comdatTable.at(name);
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

    // Load import map
    ImportMap importmap;
    if (!g_importmap.empty())
    {
        std::ifstream file(g_importmap);
        if (!file.is_open())
        {
            outs() << "Failed to open import map: " << g_importmap << "\n";
            return EXIT_FAILURE;
        }

        std::string line;
        while (std::getline(file, line))
        {
            auto colonIdx = line.find(':');
            if (colonIdx == line.npos || colonIdx + 1 == line.size())
            {
                continue;
            }

            auto name = line.substr(0, colonIdx);
            auto dll  = line.substr(colonIdx + 1);
            if (importmap.count(name) != 0)
            {
                outs() << "[WARNING] Duplicate import " << name << "\n";
            }
            else
            {
                importmap[name] = dll;
            }
        }
    }

    // Process module
    try
    {
        ProcessModule(*module, importmap);
        if (verifyModule(*module, &outs()))
        {
            return EXIT_FAILURE;
        }
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
