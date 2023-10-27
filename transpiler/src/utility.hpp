#pragma once

#include <cstdlib>
#include <memory>
#include <filesystem>

#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/FormattedStream.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/ToolOutputFile.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Bitcode/BitcodeWriter.h>

inline std::unique_ptr<llvm::Module> LoadModule(llvm::LLVMContext& Context, const std::string& Filename)
{
    llvm::SMDiagnostic Err;
    auto               M = llvm::parseIRFile(Filename, Err, Context);
    if (!M)
    {
        llvm::errs() << "Failed to parse IR: " << Err.getMessage() << "\n";
        llvm::errs().flush();
        std::exit(EXIT_FAILURE);
    }
    return M;
}

inline void SaveModule(llvm::Module* Module, const std::string& Filename)
{
    if (Filename.ends_with(".ll") || Filename.ends_with(".txt"))
    {
        std::error_code      EC;
        llvm::raw_fd_ostream RFO(Filename, EC);
        Module->print(RFO, nullptr, true, true);
    }
    else if (Filename.ends_with(".bc"))
    {
        std::error_code      EC;
        llvm::ToolOutputFile Out(Filename, EC, llvm::sys::fs::OF_None);
        WriteBitcodeToFile(*Module, Out.os(), true);
        if (EC)
        {
            llvm::errs() << "Failed to write IR: " << EC.message() << "\n";
            llvm::errs().flush();
            std::exit(EXIT_FAILURE);
        }
        Out.keep();
    }
    else
    {
        llvm::errs() << "Unsupported output extension for filename '" << Filename << "'\n";
        llvm::errs().flush();
        std::exit(EXIT_FAILURE);
    }
}
