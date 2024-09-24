#include "analyzer.hpp"
#include "logger.hpp"

namespace ObfuscatorLib
{

using namespace zasm;

Analyzer::Analyzer(Program& program, CFG& cfg) : program_(program), cfg_(cfg)
{
}

bool Analyzer::analyze(bool verbose)
{
    auto entryLabel = program_.getEntryPoint();
    if(!cfg_.create(program_, entryLabel))
    {
        Logger::logError("Failed to create CFG.");
        return false;
    }

    cfg_.computeLiveness();

    if(verbose)
    {
        cfg_.printResults(program_);
        cfg_.printDot(program_);
    }

    return true;
}

CFG& Analyzer::getCFG()
{
    return cfg_;
}

} // namespace ObfuscatorLib
