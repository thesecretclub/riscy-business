#include "context.hpp"
#include "util.hpp"

namespace ObfuscatorLib
{

using namespace zasm;

Context::Context(Program& program) : program_(program)
{
}

void Context::addInstructionData(Node* node, uintptr_t address, const InstructionDetail& detail)
{
    auto data = node->getUserData<InstructionData>();
    if (data != nullptr)
        return;

    instructionDataPool_.emplace_back();
    data          = &instructionDataPool_.back();
    data->address = address;
    data->detail  = detail;

    data->regsRead      = 0;
    data->regsWritten   = 0;
    data->flagsModified = 0;
    data->flagsTested   = 0;

    auto mode = program_.getMode();

    auto operandCount = detail.getOperandCount();
    for (size_t i = 0; i < operandCount; i++)
    {
        const auto& operand = detail.getOperand(i);
        auto        access  = detail.getOperandAccess(i);

        if (auto reg = operand.getIf<Reg>())
        {
            auto rootReg = reg->getRoot(mode);

            if ((access & Operand::Access::MaskRead) != Operand::Access::None)
                data->regsRead |= regMask(rootReg);

            if ((access & Operand::Access::MaskWrite) != Operand::Access::None)
            {
                // mov al, 66 does not kill rax
                if (rootReg.isGp32() || rootReg.isGp64())
                    data->regsWritten |= regMask(rootReg);
            }
        }
        else if (auto mem = operand.getIf<Mem>())
        {
            if (auto baseReg = mem->getBase(); baseReg.isValid())
                data->regsRead |= regMask(baseReg.getRoot(mode));

            if (auto indexReg = mem->getIndex(); indexReg.isValid())
                data->regsRead |= regMask(indexReg.getRoot(mode));

            if (auto segmentReg = mem->getSegment(); segmentReg.isValid())
                data->regsRead |= regMask(segmentReg.getRoot(mode));
        }
    }

    const auto& flags = detail.getCPUFlags();
    data->flagsModified |= uint32_t(flags.set0 | flags.set1 | flags.modified | flags.undefined);
    data->flagsTested |= uint32_t(flags.tested);

    switch (detail.getCategory())
    {
    case x86::Category::Call:
    {
        const uint32_t volatileRegs = regMask(x86::rax) | regMask(x86::rcx) | regMask(x86::rdx)
                                    | regMask(x86::r8) | regMask(x86::r9) | regMask(x86::r10)
                                    | regMask(x86::r11);

        const uint32_t argRegsMask = regMask(x86::rcx) | regMask(x86::rdx) | regMask(x86::r8) | regMask(x86::r9);

        // The call instruction clobbers all volatile registers
        data->regsWritten = volatileRegs;
        // The call instruction reads the first 4 arguments from rcx, rdx, r8, r9 (and rsp because mishap said so)
        data->regsRead = argRegsMask | regMask(x86::rsp);
    }
    break;

    case x86::Category::Ret:
    {

        const uint32_t nonVolatileRegsMask = regMask(x86::rbx) | regMask(x86::rbp) | regMask(x86::rsi)
                                           | regMask(x86::rdi) | regMask(x86::r12) | regMask(x86::r13)
                                           | regMask(x86::r14) | regMask(x86::r15);

        // The ret instruction 'reads' all nonvolatile registers and the return value
        data->regsRead = nonVolatileRegsMask | regMask(x86::rsp) | regMask(x86::rax);
    }
    break;

    default:
        break;
    }

    node->setUserData(data);
};

} // namespace ObfuscatorLib
