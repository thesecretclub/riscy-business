#include "disassembler.hpp"
#include "logger.hpp"
#include <map>
#include <zasm/formatter/formatter.hpp>

namespace ObfuscatorLib
{

using namespace zasm;
using namespace zasm::x86;

Disassembler::Disassembler(Program& program, Context& context) : program_(program), ctx_(context)
{
}

bool Disassembler::disassemble(
    const std::string& functionName, uint64_t address, const std::vector<uint8_t>& code, bool verbose
)
{
    auto mode = program_.getMode();

    Decoder   decoder(mode);
    Assembler assembler(program_);

    auto entryLabel = assembler.createLabel(functionName.c_str());
    assembler.bind(entryLabel);
    ctx_.addInstructionData(assembler.getCursor(), address, {});
    program_.setEntryPoint(entryLabel);

    std::map<uint64_t, Node*> nodes;
    std::map<uint64_t, Label> labels;

    size_t offset = 0;
    while (offset < code.size())
    {
        auto curAddress = address + offset;
        auto decoderRes = decoder.decode(code.data() + offset, code.size() - offset, curAddress);
        if (!decoderRes)
        {
            Logger::logError("Failed to decode at 0x%llX, %s", curAddress, decoderRes.error().getErrorName());
            return false;
        }

        nodes.emplace(curAddress, assembler.getCursor());

        const auto& detail = *decoderRes;
        const auto  instr  = detail.getInstruction();

        offset += detail.getLength();

        if (verbose)
        {
            auto str = formatter::toString(&instr, formatter::Options::HexImmediates);
            Logger::logLine("0x%llX | %s", curAddress, str.c_str());
        }

        auto emit = [&]
        {
            if (auto res = assembler.emit(instr); res != ErrorCode::None)
            {
                Logger::logError("Failed to emit instruction at 0x%llX, %s", curAddress, res.getErrorName());
                return false;
            }
            ctx_.addInstructionData(assembler.getCursor(), curAddress, detail);
            return true;
        };

        auto createLabel = [&](uint64_t targetAddress)
        {
            auto it = labels.find(targetAddress);
            if (it == labels.end())
            {
                char labelName[64] = "";
                sprintf(labelName, "label_%llX", targetAddress);
                auto label = assembler.createLabel(labelName);
                it         = labels.emplace(targetAddress, label).first;
            }
            return it->second;
        };

        switch (detail.getCategory())
        {
        case Category::UncondBR:
        {
            auto dest = detail.getOperand<Imm>(0).value<uint64_t>();
            assembler.emit(detail.getMnemonic(), createLabel(dest));
            ctx_.addInstructionData(assembler.getCursor(), curAddress, detail);

            if (verbose)
            {
                Logger::logLine("UncondBR: 0x%llX", dest);
            }
        }
        break;

        case Category::CondBr:
        {
            auto brtrue  = detail.getOperand<Imm>(0).value<uint64_t>();
            auto brfalse = offset + address;
            createLabel(brfalse);
            assembler.emit(detail.getMnemonic(), createLabel(brtrue));
            ctx_.addInstructionData(assembler.getCursor(), curAddress, detail);

            if (verbose)
            {
                Logger::logLine("CondBr: 0x%llX, 0x%llX", brtrue, brfalse);
            }
        }
        break;

        case Category::Call:
        {
            auto dest = detail.getOperand(0);
            if (dest.getIf<Imm>() != nullptr)
            {
                Logger::logError("Unsupported immediate call at 0x%llX", curAddress);
                return false;
            }

            if (!emit())
            {
                return false;
            }
        }
        break;

        default:
        {
            if (!emit())
            {
                return false;
            }
        }
        break;
        }
    }

    for (const auto& [addresss, label] : labels)
    {
        auto node = nodes.at(addresss);
        assembler.setCursor(node);
        assembler.bind(label);
        auto detail = *node->get<Instruction>().getDetail(mode);
        ctx_.addInstructionData(assembler.getCursor(), addresss, detail);
    }

    assembler.setCursor(program_.getTail());
    assembler.bind(assembler.createLabel("end"));

    if (verbose)
    {
        auto str = formatter::toString(program_);
        Logger::logLine("%s", str.c_str());
    }

    return true;
}

} // namespace ObfuscatorLib
