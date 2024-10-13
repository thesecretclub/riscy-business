#include <obfuscator/disassemble.hpp>
#include <obfuscator/msvc-secure.hpp>

#include <zasm/formatter/formatter.hpp>
#include <fmt/format.h>

#include <map>

namespace obfuscator
{

using namespace zasm;

bool disassemble(Context& ctx, const uint64_t functionStart, const std::vector<uint8_t>& code, bool verbose)
{
    Program& program = ctx.program;
    auto     mode    = program.getMode();

    if (verbose)
        fmt::println("=== DISASSEMBLE ===");
    zasm::Decoder  decoder(mode);
    x86::Assembler assembler(program);

    auto entryLabel = assembler.createLabel("riscvm_run");
    assembler.bind(entryLabel);
    ctx.addInstructionData(assembler.getCursor(), functionStart, mode, {});
    program.setEntryPoint(entryLabel);

    std::map<uint64_t, Node*> nodes;
    std::map<uint64_t, Label> labels;

    size_t offset = 0;
    while (offset < code.size())
    {
        auto curAddress = functionStart + offset;
        auto decoderRes = decoder.decode(code.data() + offset, code.size() - offset, curAddress);
        if (!decoderRes)
        {
            fmt::println("Failed to decode at {:#x}, {}", curAddress, decoderRes.error().getErrorName());
            return false;
        }

        nodes.emplace(curAddress, assembler.getCursor());

        const auto& detail = *decoderRes;
        const auto  instr  = detail.getInstruction();
        auto        length = detail.getLength();
        offset += length;

        auto str = formatter::toString(&instr, formatter::Options::HexImmediates);
        if (verbose)
            fmt::println("{:#x}|{}", curAddress, str);

        auto emit = [&]
        {
            if (auto res = assembler.emit(instr); res != zasm::ErrorCode::None)
            {
                fmt::println("Failed to emit instruction {:#x}, {}", curAddress, res.getErrorName());
                return false;
            }
            ctx.addInstructionData(assembler.getCursor(), curAddress, mode, detail);
            return true;
        };

        auto createLabel = [&](uint64_t dest)
        {
            auto itr = labels.find(dest);
            if (itr == labels.end())
            {
                char name[64] = "";
                sprintf_s(name, "label_%llX", dest);
                auto label = assembler.createLabel(name);
                itr        = labels.emplace(dest, label).first;
            }
            return itr->second;
        };

        switch (detail.getCategory())
        {
        case x86::Category::UncondBR:
        {
            auto dest = detail.getOperand<Imm>(0).value<uint64_t>();
            if (verbose)
                fmt::println("UncondBR: {:#x}", dest);
            assembler.emit(detail.getMnemonic(), createLabel(dest));
            ctx.addInstructionData(assembler.getCursor(), curAddress, mode, detail);
        }
        break;

        case x86::Category::CondBr:
        {
            auto brtrue  = detail.getOperand<Imm>(0).value<uint64_t>();
            auto brfalse = offset + functionStart;
            createLabel(brfalse);
            if (verbose)
                fmt::println("CondBr: {:#x}, {:#x}", brtrue, brfalse);
            assembler.emit(detail.getMnemonic(), createLabel(brtrue));
            ctx.addInstructionData(assembler.getCursor(), curAddress, mode, detail);
        }
        break;

        case x86::Category::Call:
        {
            auto dest = detail.getOperand(0);
            if (dest.getIf<Imm>() != nullptr)
            {
                fmt::println("unsupported call imm {:#x}", curAddress);
                return false;
            }

            if (!emit())
            {
                return false;
            }
        }
        break;

        case x86::Category::Ret:
        {
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

    for (const auto& [address, label] : labels)
    {
        auto node = nodes.at(address);
        assembler.setCursor(node);
        assembler.bind(label);
        auto detail = *node->get<Instruction>().getDetail(mode);
        ctx.addInstructionData(assembler.getCursor(), address, mode, detail);
    }

    assembler.setCursor(program.getTail());
    assembler.bind(assembler.createLabel("end"));

    if (verbose)
    {
        fmt::println("\n{}", formatter::toString(program));
    }

    return true;
}

} // namespace obfuscator
