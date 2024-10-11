#include <gtest/gtest.h>

#include <obfuscator/context.hpp>

using namespace zasm;
using namespace obfuscator;

TEST(Context, regMask)
{
    using namespace zasm::x86;
    EXPECT_EQ(regMask(rip), 0);
    EXPECT_EQ(regMask(rflags), 0);
    EXPECT_EQ(regMask(rax), regMask(eax));
    EXPECT_EQ(regMask(rax), regMask(ax));
    EXPECT_EQ(regMask(rax), regMask(al));
    EXPECT_EQ(maskToRegs(0), (std::vector<Gp>{}));
    EXPECT_NE(regMask(rdx), regMask(rbp));
    auto mask = regMask(rax) | regMask(rbx);
    auto regs = maskToRegs(mask);
    EXPECT_TRUE(regs.size() == 2);
    EXPECT_EQ(regs, (std::vector<Gp>{rax, rbx}));
    auto format = formatRegsMask(mask);
    EXPECT_EQ(format, "(RAX RBX)");
}
