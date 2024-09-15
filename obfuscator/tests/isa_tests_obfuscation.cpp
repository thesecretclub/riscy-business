#include <obfuscator.hpp>
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <Windows.h>
#include "syscall_handler.hpp"
#include "test_config.hpp"

namespace vm
{
#define CUSTOM_SYSCALLS
#include <riscvm.h>
#include <riscvm-code.h>
} // namespace vm

#include <isa-tests/data.h>

typedef void (*riscvm_run_t)(vm::riscvm*);

class WithObfuscation : public ::testing::TestWithParam<Test>
{
  protected:
    static ObfuscatorLib::Obfuscator obfuscator;
    static std::string               functionName;
    static std::vector<uint8_t>      code;
    static void*                     execMemory;
    static riscvm_run_t              riscvmRun;

    // SetUpTestSuite runs once before all tests in the suite
    static void SetUpTestSuite()
    {
        functionName = "riscvm_run";

        ASSERT_TRUE(obfuscator.loadPEFile(TestConfig::inputFilePath, functionName, TestConfig::verbose))
            << "Failed to load PE file";
        ASSERT_TRUE(obfuscator.disassembleFunction(functionName, TestConfig::verbose))
            << "Failed to disassemble function";
        ASSERT_TRUE(obfuscator.analyzeFunction(TestConfig::verbose)) << "Failed to analyze function";
        ASSERT_TRUE(obfuscator.obfuscateFunction(TestConfig::verbose)) << "Failed to obfuscate function";
        ASSERT_TRUE(obfuscator.serialize(code, TestConfig::verbose))
            << "Failed to serialize obfuscated function";

        execMemory = VirtualAlloc(nullptr, code.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        ASSERT_NE(execMemory, nullptr) << "Failed to allocate executable memory";

        memcpy(execMemory, code.data(), code.size());

        riscvmRun = reinterpret_cast<riscvm_run_t>(execMemory);
        ASSERT_NE(riscvmRun, nullptr) << "Failed to get function address";
    }

    // TearDownTestSuite runs once after all tests in the suite
    static void TearDownTestSuite()
    {
        if (execMemory)
        {
            VirtualFree(execMemory, 0, MEM_RELEASE);
            execMemory = nullptr;
            riscvmRun  = nullptr;
        }
    }

    // Disable per-test SetUp and TearDown
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

ObfuscatorLib::Obfuscator WithObfuscation::obfuscator;
std::string               WithObfuscation::functionName;
std::vector<uint8_t>      WithObfuscation::code;
void*                     WithObfuscation::execMemory = nullptr;
riscvm_run_t              WithObfuscation::riscvmRun  = nullptr;

TEST_P(WithObfuscation, RunIsaTestCase)
{
    using namespace vm;

    // Get the test case
    const auto& test = GetParam();

    // Check the test size is not too large
    ASSERT_TRUE(test.size <= sizeof(vm::g_code)) << "Test size is too large";

    // Copy the test case to the global code buffer
    memset(g_code, 0, sizeof(g_code));
    memcpy(g_code, test.data, test.size);

    // Create the VM instance
    vm::riscvm vm_instance     = {};
    vm_instance.handle_syscall = riscvm_handle_syscall;
    auto* self                 = &vm_instance;

    // Set the stack pointer
    reg_write(reg_sp, (uint64_t)&g_stack[sizeof(g_stack) - 0x10]);
    EXPECT_EQ(reg_read(reg_sp), (uint64_t)&g_stack[sizeof(g_stack) - 0x10]);

    // Set the program counter
    self->pc = (int64_t)g_code + test.offset;

    // Run the test case
    riscvmRun(self);

    // Check the return status
    auto status = (int)reg_read(reg_a0);
    EXPECT_EQ(status, 0) << "Test " << test.name << " failed with status " << status;

    // Clear the global code buffer
    memset(g_code, 0, sizeof(g_code));
}

INSTANTIATE_TEST_SUITE_P(
    IsaTests,
    WithObfuscation,
    ::testing::ValuesIn(tests),
    [](const ::testing::TestParamInfo<WithObfuscation::ParamType>& info)
    {
        return info.param.name;
    }
);
