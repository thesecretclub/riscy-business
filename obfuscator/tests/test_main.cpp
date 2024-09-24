#include <gtest/gtest.h>
#include "test_config.hpp"

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    
    // Parse command line arguments
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];

        if (arg == "--verbose")
        {
            TestConfig::verbose = true;
        }
        else if (arg == "--input")
        {
            if (i + 1 < argc)
            {
                TestConfig::inputFilePath = argv[i + 1];
                i++;
            }
            else
            {
                std::cerr << "Missing argument for --input" << std::endl;
                return EXIT_FAILURE;
            }
        }
    }

    if (TestConfig::inputFilePath.empty())
    {
        std::cerr << "Missing input file path for the riscv-vm" << std::endl;
        std::cerr << "Usage: " << argv[0] << " --input <input_file> [--verbose]" << std::endl;
        return EXIT_FAILURE;
    }

    return RUN_ALL_TESTS();
}
