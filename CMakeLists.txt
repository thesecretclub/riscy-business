cmake_minimum_required(VERSION 3.10)

project(RISCVProject)

# Set the base path for LLVM tools
set(LLVM_BASE_PATH "C:/Program Files/LLVM/bin")

# Derive paths for individual tools from the base path
set(CLANG_PATH "${LLVM_BASE_PATH}/clang.exe")
set(CLANGXX_PATH "${LLVM_BASE_PATH}/clang++.exe")
set(LLD_PATH "${LLVM_BASE_PATH}/ld.lld.exe")
set(LLVM_OBJCOPY_PATH "${LLVM_BASE_PATH}/llvm-objcopy")

# Set the compiler and flags
set(CMAKE_C_COMPILER ${CLANG_PATH})
set(CMAKE_CXX_COMPILER ${CLANGXX_PATH})
set(CMAKE_C_FLAGS "-target riscv64 -march=rv64g -nostdlib -ffreestanding")
set(CMAKE_CXX_FLAGS "-target riscv64 -march=rv64g -fno-exceptions -nostdlib -ffreestanding")

function(remove_flags_from_list flag_list_name)
    set(flag_list "${${flag_list_name}}")
    string(REPLACE " " ";" flag_list_semi "${flag_list}")
    foreach(flag ${ARGN})
        list(REMOVE_ITEM flag_list_semi "${flag}")
    endforeach()
    string(REPLACE ";" " " flag_list_new "${flag_list_semi}")
    set(${flag_list_name} "${flag_list_new}" PARENT_SCOPE)
    message(STATUS "For ${flag_list_name}: Removed flags '${ARGN}' | Updated: '${flag_list_new}'")
endfunction()

remove_flags_from_list(CMAKE_CXX_FLAGS_MINSIZEREL "-Xclang;--dependent-lib=msvcrt")
remove_flags_from_list(CMAKE_C_FLAGS_MINSIZEREL "-Xclang;--dependent-lib=msvcrt")
remove_flags_from_list(CMAKE_CXX_FLAGS_RELEASE "-Xclang;--dependent-lib=msvcrt")
remove_flags_from_list(CMAKE_C_FLAGS_RELEASE "-Xclang;--dependent-lib=msvcrt")
remove_flags_from_list(CMAKE_CXX_FLAGS_DEBUG "-Xclang;--dependent-lib=msvcrtd")
remove_flags_from_list(CMAKE_C_FLAGS_DEBUG "-Xclang;--dependent-lib=msvcrtd")

# Define source files and capture object files' paths
set(SOURCE_FILES start.c main.c test.cpp test2.cpp)

foreach(SRC ${SOURCE_FILES})
    list(APPEND RISCV_OBJECTS_ABSOLUTE "${CMAKE_BINARY_DIR}/CMakeFiles/riscv.dir/${SRC}.obj")
endforeach()

add_library(riscv OBJECT ${SOURCE_FILES})

# Direct Linking using ld.lld
set(LINKER_SCRIPT ${CMAKE_SOURCE_DIR}/linker.ld)
add_custom_command(
    OUTPUT main.elf
    COMMAND ${LLD_PATH} -o main.elf -T ${LINKER_SCRIPT} --oformat=elf -emit-relocs -nostdlib --Map=main.map ${RISCV_OBJECTS_ABSOLUTE}
    DEPENDS riscv
    COMMENT "Linking using ld.lld"
)

add_custom_target(link_target ALL DEPENDS main.elf)

# Custom command for objcopy
add_custom_command(
    TARGET link_target POST_BUILD
    COMMAND ${LLVM_OBJCOPY_PATH} -O binary main.elf main.bin
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Converting ELF to binary"
)
