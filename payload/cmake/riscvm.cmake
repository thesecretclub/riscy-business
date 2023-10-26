set(EMBED_TYPE "post-merge-pre-opt") # post-merge-pre-opt/optimized
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "clang-cl is required, use -T ClangCL --fresh")
elseif(CMAKE_CXX_COMPILER_FRONTEND_VARIANT MATCHES "^MSVC$")
    # clang-cl
    add_compile_options(-flto)
    add_link_options(/mllvm:-lto-embed-bitcode=${EMBED_TYPE})
else()
    # clang
    add_compile_options(-fuse-ld=lld-link -flto)
    add_link_options(-Wl,/mllvm:-lto-embed-bitcode=${EMBED_TYPE})
    # NOTE: none of these are working
    #add_link_options(-mllvm -lto-embed-bitcode=${EMBED_TYPE})
    #add_link_options(--plugin-opt=-lto-embed-bitcode=${EMBED_TYPE})
    #add_compile_options(-Wl,-mllvm,-lto-embed-bitcode=${EMBED_TYPE})
    #add_compile_options(-Wl,--plugin-opt=-lto-embed-bitcode=${EMBED_TYPE})
endif()

# Some common annoying warnings when including Windows.h
add_compile_options(-Wno-pragma-pack -Wno-microsoft-enum-forward-reference)

set(SCRIPT_DIR "${CMAKE_CURRENT_LIST_DIR}/../..")

# TODO: only create venv if it doesn't exist

# Find system python
find_package(Python3 COMPONENTS Interpreter REQUIRED)
message(STATUS "Creating venv...")
set(VENV_DIR "${CMAKE_CURRENT_BINARY_DIR}/venv")
execute_process(
    COMMAND "${Python3_EXECUTABLE}" -m venv "${VENV_DIR}"
    ECHO_OUTPUT_VARIABLE
    ECHO_ERROR_VARIABLE
    COMMAND_ERROR_IS_FATAL ANY
)

# Switch to venv (https://discourse.cmake.org/t/possible-to-create-a-python-virtual-env-from-cmake-and-then-find-it-with-findpython3/1132/2)
set(ENV{VIRTUAL_ENV} "${VENV_DIR}")
set(Python3_FIND_VIRTUALENV FIRST)
unset(Python3_EXECUTABLE)
find_package(Python3 COMPONENTS Interpreter REQUIRED)

message(STATUS "Installing dependencies...")
execute_process(
    COMMAND "${Python3_EXECUTABLE}" -m pip install -r "${SCRIPT_DIR}/requirements.txt" --disable-pip-version-check
    ECHO_OUTPUT_VARIABLE
    ECHO_ERROR_VARIABLE
    COMMAND_ERROR_IS_FATAL ANY
)

function(add_riscvm_executable tgt)
    add_executable(${tgt} ${ARGN})
    add_custom_command(TARGET ${tgt}
        POST_BUILD
        COMMENT "Extracting bitcode..."
        COMMAND "${Python3_EXECUTABLE}" "${SCRIPT_DIR}/extract-bc.py" "$<TARGET_FILE:${tgt}>" -o "$<TARGET_FILE_DIR:${tgt}>/$<TARGET_FILE_BASE_NAME:${tgt}>.bc"
        VERBATIM
    )
endfunction()