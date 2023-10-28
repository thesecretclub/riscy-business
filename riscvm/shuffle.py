import json
import random

opcodes = {
    0:  "load",
    1:  "invalid",
    2:  "invalid",
    3:  "fence",
    4:  "imm64",
    5:  "auipc",
    6:  "imm32",
    7:  "invalid",
    8:  "store",
    9:  "invalid",
    10: "invalid",
    11: "invalid",
    12: "op64",
    13: "lui",
    14: "op32",
    15: "invalid",
    16: "invalid",
    17: "invalid",
    18: "invalid",
    19: "invalid",
    20: "invalid",
    21: "invalid",
    22: "invalid",
    23: "invalid",
    24: "branch",
    25: "jalr",
    26: "invalid",
    27: "jal",
    28: "system",
    29: "invalid",
    30: "invalid",
    31: "invalid"
}

def main():
    # Obtain all the non-invalid opcodes and randomize them
    opcode_array = [opcode for opcode, name in opcodes.items() if name != "invalid"]
    random.shuffle(opcode_array)

    # Create a mapping from original opcode to obfuscated opcode
    obfuscated_opcodes = {}
    for obfuscated, original in enumerate(opcode_array):
        obfuscated_opcodes[original] = obfuscated

    # Generate the header file
    header_code = "#pragma once\n\n"
    header_code += "#include <stdint.h>\n\n"
    header_code += "enum Opcode\n"
    header_code += "{\n"
    for original, obfuscated in obfuscated_opcodes.items():
        header_code += f"    rv64_{opcodes[original]} = 0b{obfuscated:05b}, // original: 0b{original:05b}\n"
    header_code += f"    rv64_invalid = 0b11111, // placeholder\n"
    header_code += "};\n"
    header_code += "\n"
    header_code += "static uint8_t riscvm_original_opcode(uint8_t insn)\n"
    header_code += "{\n"
    header_code += "    switch (insn)\n"
    header_code += "    {\n"
    for value, name in opcodes.items():
        if name == "invalid":
            continue
        header_code += f"    case rv64_{name}: return 0b{value:05b};\n"
    header_code += "    default: return rv64_invalid;\n"
    header_code += "    }\n"
    header_code += "}\n"

    # Generate the header file
    with open("shuffled_opcodes.h", "wb") as f:
        f.write(header_code.encode("utf-8"))

    # Generate the JSON file
    with open("shuffled_opcodes.json", "wb") as f:
        f.write(json.dumps(obfuscated_opcodes).encode("utf-8"))

if __name__ == "__main__":
    main()
