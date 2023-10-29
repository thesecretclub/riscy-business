import json
import random

def generate_obfuscated_enum(enum_name, obfuscated_opcodes, names, header_code, prefix=""):
    enum_prefix = prefix
    # if prefix empty use enum name lowercased
    if not prefix:
        enum_prefix = enum_name.lower()
    header_code += f"enum {enum_name}\n"
    header_code += "{\n"
    for original, obfuscated in obfuscated_opcodes.items():
        header_code += f"    {enum_prefix}_{names[original]} = 0b{int(obfuscated):05b}, // original 0b{original:05b}\n"
    header_code += f"    {enum_prefix}_invalid = 0b11111, // placeholder\n"
    header_code += "};\n"
    header_code += "\n"
    return header_code

def generate_original_enum(enum_name, opcodes, header_code, prefix=""):
    enum_prefix = prefix
    # if prefix empty use enum name lowercased
    if not prefix:
        enum_prefix = enum_name.lower()
    header_code += f"enum {enum_name}\n"
    header_code += "{\n"
    for opcode, name in opcodes.items():
        if name == "invalid":
            continue
        header_code += f"    {enum_prefix}_{name} = 0b{int(opcode):05b},\n"
    header_code += "};\n"
    header_code += "\n"
    return header_code

def obfuscate_opcodes(opcodes):
    opcode_names = {int(k): v for k, v in opcodes.items()}
    # Obtain all the non-invalid opcodes and randomize them
    opcode_array = [opcode for opcode, name in opcode_names.items() if name != "invalid"]
    random.shuffle(opcode_array)
    # Create a mapping from original opcode to obfuscated opcode
    obfuscated_opcodes = {}
    for obfuscated, original in enumerate(opcode_array):
        obfuscated_opcodes[original] = obfuscated
    return obfuscated_opcodes, opcode_names

def main():
    with open("opcodes.json", "rb") as f:
        opcodes_dict = json.loads(f.read().decode("utf-8"))
        
    obfuscated_opcodes, names_opcodes = obfuscate_opcodes(opcodes_dict["rv64_opcodes"])
    obfuscated_op64, names_op64 = obfuscate_opcodes(opcodes_dict["rv64_op64"])
    obfuscated_op32, names_op32 = obfuscate_opcodes(opcodes_dict["rv64_op32"])
    obfuscated_imm64, names_imm64 = obfuscate_opcodes(opcodes_dict["rv64_imm64"])
    obfuscated_imm32, names_imm32 = obfuscate_opcodes(opcodes_dict["rv64_imm32"])
    obfuscated_load, names_load = obfuscate_opcodes(opcodes_dict["rv64_load"])
    obfuscated_store, names_store = obfuscate_opcodes(opcodes_dict["rv64_store"])
    obfuscated_branch, names_branch = obfuscate_opcodes(opcodes_dict["rv64_branch"])

    # Generate the shuffled header file
    shuffle_header_code = "#pragma once\n\n"
    shuffle_header_code += "#include <stdint.h>\n\n"
    shuffle_header_code = generate_obfuscated_enum("RV64_Opcode", obfuscated_opcodes, names_opcodes, shuffle_header_code, "rv64")
    shuffle_header_code = generate_obfuscated_enum("RV64_Op64", obfuscated_op64, names_op64, shuffle_header_code)
    shuffle_header_code = generate_obfuscated_enum("RV64_Op32", obfuscated_op32, names_op32, shuffle_header_code)
    shuffle_header_code = generate_obfuscated_enum("RV64_Imm64", obfuscated_imm64, names_imm64, shuffle_header_code)
    shuffle_header_code = generate_obfuscated_enum("RV64_Imm32", obfuscated_imm32, names_imm32, shuffle_header_code)
    shuffle_header_code = generate_obfuscated_enum("RV64_Load", obfuscated_load, names_load, shuffle_header_code)
    shuffle_header_code = generate_obfuscated_enum("RV64_Store", obfuscated_store, names_store, shuffle_header_code)
    shuffle_header_code = generate_obfuscated_enum("RV64_Branch", obfuscated_branch, names_branch, shuffle_header_code)
    
    # Generate the original header file
    original_header_code = "#pragma once\n\n"
    original_header_code += "#include <stdint.h>\n\n"
    original_header_code = generate_original_enum("RV64_Opcode", opcodes_dict["rv64_opcodes"], original_header_code, "rv64")
    original_header_code = generate_original_enum("RV64_Op64", opcodes_dict["rv64_op64"], original_header_code)
    original_header_code = generate_original_enum("RV64_Op32", opcodes_dict["rv64_op32"], original_header_code)
    original_header_code = generate_original_enum("RV64_Imm64", opcodes_dict["rv64_imm64"], original_header_code)
    original_header_code = generate_original_enum("RV64_Imm32", opcodes_dict["rv64_imm32"], original_header_code)
    original_header_code = generate_original_enum("RV64_Load", opcodes_dict["rv64_load"], original_header_code)
    original_header_code = generate_original_enum("RV64_Store", opcodes_dict["rv64_store"], original_header_code)
    original_header_code = generate_original_enum("RV64_Branch", opcodes_dict["rv64_branch"], original_header_code)

    # Generate the shuffled header file
    with open("shuffled_opcodes.h", "wb") as f:
        f.write(shuffle_header_code.encode("utf-8"))

    
    with open("opcodes.h", "wb") as f:
        f.write(original_header_code.encode("utf-8"))
        

    obfuscated_dict = {
        "rv64_opcodes": obfuscated_opcodes,
        "rv64_op64": obfuscated_op64,
        "rv64_op32": obfuscated_op32,
        "rv64_imm64": obfuscated_imm64,
        "rv64_imm32": obfuscated_imm32,
        "rv64_load": obfuscated_load,
        "rv64_store": obfuscated_store,
        "rv64_branch": obfuscated_branch,
    }

    # Generate the JSON file
    with open("shuffled_opcodes.json", "wb") as f:
        f.write(json.dumps(obfuscated_dict).encode("utf-8"))

if __name__ == "__main__":
    main()
