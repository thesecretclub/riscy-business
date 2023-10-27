import json
import re
import sys
import argparse
import struct
import random

op_table = {
    0:  "load",
    1:  "unimp",
    2:  "unimp",
    3:  "fence",
    4:  "imm64",
    5:  "auipc",
    6:  "imm32",
    7:  "unimp",
    8:  "store",
    9:  "unimp",
    10: "unimp",
    11: "unimp",
    12: "op64",
    13: "lui",
    14: "op32",
    15: "unimp",
    16: "unimp",
    17: "unimp",
    18: "unimp",
    19: "unimp",
    20: "unimp",
    21: "unimp",
    22: "unimp",
    23: "unimp",
    24: "branch",
    25: "jalr",
    26: "unimp",
    27: "jal",
    28: "system",
    29: "unimp",
    30: "unimp",
    31: "unimp"
}

def parse_map_file(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()

    # Skip the header line
    lines = lines[1:]

    sections = {}
    current_section = None

    # Regular expression to detect section and its symbols.
    section_pattern = re.compile(r'^\s*([0-9a-fA-F]+)?\s+([0-9a-fA-F]+)?\s+([0-9a-fA-F]+)?\s+([0-9a-fA-F]+)?\s+(\.[a-z0-9_.]+)$')
    symbol_pattern = re.compile(r'^\s*([0-9a-fA-F]+)?\s+([0-9a-fA-F]+)?\s+([0-9a-fA-F]+)?\s+([0-9a-fA-F]+)?\s+(.*?)$')

    for line in lines:
        section_match = section_pattern.match(line)
        symbol_match = symbol_pattern.match(line)

        if section_match:
            vma, lma, size, align, section_name = section_match.groups()
            current_section = {
                'vma': vma,
                'lma': lma,
                'size': size,
                'align': align,
                'symbols': []
            }
            sections[section_name] = current_section
        elif symbol_match and current_section is not None:
            vma, lma, size, align, symbol = symbol_match.groups()
            current_section['symbols'].append({
                'vma': vma,
                'lma': lma,
                'size': size,
                'align': align,
                'symbol': symbol.strip()
            })

    return sections

def get_link_base(sections):
    for section_name, section_data in sections.items():
        for symbol in section_data['symbols']:
            if symbol['symbol'] == ". = LINK_BASE":
                return int(symbol['vma'], 16)
    return None

def get_functions(sections, link_base):
    functions = []
    for section_name, section_data in sections.items():
        if section_name == ".text":
            for symbol in section_data['symbols']:
                # Only valid functions
                if symbol['align'] == '1' and symbol['size'] != '0':
                    functions.append({
                        'symbol': symbol['symbol'],
                        'size': int(symbol['size'], 16),
                        'address': int(symbol['vma'], 16) - link_base,
                        'vma': int(symbol['vma'], 16),
                    })
    return functions

def djb2_hash(data: bytes) -> int:
    hash_val = 5381
    for byte in data:
        hash_val = ((hash_val << 5) + hash_val) + byte
    return hash_val & 0xFFFFFFFF

def transform(offset: int, key: int) -> int:
    key2 = key + offset
    return djb2_hash(struct.pack("<I", key2))

def replace_opcode(instruction, shuffled):
    # Extract the opcode from the instruction
    original_opcode = (instruction >> 2) & 0b11111
    # Get the new opcode from the shuffled_dict
    new_opcode = shuffled[original_opcode]
    # Clear out the original opcode from the instruction
    instruction &= ~(0b11111 << 2)
    # Insert the new opcode
    instruction |= (new_opcode << 2)
    return instruction

def encrypt_function(encrypt: bool, data: bytearray, function: dict, key: int, shuffled: dict = None):
    """Encrypts the provided function in place based on the function address and key."""
    print(f"Encrypting function {function['symbol']} at {hex(function['vma'])} with size {hex(function['size'])}")
    for i in range(0, function['size'], 4):
        offset = function['address'] + i
        dword, = struct.unpack("<I", data[offset:offset+4])

        if shuffled is not None:
            # Shuffle the operands
            dword = replace_opcode(dword, shuffled)
        if encrypt:
            dword = dword ^ transform(offset, key)
        data[offset:offset+4] = struct.pack("<I", dword)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="Input RISC-V binary")
    parser.add_argument("--shuffle", "-s", help="Shuffle the operands", action="store_true")
    parser.add_argument("--encrypt", "-e", help="Encrypt Binary", action="store_true")
    parser.add_argument("--map", "-m", help="Input map file")
    parser.add_argument("--output", "-b", help="Output binary file")
    parser.add_argument("--key", "-k", help="Encryption key (hex, int)", default="0xDEADBEEF")
    parser.add_argument("--shuffle-map", "-sm", help="Shuffle map file")

    args = parser.parse_args()
    input: str = args.input
    map_file: str = args.map
    output: str = args.output
    shuffle_json: str = args.shuffle_map
    shuffle: bool = args.shuffle
    encrypt: bool = args.encrypt

    try:
        key = int(args.key, 0)
    except:
        print("Invalid key specified, must be a hex or int value")
        sys.exit(1)

    if key < 0 or key > 0xFFFFFFFF:
        print("Invalid key specified, must be a 32-bit value")
        sys.exit(1)

    sections = parse_map_file(map_file)
    if len(sections) == 0:
        print("Could not find any sections in map file")
        sys.exit(1)

    link_base = get_link_base(sections)
    if link_base is None:
        print("Could not find link base in map file")
        sys.exit(1)

    functions = get_functions(sections, link_base)
    if len(functions) == 0:
        print("Could not find any functions in map file")
        sys.exit(1)

    binary = bytearray()
    with open(input, "rb") as f:
        binary = bytearray(f.read())

    shuffle_map = None
    if shuffle:
        with open(shuffle_json, "r") as f:
            shuffle_map = json.load(f)
            shuffle_map = {int(k): int(v) for k, v in shuffle_map.items()}

    print(shuffle_map)

    # Encrypt the functions
    for function in functions:
        encrypt_function(encrypt, binary, function, key, shuffle_map)

    # Write the encrypted binary
    with open(output, "wb") as f:
        f.write(binary)

if __name__ == "__main__":
    main()
