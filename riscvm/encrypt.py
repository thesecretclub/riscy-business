import json
import re
import sys
import argparse
import struct

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
    symbols = sections.get(".text", {}).get('symbols', [])
    return [{
        'symbol': s['symbol'],
        'size': int(s['size'], 16),
        'address': int(s['vma'], 16) - link_base,
        'vma': int(s['vma'], 16),
    } for s in symbols if s['align'] == '1' and s['size'] != '0']

def tetra_twist(data: bytes) -> int:
    """
    Custom hash function that is used to generate the encryption key.
    This has strong avalanche properties and is used to ensure that
    small changes to the input result in large changes to the output.
    """

    assert len(data) == 4, "Input should be 4 bytes"

    input_val = int.from_bytes(data, 'little')  # Convert bytes to an integer
    prime1 = 0x9E3779B1

    input_val ^= input_val >> 15
    input_val *= prime1
    input_val &= 0xFFFFFFFF
    input_val ^= input_val >> 12
    input_val *= prime1
    input_val &= 0xFFFFFFFF
    input_val ^= input_val >> 4
    input_val *= prime1
    input_val &= 0xFFFFFFFF
    input_val ^= input_val >> 16

    return input_val & 0xFFFFFFFF


def transform(offset: int, key: int) -> int:
    key2 = key + offset
    return tetra_twist(struct.pack("<I", key2))

def replace_opcode(instruction, shuffled):
    """Replaces the opcode in the instruction with the shuffled opcode"""
    original_opcode = (instruction >> 2) & 0b11111
    new_opcode = shuffled[original_opcode]
    instruction &= ~(0b11111 << 2)
    instruction |= (new_opcode << 2)
    return instruction

def replace_func3(instruction, shuffled):
    """Replaces the func3 in the instruction with the shuffled func3"""
    original_func3 = (instruction >> 12) & 0b111
    new_func3 = shuffled[original_func3]
    instruction &= ~(0b111 << 12)       # null func3
    instruction |= (new_func3 << 12)    # insert new func3
    return instruction

def replace_func3_func7(instruction, shuffled):
    """Replaces the func3 and func7 in the instruction with the shuffled func3 and func7"""
    # func3 is bits 12-14 and func7 is bits 25-31, combine them into a single value
    original_func3_func7 = ((instruction >> 12) & 0b111) | ((instruction >> 25) & 0b1111111) << 3
    new_func3_func7 = shuffled[original_func3_func7]
    instruction &= ~(0b111 << 12)                   # null func3
    instruction &= ~(0b1111111 << 25)               # null func7
    instruction |= (new_func3_func7 & 0b111) << 12  # insert new func3
    instruction |= (new_func3_func7 >> 3) << 25     # insert new func7
    return instruction

def shuffle_operands(instruction, shuffled, opcodes):
    """
    Shuffles the operands in the instruction based on the opcode.
    If instruction contains a function it will be shuffled as well.
    """
    opcode = (instruction >> 2) & 0b11111
    assert opcodes["rv64_opcodes"][opcode] != "invalid", "Invalid opcode"
    opcode_name = f"rv64_{opcodes['rv64_opcodes'][opcode]}"
    if opcode_name in opcodes:
        # shuffle function for this instruction 
        if opcode_name in ["rv64_imm64", "rv64_imm32", "rv64_load", "rv64_store", "rv64_branch"]:
            instruction = replace_func3(instruction, shuffled[opcode_name])
        elif opcode_name in ["rv64_op64", "rv64_op32"]:
            instruction = replace_func3_func7(instruction, shuffled[opcode_name])
    instruction = replace_opcode(instruction, shuffled["rv64_opcodes"])
    return instruction

def process_function(encrypt: bool, data: bytearray, function: dict, key: int, shuffled: dict = None, opcodes: dict = None):
    """Encrypts the provided function in place based on the function address and key."""
    print(f"Processing function {function['symbol']} at {hex(function['vma'])} with size {hex(function['size'])}")
    for i in range(0, function['size'], 4):
        offset = function['address'] + i
        dword, = struct.unpack("<I", data[offset:offset+4])

        if shuffled is not None or opcodes is not None:
            # Shuffle the operands
            dword = shuffle_operands(dword, shuffled, opcodes)
        if encrypt:
            dword = dword ^ transform(offset, key)
        data[offset:offset+4] = struct.pack("<I", dword)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="Input RISC-V binary")
    parser.add_argument("--shuffle", "-s", help="Shuffle the operands", action="store_true", default=False)
    parser.add_argument("--encrypt", "-e", help="Encrypt Binary", action="store_true", default=False)
    parser.add_argument("--map", "-m", help="Input map file", required=True)
    parser.add_argument("--output", "-o", help="Output binary file", required=True)
    parser.add_argument("--key", "-k", help="Encryption key (hex, int)", default="0xDEADBEEF")
    parser.add_argument("--shuffle-map", "-sm", help="Shuffle map file")
    parser.add_argument("--opcodes-map", "-om", help="Opcodes map file")

    args = parser.parse_args()
    input: str = args.input
    map_file: str = args.map
    output: str = args.output
    shuffle_json: str = args.shuffle_map
    opcodes_json: str = args.opcodes_map
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
    opcode_map = None
    
    if shuffle:
        if shuffle_json is None:
            print("Shuffle map file required when shuffling")
            sys.exit(1)
        if opcodes_json is None:
            print("Opcodes map file required when shuffling")
            sys.exit(1)
        with open(shuffle_json, "r") as f:
            shuffle_map = json.load(f)
            # layout is { "rv64_opcodes": { "1": 0, ... }, "rv64_op64": { "1": 0, ... }, }
            # convert the number strings to ints
            shuffle_map = {k: {int(k2): v2 for k2, v2 in v.items()} for k, v in shuffle_map.items()}

        with open(opcodes_json, "r") as f:
            opcode_map = json.load(f)
            # layout is { "rv64_opcodes": { "1": "add", ... }, "rv64_op64": { "1": "addw", ... }, }
            # convert the number strings to ints
            opcode_map = {k: {int(k2): v2 for k2, v2 in v.items()} for k, v in opcode_map.items()}
        
        if shuffle_map is None or opcode_map is None:
            print("Could not load shuffle or opcode map")
            sys.exit(1)
            
    # Encrypt the functions
    for function in functions:
        process_function(encrypt, binary, function, key, shuffle_map, opcode_map)

    # Walk and verify the relocations
    rela_offset = binary.rfind(b"RELA")
    if rela_offset == -1:
        print("Could not find RELA section")
        sys.exit(1)
    rela_offset += 4
    while binary[rela_offset] != 0:
        rela = binary[rela_offset:rela_offset + 13]
        assert len(rela) == 13
        type, offset, addend = struct.unpack("<BIq", rela)
        print(f"Relocation type {type} at offset {hex(offset)} with addend {addend}")
        rela_offset += 13
    assert rela_offset + 1 == len(binary), "Incorrect relocation format"

    # Append the feature section
    features = 0
    if encrypt:
        features |= 1
    if shuffle:
        features |= 2
    binary += b"FEAT"
    binary += struct.pack("<BI", features, key)

    # Write the encrypted binary
    with open(output, "wb") as f:
        f.write(binary)

if __name__ == "__main__":
    main()
