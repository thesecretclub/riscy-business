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
    # Extract the opcode from the instruction
    original_opcode = (instruction >> 2) & 0b11111
    # Get the new opcode from the shuffled_dict
    new_opcode = shuffled[original_opcode]
    # Clear out the original opcode from the instruction
    instruction &= ~(0b11111 << 2)
    # Insert the new opcode
    instruction |= (new_opcode << 2)
    return instruction

def process_function(encrypt: bool, data: bytearray, function: dict, key: int, shuffled: dict = None):
    """Encrypts the provided function in place based on the function address and key."""
    print(f"Processing function {function['symbol']} at {hex(function['vma'])} with size {hex(function['size'])}")
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
    parser.add_argument("--shuffle", "-s", help="Shuffle the operands", action="store_true", default=False)
    parser.add_argument("--encrypt", "-e", help="Encrypt Binary", action="store_true", default=False)
    parser.add_argument("--map", "-m", help="Input map file", required=True)
    parser.add_argument("--output", "-o", help="Output binary file", required=True)
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
        if shuffle_json is None:
            print("Shuffle map file required when shuffling")
            sys.exit(1)
        with open(shuffle_json, "r") as f:
            shuffle_map = json.load(f)
            shuffle_map = {int(k): int(v) for k, v in shuffle_map.items()}

    # Encrypt the functions
    for function in functions:
        process_function(encrypt, binary, function, key, shuffle_map)

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
