import argparse
import sys

import pefile

def main():
    # Parse the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", help="Executable with embedded .llvmbc section")
    parser.add_argument("--output", "-o", help="Output file name", required=True)
    args = parser.parse_args()
    executable: str = args.executable
    output: str = args.output

    # Find the .llvmbc section
    pe = pefile.PE(executable)
    llvmbc = None
    for section in pe.sections:
        if section.Name.decode("utf-8").strip("\x00") == ".llvmbc":
            llvmbc = section
            break
    if llvmbc is None:
        print("No .llvmbc section found")
        sys.exit(1)

    # Recover the bitcode and write it to a file
    with open(output, "wb") as f:
        data = bytearray(llvmbc.get_data())
        # Truncate all trailing null bytes
        while data[-1] == 0:
            data.pop()
        # Recover alignment to 4
        while len(data) % 4 != 0:
            data.append(0)
        # Add a block end marker
        for _ in range(4):
            data.append(0)
        f.write(data)

if __name__ == "__main__":
    main()
