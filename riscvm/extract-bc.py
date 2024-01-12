import argparse
import sys

import pefile

# These functions are not in the import table, but might be used by the compiler
ntdll_msvcrt = [
    "_atoi64",
    "_errno",
    "_fltused",
    "_i64toa",
    "_i64toa_s",
    "_i64tow",
    "_i64tow_s",
    "_itoa",
    "_itoa_s",
    "_itow",
    "_itow_s",
    "_lfind",
    "_local_unwind",
    "_ltoa",
    "_ltoa_s",
    "_ltow",
    "_ltow_s",
    "_makepath_s",
    "_memccpy",
    "_memicmp",
    "_snprintf",
    "_snprintf_s",
    "_snscanf_s",
    "_snwprintf",
    "_snwprintf_s",
    "_snwscanf_s",
    "_splitpath",
    "_splitpath_s",
    "_strcmpi",
    "_stricmp",
    "_strlwr",
    "_strlwr_s",
    "_strnicmp",
    "_strnset_s",
    "_strset_s",
    "_strupr",
    "_strupr_s",
    "_swprintf",
    "_ui64toa",
    "_ui64toa_s",
    "_ui64tow",
    "_ui64tow_s",
    "_ultoa",
    "_ultoa_s",
    "_ultow",
    "_ultow_s",
    "_vscprintf",
    "_vscwprintf",
    "_vsnprintf",
    "_vsnprintf_s",
    "_vsnwprintf",
    "_vsnwprintf_s",
    "_vswprintf",
    "_wcsicmp",
    "_wcslwr",
    "_wcslwr_s",
    "_wcsnicmp",
    "_wcsnset_s",
    "_wcsset_s",
    "_wcstoi64",
    "_wcstoui64",
    "_wcsupr",
    "_wcsupr_s",
    "_wmakepath_s",
    "_wsplitpath_s",
    "_wtoi",
    "_wtoi64",
    "_wtol",
    "abs",
    "atan",
    "atan2",
    "atoi",
    "atol",
    "bsearch",
    "bsearch_s",
    "ceil",
    "cos",
    "fabs",
    "floor",
    "isalnum",
    "isalpha",
    "iscntrl",
    "isdigit",
    "isgraph",
    "islower",
    "isprint",
    "ispunct",
    "isspace",
    "isupper",
    "iswalnum",
    "iswalpha",
    "iswascii",
    "iswctype",
    "iswdigit",
    "iswgraph",
    "iswlower",
    "iswprint",
    "iswspace",
    "iswxdigit",
    "isxdigit",
    "labs",
    "log",
    "longjmp",
    "mbstowcs",
    "memchr",
    "memcmp",
    "memcpy",
    "memcpy_s",
    "memmove",
    "memmove_s",
    "memset",
    "pow",
    "qsort",
    "qsort_s",
    "sin",
    "sprintf",
    "sprintf_s",
    "sqrt",
    "sscanf",
    "sscanf_s",
    "strcat",
    "strcat_s",
    "strchr",
    "strcmp",
    "strcpy",
    "strcpy_s",
    "strcspn",
    "strlen",
    "strncat",
    "strncat_s",
    "strncmp",
    "strncpy",
    "strncpy_s",
    "strnlen",
    "strpbrk",
    "strrchr",
    "strspn",
    "strstr",
    "strtok_s",
    "strtol",
    "strtoul",
    "swprintf",
    "swprintf_s",
    "swscanf_s",
    "tan",
    "tolower",
    "toupper",
    "towlower",
    "towupper",
    "vsprintf",
    "vsprintf_s",
    "vswprintf_s",
    "wcscat",
    "wcscat_s",
    "wcschr",
    "wcscmp",
    "wcscpy",
    "wcscpy_s",
    "wcscspn",
    "wcslen",
    "wcsncat",
    "wcsncat_s",
    "wcsncmp",
    "wcsncpy",
    "wcsncpy_s",
    "wcsnlen",
    "wcspbrk",
    "wcsrchr",
    "wcsspn",
    "wcsstr",
    "wcstok_s",
    "wcstol",
    "wcstombs",
    "wcstoul",
]

def main():
    # Parse the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", help="Executable with embedded .llvmbc section")
    parser.add_argument("--output", "-o", help="Output file name", required=True)
    parser.add_argument("--importmap", help="Import map", required=False)
    args = parser.parse_args()
    executable: str = args.executable
    output: str = args.output
    importmap: str = args.importmap

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

    # Save the import map
    if importmap is not None:
        with open(importmap, "wb") as f:
            visited = set()
            for desc in pe.DIRECTORY_ENTRY_IMPORT:
                dll: str = desc.dll.decode("utf-8")
                for imp in desc.imports:
                    name: str = imp.name.decode("utf-8")
                    visited.add(name)
                    f.write(f"{name}:{dll.lower()}\n".encode("utf-8"))

            # Add implicit ntdll MSVCRT imports
            for name in ntdll_msvcrt:
                if name not in visited:
                    f.write(f"{name}:ntdll.dll\n".encode("utf-8"))

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
