#!/usr/bin/env python3

import glob
import os
import shutil
import subprocess
import sys

binary = "clang-format-11"
if not shutil.which(binary):
    binary = "clang-format"
    verstr = subprocess.run([binary, "--version"], capture_output=True).stdout
    if not b"version 11." in verstr:
        sys.stderr.write("ERROR: clang-format 11 required\n")
        sys.exit(1)

dirlist = [
    "binrz",
    "librz",
    "shlr/ar",
    "shlr/bochs",
    "shlr/gdb",
    "shlr/java",
    "shlr/ptrace-wrap",
    "shlr/qnx",
    "shlr/rar",
    "shlr/tcc",
    "shlr/w32dbg_wrap",
    "shlr/winkd",
    "test/unit",
]

skiplist = [
    "/gnu/",
    "librz/asm/arch/vax/",
    "librz/asm/arch/riscv/",
    "librz/asm/arch/sh/gnu/",
    "librz/asm/arch/i8080/",
    "librz/asm/arch/z80/",
    "librz/asm/arch/avr/",
    "librz/asm/arch/arm/aarch64/",
    "librz/hash/xxhash/",
    "librz/bin/mangling/cxx/",
    "librz/util/bdiff.c",
]

pattern = ["*.c", "*.cpp", "*.h", "*.hpp", "*.inc"]


def skip(filename):
    for s in skiplist:
        if s in filename:
            return True
    return False


try:
    for d in dirlist:
        print("Processing directory: {0}".format(d))
        for pat in pattern:
            print("Processing pattern: {0}".format(pat))
            for filename in glob.iglob(d + "/**/" + pat, recursive=True):
                if not skip(filename):
                    CMD = "{0} -style=file -i {1}".format(binary, filename)
                    print(CMD)
                    os.system(CMD)

except KeyboardInterrupt:
    print("clang-format.py interrupted by the user.")
    sys.exit(1)
