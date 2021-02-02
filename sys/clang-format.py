#!/usr/bin/env python3

import argparse
import glob
import itertools
import os
import sys

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
    "librz/asm/arch/tms320/c55x/table.h"
]

patterns = ["*.c", "*.cpp", "*.h", "*.hpp", "*.inc"]


def skip(filename):
    return any(skipfile in filename for skipfile in skiplist)


def build_command(check, filename):
    if check:
        return "clang-format --style=file --Werror --dry-run {0}".format(filename)

    return "clang-format --style=file -i {0}".format(filename)


def get_matching_files():
    for directory, pattern in itertools.product(dirlist, patterns):
        for filename in glob.iglob(directory + "/**/" + pattern, recursive=True):
            if not skip(filename):
                yield filename


def format_rizin(args):
    return_code = 0

    for filename in get_matching_files():
        cmd = build_command(args.check, filename)

        if args.verbose:
            print(cmd)

        if os.system(cmd) == 256:
            return_code = 1

    sys.exit(return_code)


def main():
    parser = argparse.ArgumentParser(description="Clang format the rizin project")
    parser.add_argument(
        "--check", action="store_true", help="Flag that enable the check mode"
    )
    parser.add_argument("--verbose", action="store_true", help="Use verbose output")
    args = parser.parse_args()

    format_rizin(args)


if __name__ == "__main__":
    main()
