#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

import argparse
import glob
import itertools
import subprocess
import sys

from git import Repo

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
    "librz/asm/arch/tms320/c55x/table.h",
]

patterns = ["*.c", "*.cpp", "*.h", "*.hpp", "*.inc"]


def should_scan(filename):
    return any(directory in filename for directory in dirlist) and any(
        pattern[1:] in filename for pattern in patterns
    )


def skip(filename):
    return any(skipfile in filename for skipfile in skiplist)


def get_matching_files():
    for directory, pattern in itertools.product(dirlist, patterns):
        for filename in glob.iglob(directory + "/**/" + pattern, recursive=True):
            if not skip(filename):
                yield filename


def get_edited_files(args):
    repo = Repo()

    for diff in repo.index.diff(args.diff):
        filename = diff.a_path
        if should_scan(filename) and not skip(filename):
            yield filename


def build_command(check, filenames):
    if check:
        return ["clang-format", "--style=file", "--Werror", "--dry-run"] + filenames

    return ["clang-format", "--style=file", "-i"] + filenames


def format_files(args, files):
    if len(files) == 0:
        print("No C files to format.")
        sys.exit(0)
    cmd = build_command(args.check, files)
    if args.verbose:
        print(cmd)
    r = subprocess.run(cmd, check=False)
    sys.exit(r.returncode)


def get_file(args):
    filename = args.file
    if should_scan(filename) and not skip(filename):
        return [filename]

    return []


def get_files(args):
    if args.diff:
        return get_edited_files(args)

    if args.file:
        return get_file(args)

    return get_matching_files()


def process(args):
    files = get_files(args)
    format_files(args, list(files))


def parse():
    parser = argparse.ArgumentParser(description="Clang format the rizin project")
    parser.add_argument(
        "-c", "--check", action="store_true", help="enable the check mode"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="use verbose output"
    )
    parser.add_argument("-f", "--file", help="formats (or checks) only the given file")
    parser.add_argument(
        "-d",
        "--diff",
        type=str,
        default=None,
        help="format all modified file related to branch",
    )
    return parser.parse_args()


def main():
    args = parse()
    process(args)


if __name__ == "__main__":
    main()
