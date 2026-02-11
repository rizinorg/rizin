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
    "subprojects/rzar",
    "subprojects/rzgdb",
    "subprojects/ptrace-wrap",
    "subprojects/rzqnx",
    "subprojects/rzw32dbg_wrap",
    "subprojects/rzwinkd",
    "subprojects/rzheap/rz_jemalloc",
    "subprojects/rzheap/rz_glibc",
    "test/unit",
]

skiplist = [
    "/gnu/",
    "librz/arch/isa_gnu/",
    "librz/hash/xxhash/",
    "librz/bin/mangling/cxx/",
    "librz/bin/d/jni.h",
    "librz/util/bdiff.c",
    "librz/arch/isa/tms320/c55x/table.h",
    "librz/include/sflib/",
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


def build_command(clangformat, check, filenames, verbose):
    cmd = [clangformat, "--style=file"]
    if verbose:
        cmd += ["--verbose"]
    if check:
        cmd += ["--Werror", "--dry-run"]
    else:
        cmd += ["-i"]
    return cmd + filenames


def format_files(args, files):
    if len(files) == 0:
        print("No C files to format.")
        sys.exit(0)
    cmd = build_command(args.clang_format, args.check, files, args.verbose)
    r = subprocess.run(cmd, check=False)
    sys.exit(r.returncode)


def get_files_from_arg_option(args):
    files = []
    for filename in args.file:
        if should_scan(filename) and not skip(filename):
            files.append(filename)
        else:
            print(f"{filename} will be skipped.")
    return files


def get_files(args):
    if args.diff:
        return get_edited_files(args)

    if args.file:
        return get_files_from_arg_option(args)

    return get_matching_files()


def process(args):
    files = get_files(args)
    format_files(args, list(files))


def parse():
    parser = argparse.ArgumentParser(description="Clang format the rizin project")

    parser.add_argument(
        "-C", "--clang-format", default="clang-format", help="path of clang-format"
    )
    parser.add_argument(
        "-c", "--check", action="store_true", help="enable the check mode"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="use verbose output"
    )
    parser.add_argument(
        "-f", "--file", action="append", help="formats (or checks) only the given file"
    )
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
