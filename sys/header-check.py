#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
# SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
# SPDX-License-Identifier: LGPL-3.0-only

import argparse
import glob
import itertools
import subprocess
import datetime
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
    "librz/bin/d/jni.h",
    "librz/util/bdiff.c",
    "librz/asm/arch/tms320/c55x/table.h",
    "librz/include/sflib/",
    "librz/asm/arch/include/opcode/",
    "librz/bin/d/",
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


def get_edited_files():
    repo = Repo()
    for diff in repo.index.diff(None):
        filename = diff.a_path
        if should_scan(filename) and not skip(filename):
            yield filename


def execute_grep(file):
    try:
        return subprocess.check_output(["grep", "SPDX-", file]).decode("utf-8")
    except subprocess.CalledProcessError as e:
        return e.output.decode("utf-8")


def execute_git_log(file):
    cmd = [
        "git",
        "log",
        "--numstat",
        "-M",
        "--all",
        "--follow",
        "--date=format:%Y",
        "--pretty=%an <%ae>|%ad",
        "--",
        file,
    ]
    try:
        output = subprocess.check_output(cmd).decode("utf-8")
    except subprocess.CalledProcessError as e:
        output = e.output.decode("utf-8")
    return (
        output.strip()
        .replace("\n\n", "|")
        .replace("\t" + file, "")
        .replace("\t", "|")
        .split("\n")
    )


def generate_copyright(begin, end, editor):
    if begin == end:
        return f"{begin} {editor}"
    return f"{begin}-{end} {editor}"


def parse_git_log(log):
    log = log.replace("\t", "|").split("|")
    return log[0], int(log[1]), int(log[2]) + int(log[3])


def find_copyright_editors(file):
    editors = {}
    logs = execute_git_log(file)
    logs += execute_git_log(file.replace("rz/", "r/").replace("rz_", "r_"))

    for log in logs:
        if "|" not in log:
            continue
        who, year, changes = parse_git_log(log)
        if changes < 5:
            continue
        if who not in editors:
            editors[who] = [year, year, changes]
        else:
            editors[who][0] = min(year, editors[who][0])
            editors[who][1] = max(year, editors[who][1])
            editors[who][2] += changes

    top = []
    for editor, value in editors.items():
        begin, end, changes = value
        copyright_line = generate_copyright(begin, end, editor)
        top.append([copyright_line, changes])

    top = sorted(top, key=lambda x: x[1], reverse=True)

    now = datetime.date.today().year
    rizinorg = generate_copyright(now, now, "RizinOrg <info@rizin.re>")
    top.insert(0, [rizinorg, 0])
    return top


def suggest_header(file, show_all):
    editors = find_copyright_editors(file)
    count = 0
    for editor in editors:
        # Without this tokenization, the reuse linter breaks
        print("// SPDX-" + "FileCopyrightText: " + editor[0])
        count += 1
        if not show_all and count > 5:
            break
    # Without this tokenization, the reuse linter breaks
    print("// SPDX" + "-License" + "-Identifier: " + "LGPL-" + "3.0-" + "only")


def check_for_headers(file, output, args):
    has_spdx_headers = len(output.strip().split("\n")) > 1
    if args.verbose and has_spdx_headers:
        print("[OK]", file)
    elif not has_spdx_headers:
        print("[XX]", file)
        suggest_header(file, args.file is not None or args.interactive)
    if args.interactive and (args.verbose or not has_spdx_headers):
        input("press Enter to continue")


def check_for_headers_update(file, output, verbose):
    check_for_headers(file, output, verbose)


def format_files(args, files):
    if len(files) == 0:
        print("No C files to format.")
        sys.exit(0)
    for file in files:
        output = execute_grep(file)
        if args.check or len(args.file):
            check_for_headers(file, output, args)
        else:
            check_for_headers_update(file, output, args)


def get_files(args):
    if args.file:
        return [args.file]
    if args.check:
        return get_matching_files()
    return get_edited_files()


def process(args):
    if args.file:
        check_for_headers(args.file, "", args)
        return

    files = get_files(args)
    format_files(args, list(files))


def parse():
    parser = argparse.ArgumentParser(description="Header linter for the rizin project")
    parser.add_argument(
        "-c", "--check", action="store_true", help="enable the check mode"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="use verbose output"
    )
    parser.add_argument(
        "-i", "--interactive", action="store_true", help="use interactive output"
    )
    parser.add_argument("-f", "--file", help="forces check a single file")
    return parser.parse_args()


def main():
    args = parse()
    process(args)


if __name__ == "__main__":
    main()
