#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

import argparse
import glob
import os
import sys
import subprocess

import yaml
from cmd_descs_util import (
    CD_TYPE_OLDINPUT,
    CD_TYPE_FAKE,
    CD_TYPE_INNER,
    compute_cname,
    get_handler_cname,
)


def get_yaml_files(basedir):
    for file in glob.glob(os.path.join(basedir, "*.yaml")):
        yield file


def find_entry(commands, rzcommand):
    for c in commands:
        if "subcommands" in c and isinstance(c["subcommands"], list):
            e = find_entry(c["subcommands"], rzcommand)
            if e is not None:
                return e
        if "subcommands" in c and isinstance(c["subcommands"], str):
            # This cd is only a group pointing to another file,
            # the handler cname will be fetched from there.
            return None

        if c["name"] == rzcommand:
            if "type" in c:
                if c["type"] not in [CD_TYPE_FAKE, CD_TYPE_INNER]:
                    return c
            else:
                return c

    return None


def get_c_handler_name_from_entry(e):
    name = e["cname"]
    if "handler" in e and e["handler"]:
        name = e["handler"]

    if "type" in e and e["type"] == CD_TYPE_OLDINPUT:
        return f"rz_{name}"

    return f"rz_{name}_handler"


def find_c_name_handler(basedir, rzcommand):
    for f in get_yaml_files(basedir):
        with open(f, "r", encoding="utf8") as of:
            y = yaml.safe_load(of)
            e = find_entry(y["commands"], rzcommand)
            if e is not None:
                cname = e.get("cname", compute_cname(e["name"]))
                return get_handler_cname(
                    e.get("type", None), e.get("handler", None), cname
                )

    return None


def format_shell_command(args):
    return " ".join(
        [arg if '"' not in arg and "*" not in arg else f"'{arg}'" for arg in args]
    )


def main():
    parser = argparse.ArgumentParser(
        description="Find the C handler of a rizin command"
    )
    parser.add_argument(
        "--cmddescs-dir",
        default=os.path.join("librz", "core", "cmd_descs"),
        type=str,
        help="Path to the cmd_descs directory containing the *.yaml files",
    )
    parser.add_argument(
        "-g",
        "--grep",
        action="store_true",
        help="Run the grep command directly instead of just showing it",
    )
    parser.add_argument("rzcommand", type=str, help="Name of the rizin command")

    args = parser.parse_args()
    c_name = find_c_name_handler(args.cmddescs_dir, args.rzcommand)
    CRED = "\033[91m"
    CEND = "\033[0m"
    if c_name is None:
        print(
            f"Command {args.rzcommand} does not exist or it is not converted to rzshell yet."
        )
        grep_cmd = ["git", "grep", "-n", f'"{args.rzcommand}"', "librz/core/cmd"]
        print(
            f"Some old commands may be found like this: {CRED}{format_shell_command(grep_cmd)}{CEND}"
        )
    else:
        print(f"Rizin Command: {CRED}{args.rzcommand}{CEND}")
        print(f"C handler: {CRED}{c_name}{CEND}")
        grep_cmd = ["git", "grep", "-nWG", f"^[^[:blank:]].*{c_name}(", "*.c"]
        print(f"Git command to get it: {CRED}{format_shell_command(grep_cmd)}{CEND}")

    if args.grep:
        print("--------")
        sys.exit(subprocess.run(grep_cmd, check=False).returncode)


if __name__ == "__main__":
    main()
