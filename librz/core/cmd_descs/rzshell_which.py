#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

import argparse
import glob
import os
import sys

import yaml
from cmd_descs_util import CD_TYPE_OLDINPUT, compute_cname, get_handler_cname


def get_yaml_files(basedir):
    for file in glob.glob(os.path.join(basedir, "*.yaml")):
        yield file


def find_entry(commands, rzcommand):
    for c in commands:
        if "subcommands" in c and isinstance(c["subcommands"], list):
            e = find_entry(c["subcommands"], rzcommand)
            if e is not None:
                return e

        if c["name"] == rzcommand:
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
    parser.add_argument("rzcommand", type=str, help="Name of the rizin command")

    args = parser.parse_args()
    c_name = find_c_name_handler(args.cmddescs_dir, args.rzcommand)
    if c_name is None:
        print(
            f"Command {args.rzcommand} does not exist or it is not converted to rzshell yet."
        )
        sys.exit(1)

    CRED = "\033[91m"
    CEND = "\033[0m"

    print(f"Rizin Command: {CRED}{args.rzcommand}{CEND}")
    print(f"C handler: {CRED}{c_name}{CEND}")
    print(
        f'Git command to get it: {CRED}git grep -nWG "^[^[:blank:]].*{c_name}(" *.c{CEND}'
    )


if __name__ == "__main__":
    main()
