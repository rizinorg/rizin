#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
# SPDX-License-Identifier: LGPL-3.0-only

"""
Check that the commands printing data offer a JSON output mode.

A command is expected to offer JSON when it has output modes, or when its
summary starts with a verb like "List" or "Show". With --base, only the
commands added since that revision, or whose output modes changed, are
checked, and no command may lose its JSON mode. With --all, every command
is checked, which lists what is left to do.
"""

import argparse
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CMD_DESCS = "librz/core/cmd_descs"

JSON_MODES = {"RZ_OUTPUT_MODE_JSON", "RZ_OUTPUT_MODE_LONG_JSON"}
EXEC_TYPES = {
    "RZ_CMD_DESC_TYPE_ARGV",
    "RZ_CMD_DESC_TYPE_ARGV_MODES",
    "RZ_CMD_DESC_TYPE_ARGV_STATE",
}
DATA_VERBS = {
    "disassemble",
    "display",
    "dump",
    "enumerate",
    "find",
    "get",
    "list",
    "print",
    "search",
    "show",
}

# Commands that need no JSON mode, with the reason.
EXEMPT = {
    "(": "`(j` is taken as the start of a macro definition",
    "%l": "prints one number",
    "aav": "runs an analysis",
    "ahi": "sets a hint",
    "aii-": "removes the imports",
    "dm.": "prints one name",
    "dtg": "draws a graph",
    "fg": "draws a graph",
    "pa": "assembles its argument",
    "pad": "disassembles its argument",
    "pade": "translates its argument",
    "pae": "translates its argument",
    "pb": "prints one bitstream",
    "pB": "prints one bitstream",
    "pdbJ": "prints JSON already",
    "pdJ": "prints JSON already",
    "pFa": "prints a hexdump, `pFasj` is the JSON",
    "pix": "disassembles its argument",
    "psc": "generates code",
    "pss": "wraps `ps` to the screen, `psj` is the JSON",
    "pxA": "draws a color map",
    "p-h": "prints a table, `p-j` is the JSON",
    "p6d": "decodes its argument",
    "p6e": "encodes its argument",
}


def cd_type(c):
    # Same defaults as cmd_descs_generate.py
    if "type" in c:
        return c["type"]
    if c.get("subcommands"):
        return "RZ_CMD_DESC_TYPE_GROUP"
    if c.get("modes"):
        return "RZ_CMD_DESC_TYPE_ARGV_MODES"
    return "RZ_CMD_DESC_TYPE_ARGV"


def collect(yamls, cmds, out):
    for c in cmds:
        if cd_type(c) in EXEC_TYPES:
            # cname is unique, while some names are not
            out[c.get("cname") or c["name"]] = {
                "name": c["name"],
                "modes": set(c.get("modes") or []),
                "summary": " ".join(str(c.get("summary", "")).split()),
            }
        subs = c.get("subcommands")
        if isinstance(subs, str):
            subs = yamls[subs]
        collect(yamls, subs or [], out)


def load(texts):
    yamls = {}
    root = None
    for path, text in texts.items():
        y = yaml.safe_load(text)
        yamls[y["name"]] = y["commands"]
        if Path(path).name == "cmd_descs.yaml":
            root = y["commands"]
    cmds = {}
    collect(yamls, root, cmds)
    return cmds


def worktree_texts():
    return {
        str(p): p.read_text(encoding="utf8")
        for p in sorted((ROOT / CMD_DESCS).glob("*.yaml"))
    }


def git(*args):
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout


def revision_texts(rev):
    paths = git("ls-tree", "--name-only", f"{rev}:{CMD_DESCS}").split()
    return {
        p: git("show", f"{rev}:{CMD_DESCS}/{p}") for p in paths if p.endswith(".yaml")
    }


def wants_json(cmd):
    if cmd["name"] in EXEMPT:
        return False
    if cmd["modes"]:
        return True
    words = cmd["summary"].split()
    return bool(words) and words[0].lower() in DATA_VERBS


def problems(head, base):
    for cname, cmd in sorted(head.items(), key=lambda kv: kv[1]["name"]):
        old = base.get(cname) if base is not None else None
        if old and old["modes"] & JSON_MODES and not cmd["modes"] & JSON_MODES:
            yield f"`{cmd['name']}` lost its JSON output mode"
            continue
        if old and old["modes"] == cmd["modes"]:
            continue
        if not cmd["modes"] & JSON_MODES and wants_json(cmd):
            yield f"`{cmd['name']}` ({cmd['summary']}) has no JSON output mode"


def main():
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--base", help="check the changes since this git revision")
    group.add_argument("--all", action="store_true", help="check every command")
    args = parser.parse_args()

    head = load(worktree_texts())
    base = None if args.all else load(revision_texts(args.base))
    found = list(problems(head, base))
    for p in found:
        print(p)
    if found and not args.all:
        print(
            "\nAdd RZ_OUTPUT_MODE_JSON to the commands printing data. If one prints no"
            f" data, add it to EXEMPT in {Path(__file__).name} with the reason."
        )
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
