#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 Rot127 <rot127@posteo.com>
# SPDX-License-Identifier: LGPL-3.0-only

import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple


def get_changed_lines(
    base_ref: str, head_ref: str
) -> Dict[str, List[Tuple[int, int]]] | None:
    """
    Return dict:  file-path -> [(start_line, end_line), …]
    representing *added/modified* line ranges in the current branch.
    """
    changed: Dict[Path, List[Tuple[int, int]]] = {}

    try:
        subprocess.check_call(["git", "rev-parse", "--verify", f"{base_ref}"])
        subprocess.check_call(["git", "rev-parse", "--verify", f"{head_ref}"])
    except subprocess.CalledProcessError:
        # References were malformed.
        print(f"One or both references are invalid: {base_ref} and {head_ref}")
        sys.exit(1)

    # --unified=0  gives hunks like “@@ -L,C +L,C @@”  (we care about the + side)
    cmd = ["git", "diff", "--unified=0", f"{base_ref}..{head_ref}"]
    try:
        out = subprocess.check_output(cmd, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Random failure: stderr: {e.stderr}\nstdout: {e.stdout}\n")
        sys.exit(1)
    if not out:
        return None

    path = None
    for line in out.splitlines():
        # New file header
        if line.startswith("+++"):
            path = Path(line.strip("+++ b/")).name
            changed[path] = []
            continue
        # Hunk header
        m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
        if m and path is not None:
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) else 1
            changed[path].append((start, start + count - 1))
    return changed


def parse_asan_leaks(
    asan_output: str, changed: Dict[str, List[Tuple[int, int]]]
) -> Tuple[int, List[Tuple[Path, int, str]]]:
    leaks: List[Tuple[Path, int]] = []
    leak_traces = re.split(r"\n\n", asan_output)
    # Remove empty lines
    leak_traces = [t for t in leak_traces if t]
    total_leaks = len([x for x in leak_traces if " leak " in x])

    # Split into individual leak lines and search.
    leak_re = re.compile(
        r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+\w+\s+([^\n(]+):(\d+)", re.MULTILINE
    )
    for trace in leak_traces:
        for match in leak_re.finditer(trace):
            name = Path(match.group(1)).name
            line = int(match.group(2))
            if name in changed and any(
                line in range(start_end[0], start_end[1] + 1)
                for start_end in changed[name]
            ):
                leaks.append((name, line, trace))
                break
    return (total_leaks, leaks)


def main() -> None:
    if len(sys.argv) < 4:
        print("Supply ASAN output via stdin or file argument")
        print(f"{sys.argv[0]} <base_git_ref> <head_git_ref> [<file.log> ...]")
        sys.exit(2)
    base_ref = sys.argv[1]
    head_ref = sys.argv[2]

    changed = get_changed_lines(base_ref, head_ref)
    if not changed:
        print("No changed files")
        sys.exit(1)

    asan_text = ""
    for i in range(3, len(sys.argv)):
        asan_text += Path(sys.argv[i]).read_text(encoding="utf8")
    total_leaks, leaks = parse_asan_leaks(asan_text.strip(), changed)

    print("\nLEAK REPORT\n")
    print(f"Total leaks: {total_leaks}")
    print(f"New leaks: {len(leaks)}\n")

    print("Note: The leaks can be false positives but are rarely.\n")

    indent = "  "
    if leaks:
        print("Memory leaks detected in changed lines:")
        for f, l, trace in leaks:
            print("-" * 32)
            print(f"\n{indent}{f}:{l}\n")
            print(f"{indent}{trace.replace("\n", "\n" + indent)}\n")
        sys.exit(1)

    print("No new leaks in changed lines")
    sys.exit(0)


if __name__ == "__main__":
    main()
