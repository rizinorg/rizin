#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 Rot127 <rot127@posteo.com>
# SPDX-License-Identifier: LGPL-3.0-only

import re
import sys
from pathlib import Path


def get_changed_lines(diff: str) -> dict[str, list[range]]:
    """
    Return dict:  filename -> [(start_line, end_line), …]
    representing *added/modified* line ranges in the current branch.
    """
    changed: dict[Path, list[tuple[int, int]]] = {}

    path = None
    for line in diff.splitlines():
        # New file header
        if line.startswith("+++ b/"):
            path = Path(line.strip("+++ b/")).name
            changed[path] = []
            continue
        # Changed lines
        m = re.match(r"@@ -\d+(,\d+)? \+(?P<line_b>\d+)(,(?P<n_b>\d+))? @@", line)
        if m and path:
            start = int(m.group("line_b"))
            count = int(m.group("n_b")) if m.group("n_b") else 1
            if count != 0:
                changed[path].append(range(start, start + count))
    return changed


def parse_asan_leaks(
    asan_output: str, changed: dict[str, list[range]]
) -> tuple[int, list[tuple[Path, int, str]]]:
    leaks: list[tuple[Path, int]] = []
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
                line in start_end for start_end in changed[name]
            ):
                leaks.append((name, line, trace))
                break
    return (total_leaks, leaks)


def main() -> None:
    if len(sys.argv) < 3:
        print("Supply ASAN output via stdin or file argument")
        print(f"{sys.argv[0]} <some.diff> [<file.log> ...]")
        sys.exit(2)
    diff_file = sys.argv[1]
    with open(diff_file, "r", encoding="utf8") as f:
        diff = f.read()

    changed = get_changed_lines(diff)
    if not changed:
        print("No changed files")
        sys.exit(1)
    print(changed)

    asan_text = ""
    for i in range(2, len(sys.argv)):
        p = Path(sys.argv[i])
        if p.is_dir():
            print(f"Skip dir: {p}")
            continue
        asan_text += p.read_text(encoding="utf8")
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
            print(f"{indent}{trace.replace('\n', '\n' + indent)}\n")
        sys.exit(1)

    print("No new leaks in changed lines")
    sys.exit(0)


if __name__ == "__main__":
    main()
