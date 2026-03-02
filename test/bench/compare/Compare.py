#!/usr/bin/env python3

from pathlib import Path
import argparse
import logging as log

from Binary import Binary


class Comparator:
    MAX_BINARIES = 10

    def __init__(self, bin_path: Path):
        self.bins = list()
        i = 0
        for bp in bin_path.glob("**/*"):
            if bp.is_dir():
                continue
            if not bp.exists():
                log.error(f"File '{bp}' doesn't exist.")
                continue

            try:
                bin = Binary(bp)
                log.debug(f"Add '{bp}'")
                self.bins.append(bin)
                i += 1
            except Exception as e:
                log.error(f"Load error for '{bp}'.")
                log.error(e)

            if i > self.MAX_BINARIES:
                log.error(f"Added {self.MAX_BINARIES} files. Stop.")
                break
        log.info(f"Added {len(self.bins)} binaries")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-f",
        "--frameworks",
        help="The frameworks to compare.",
        nargs="+",
        choices=["rz", "rz_old", "IDA", "Ghidra", "r2"],
        default="rz",
    )
    parser.add_argument(
        "bin_path",
        help="Path to one binary or a directory of binaries (walked recursively) for comparison.",
        type=Path,
    )
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = parse_args()
    comparator = Comparator(args.bin_path)
