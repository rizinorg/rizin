#!/usr/bin/env python3

from pathlib import Path
import argparse
import logging as log

from Binary import Binary
from Framework import FRAMEWORK_NAMES, Framework, init_framework_by_name


class Comparator:
    MAX_BINARIES = 10

    def __init__(self, bin_path: Path, framework_names: list[str]):
        self.bins: list[Binary] = list()
        self.framework_names: list[str] = framework_names
        self.frameworks: dict[str, Framework] = dict()
        self.load_binaries()
        self.init_frameworks()

    def load_binaries(self):
        i = 0
        for bp in self.bin_path.glob("**/*"):
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

    def init_framework_analyzers(self):
        for fname in self.framework_names:
            self.frameworks[fname] = init_framework_by_name(fname)

    def analyze_all():
        pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-f",
        "--frameworks",
        help="The frameworks to compare.",
        nargs="+",
        choices=FRAMEWORK_NAMES,
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
    comparator = Comparator(args.bin_path, args.frameworks)
