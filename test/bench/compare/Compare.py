#!/usr/bin/env python3

from pathlib import Path
import argparse
import logging as log

from Binary import Binary, init_binary
from Framework import (
    FRAMEWORK_NAMES,
    FRAMEWORK_RIZIN,
    FRAMEWORK_RIZIN_OLD_ANALYSIS,
    Framework,
    init_framework_by_name,
)
from stats.Stats import Stats


class Comparator:
    MAX_BINARIES = 10

    def __init__(self, bin_path: Path, framework_names: list[str]):
        # Statistics for a Framework + Binary combination
        self.stats: Stats = Stats()
        self.bins: list[Binary] = list()
        self.framework_names: list[str] = framework_names
        self.frameworks: dict[str, Framework] = dict()
        self.load_binaries(bin_path)
        self.init_frameworks()

    def load_binaries(self, bin_path: Path):
        i = 0
        for bp in list(bin_path.glob("**/*")) + [bin_path]:
            if bp.is_dir():
                continue
            if not bp.exists():
                log.warning(f"File '{bp}' doesn't exist.")
                continue

            try:
                bin = init_binary(bp)
                log.info(f"Add '{bp}' with {len(bin.symbols)} symbols")
                self.bins.append(bin)
                i += 1
            except Exception as e:
                log.error(f"Load error for '{bp}'.")
                # log.error(repr(e))
                raise e

            if i > self.MAX_BINARIES:
                log.warning(f"Added maxiumum of {self.MAX_BINARIES} files. Stop.")
                break
        log.info(f"Added {len(self.bins)} binaries")

    def init_frameworks(self):
        for fname in self.framework_names:
            self.frameworks[fname] = init_framework_by_name(fname)
            log.info(f"Initialized {fname}")

    def analyze_all(self):
        for fw_name, fw in self.frameworks.items():
            for bin in self.bins:
                stats = Stats()
                dps = fw.analyze_bin(bin)
                stats.add_dps_duration(dps)
                self.stats[(fw, bin)] = stats
                log.info(
                    f"Analyzing '{bin.path.name}' with {fw_name} found {len(fw.symbols)} symbols."
                )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug output"
    )
    parser.add_argument(
        "-f",
        "--frameworks",
        help="The frameworks to compare.",
        nargs="+",
        choices=FRAMEWORK_NAMES,
        default=[FRAMEWORK_RIZIN, FRAMEWORK_RIZIN_OLD_ANALYSIS],
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
    log.basicConfig(level=log.DEBUG if args.verbose else log.INFO)
    comparator = Comparator(args.bin_path, args.frameworks)
    comparator.analyze_all()
