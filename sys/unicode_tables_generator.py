#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
# SPDX-License-Identifier: LGPL-3.0-only

"""
Regenerates the Unicode tables used by Rizin from the Unicode Character Database.

Inputs (all three from the same UCD release, found in one directory):
  - UnicodeData.txt     -> general category ranges + simple case mappings
  - SpecialCasing.txt   -> unconditional full case mappings (e.g. U+00DF -> "SS")
  - Blocks.txt          -> Unicode block names

Files rewritten:
  - librz/util/unicode.c                   (range tables + case mapping tables)
  - librz/util/utf8.c                      (unicode_blocks table)
  - librz/include/rz_util/rz_unicode.h     (RZ_UNICODE_VERSION_* defines)

Usage:
  # Regenerate in place:
  python3 sys/unicode_tables_generator.py --ucd /path/to/ucd

  # Only verify that the committed files match the given UCD (exit code 1 if not).
  # Running this with the *previous* UCD release on an untouched checkout must pass,
  # which shows that the generator reproduces what is committed.
  python3 sys/unicode_tables_generator.py --ucd /path/to/ucd --check

Notes:
  - Only the table bodies and the "Unicode version" comments are replaced.
    Everything else in those files is left untouched.
  - Conditional entries of SpecialCasing.txt (Final_Sigma, language specific
    ones for lt/tr/az) are skipped, because they cannot be applied without context.
  - The "undefined" table is the Cn (Unassigned) category plus the sentinel
    entry { 0x110000, 0xFFFFFFFF }, which makes everything above the last
    code point undefined, too.
"""

import argparse
import os
import re
import sys

LAST_CODE_POINT = 0x10FFFF

# Range tables in librz/util/unicode.c: table name -> general category.
RANGE_TABLES = {
    "surrogate_ranges": "Cs",
    "control_ranges": "Cc",
    "private_ranges": "Co",
    "format_ranges": "Cf",
    "undefined_ranges": "Cn",
}

# How many entries are printed on one line. Tables not listed here use 1.
ENTRIES_PER_LINE = {
    "undefined_ranges": 6,
    "lowercase_mapping": 5,
    "uppercase_mapping": 5,
}

UNDEFINED_SENTINEL = (0x110000, 0xFFFFFFFF)


# --------------------------------------------------------------------------- #
# Parsing of the UCD files
# --------------------------------------------------------------------------- #


def parse_unicode_data(path):
    """
    Returns (category, lower, upper):
      category: dict code point -> general category (assigned code points only)
      lower/upper: dict code point -> [simple mapping]
    Ranges written as "<..., First>" / "<..., Last>" are expanded.
    """
    category = {}
    lower = {}
    upper = {}
    range_first = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            fields = line.rstrip("\n").split(";")
            if len(fields) < 15:
                continue
            cp = int(fields[0], 16)
            name = fields[1]
            gc = fields[2]
            if name.endswith(", First>"):
                range_first = cp
                continue
            if name.endswith(", Last>"):
                for c in range(range_first, cp + 1):
                    category[c] = gc
                range_first = None
                continue
            category[cp] = gc
            if fields[12]:
                upper[cp] = [int(fields[12], 16)]
            if fields[13]:
                lower[cp] = [int(fields[13], 16)]
    return category, lower, upper


def parse_special_casing(path):
    """
    Returns (lower, upper): unconditional full mappings, code point -> [code points].
    Line format: code; lower; title; upper; (condition_list;)? # comment
    """
    lower = {}
    upper = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            fields = [x.strip() for x in line.split(";")]
            if len(fields) > 5 and fields[4]:
                continue  # conditional mapping
            cp = int(fields[0], 16)
            lower[cp] = [int(x, 16) for x in fields[1].split()]
            upper[cp] = [int(x, 16) for x in fields[3].split()]
    return lower, upper


def parse_blocks(path):
    """Returns a list of (first, last, name) sorted by first."""
    blocks = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            rng, name = [x.strip() for x in line.split(";", 1)]
            first, last = rng.split("..")
            blocks.append((int(first, 16), int(last, 16), name))
    blocks.sort()
    return blocks


def read_ucd_version(path, prefix):
    """The first line of UCD files looks like: '# SpecialCasing-18.0.0.txt'"""
    with open(path, encoding="utf-8") as f:
        first = f.readline()
    m = re.match(r"#\s*%s-(\d+)\.(\d+)\.(\d+)\.txt" % re.escape(prefix), first)
    if not m:
        sys.exit("Cannot read the Unicode version from the header of %s" % path)
    return tuple(int(x) for x in m.groups())


# --------------------------------------------------------------------------- #
# Table construction
# --------------------------------------------------------------------------- #


def category_ranges(category, wanted):
    """Contiguous (first, last) ranges of code points whose category is `wanted`.
    Code points missing from the UCD are Cn (unassigned)."""
    ranges = []
    start = None
    for cp in range(LAST_CODE_POINT + 1):
        hit = category.get(cp, "Cn") == wanted
        if hit and start is None:
            start = cp
        elif not hit and start is not None:
            ranges.append((start, cp - 1))
            start = None
    if start is not None:
        ranges.append((start, LAST_CODE_POINT))
    return ranges


def build_tables(ucd_dir):
    category, lower, upper = parse_unicode_data(os.path.join(ucd_dir, "UnicodeData.txt"))
    sc_lower, sc_upper = parse_special_casing(os.path.join(ucd_dir, "SpecialCasing.txt"))
    lower.update(sc_lower)  # full mappings override the simple ones
    upper.update(sc_upper)

    tables = {}
    for name, gc in RANGE_TABLES.items():
        tables[name] = category_ranges(category, gc)
    tables["undefined_ranges"].append(UNDEFINED_SENTINEL)
    tables["lowercase_mapping"] = sorted(lower.items())
    tables["uppercase_mapping"] = sorted(upper.items())
    return tables


# --------------------------------------------------------------------------- #
# Formatting (must match the committed layout byte for byte)
# --------------------------------------------------------------------------- #


def format_entry(name, entry):
    if name.endswith("_mapping"):
        key, vals = entry
        return "{ %d, { %s }}" % (key, ", ".join(str(v) for v in vals))
    if entry == UNDEFINED_SENTINEL:
        return "{ 0x%X, 0x%X }" % entry  # keep the hex spelling used by the committed table
    return "{ %d, %d }" % entry


def format_table_body(name, entries):
    per_line = ENTRIES_PER_LINE.get(name, 1)
    items = [format_entry(name, e) for e in entries]
    if per_line == 1:
        return "\n".join("\t%s," % it for it in items)
    lines = []
    for i in range(0, len(items), per_line):
        lines.append("\t" + ", ".join(items[i : i + per_line]))
    return ",\n".join(lines)


def format_blocks_body(blocks):
    return "\n".join('\t{ 0x%04X, 0x%04X, "%s" },' % b for b in blocks)


# --------------------------------------------------------------------------- #
# Rewriting of the source files
# --------------------------------------------------------------------------- #

VERSION_COMMENT_RE = re.compile(r"(Unicode version: )\d+\.\d+\.\d+(\.)")


def replace_table(text, decl_re, body, what):
    pattern = re.compile(r"(?P<head>%s = \{\n)(?P<body>.*?)(?P<tail>\n\};)" % decl_re, re.S)
    new_text, n = pattern.subn(lambda m: m.group("head") + body + m.group("tail"), text)
    if n != 1:
        sys.exit("Expected exactly one declaration of %s, found %d" % (what, n))
    return new_text


def set_version_comments(text, version):
    return VERSION_COMMENT_RE.sub(lambda m: m.group(1) + ".".join(map(str, version)) + m.group(2), text)


def rewrite_unicode_c(text, tables, version):
    for name, entries in tables.items():
        kind = "RzUnicodeCaseMap" if name.endswith("_mapping") else "RzUnicodeRangeTable"
        decl = r"(?:static )?const %s %s" % (kind, name)
        text = replace_table(text, decl, format_table_body(name, entries), name)
    return set_version_comments(text, version)


def rewrite_utf8_c(text, blocks, version):
    decl = r"const RzUnicodeRangeNameTable unicode_blocks"
    text = replace_table(text, decl, format_blocks_body(blocks), "unicode_blocks")
    return set_version_comments(text, version)


def rewrite_header(text, version):
    for label, value in zip(("MAJOR", "MINOR", "PATCH"), version):
        pattern = re.compile(r"(#define RZ_UNICODE_VERSION_%s\s+)\d+" % label)
        text, n = pattern.subn(lambda m: m.group(1) + str(value), text)
        if n != 1:
            sys.exit("Cannot find RZ_UNICODE_VERSION_%s in the header" % label)
    return text


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ucd", required=True, help="directory with UnicodeData.txt, SpecialCasing.txt and Blocks.txt")
    ap.add_argument("--repo", default=".", help="path to the Rizin repository root (default: .)")
    ap.add_argument("--check", action="store_true", help="do not write, only report whether files are up to date")
    args = ap.parse_args()

    version = read_ucd_version(os.path.join(args.ucd, "SpecialCasing.txt"), "SpecialCasing")
    blocks_version = read_ucd_version(os.path.join(args.ucd, "Blocks.txt"), "Blocks")
    if version != blocks_version:
        sys.exit("Version mismatch: SpecialCasing.txt is %s but Blocks.txt is %s" % (version, blocks_version))
    print("Unicode version: %s" % ".".join(map(str, version)))

    tables = build_tables(args.ucd)
    blocks = parse_blocks(os.path.join(args.ucd, "Blocks.txt"))

    jobs = [
        ("librz/util/unicode.c", lambda t: rewrite_unicode_c(t, tables, version)),
        ("librz/util/utf8.c", lambda t: rewrite_utf8_c(t, blocks, version)),
        ("librz/include/rz_util/rz_unicode.h", lambda t: rewrite_header(t, version)),
    ]

    outdated = False
    for rel, rewrite in jobs:
        path = os.path.join(args.repo, rel)
        with open(path, encoding="utf-8", newline="") as f:
            raw = f.read()
        # Work on LF internally, but keep the line endings the file already uses
        # (Git on Windows may check files out with CRLF).
        crlf = "\r\n" in raw
        old = raw.replace("\r\n", "\n")
        new = rewrite(old)
        if new == old:
            print("up to date : %s" % rel)
            continue
        outdated = True
        if args.check:
            print("OUT OF DATE: %s" % rel)
        else:
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(new.replace("\n", "\r\n") if crlf else new)
            print("rewritten  : %s" % rel)

    if args.check and outdated:
        sys.exit(1)


if __name__ == "__main__":
    main()
