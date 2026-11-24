#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anton Angelov <anton.angelov@protonmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

"""
Regenerates librz/util/undefined_ranges_bitmap.inc from the `undefined_ranges`
table in librz/util/unicode.c.

Run this whenever `undefined_ranges` is updated (e.g. on a Unicode version bump).

Dependencies: pip install tree-sitter tree-sitter-c
"""
import argparse
import datetime
import pathlib
import sys

from tree_sitter import Language, Parser, Query, QueryCursor
import tree_sitter_c as tsc

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_UNICODE_C = REPO_ROOT / "librz/util/unicode.c"
DEFAULT_OUT_INC = REPO_ROOT / "librz/util/undefined_ranges_bitmap.inc"
TABLE_NAME = "undefined_ranges"
BITS_PER_WORD = 64
WORDS_PER_LINE = 3

LANG = Language(tsc.language())
QUERY = Query(LANG, """
(declaration
  declarator: (init_declarator
    declarator: (identifier) @name
    value: (initializer_list) @init))
""")


def extract_ranges(src: bytes):
    tree = Parser(LANG).parse(src)
    cursor = QueryCursor(QUERY)
    for _pattern_index, captures in cursor.matches(tree.root_node):
        name_node = captures["name"][0]
        if src[name_node.start_byte:name_node.end_byte].decode() != TABLE_NAME:
            continue
        init_node = captures["init"][0]
        ranges = []
        for pair in init_node.named_children:
            if pair.type != "initializer_list":
                continue
            nums = [c for c in pair.named_children if c.type == "number_literal"]
            if len(nums) != 2:
                raise ValueError(f"unexpected range shape: {pair.text}")
            lo, hi = (int(src[n.start_byte:n.end_byte], 0) for n in nums)
            ranges.append((lo, hi))
        return ranges
    raise ValueError(f"could not find `{TABLE_NAME}` declaration")


def build_bitmap(ranges, size):
    nwords = (size + BITS_PER_WORD - 1) // BITS_PER_WORD
    bitmap = [0] * nwords
    for lo, hi in ranges:
        hi = min(hi, size - 1)
        for cp in range(lo, hi + 1):
            bitmap[cp // BITS_PER_WORD] |= 1 << (cp % BITS_PER_WORD)
    return bitmap


def compute_skip_entries(ranges, size):
    """Number of leading `undefined_ranges` entries already covered by a bitmap of `size` bits,
    i.e. how many entries a fallback search over `undefined_ranges` can skip."""
    for i, (_lo, hi) in enumerate(ranges):
        if hi >= size:
            return i
    return len(ranges)


def emit_inc(bitmap, skip_entries, unicode_version, author_name, author_email):
    year = datetime.date.today().year
    lines = [
        f"// SPDX-FileCopyrightText: {year} {author_name} <{author_email}>",
        "// SPDX-License-Identifier: LGPL-3.0-only",
        "",
        "/**",
        " * \\brief A static bitmap indicating whether a Unicode code point is defined.",
        " *",
        " * AUTO-GENERATED FILE — DO NOT EDIT.",
        " * Regenerate with: python3 sys/gen_unicode_undefined_bitmap.py",
        " *",
        f" * Unicode version: {unicode_version}.",
        " */",
        "",
        f"static const ut64 undefined_ranges_bitmap[{len(bitmap)}] = {{",
    ]
    for i in range(0, len(bitmap), WORDS_PER_LINE):
        row = bitmap[i:i + WORDS_PER_LINE]
        lines.append("\t" + " ".join(f"0x{w:016x}ULL," for w in row))
    lines.append("};")
    lines.append("")
    lines.append("/**")
    lines.append(" * \\brief Number of leading entries of `undefined_ranges` to skip when falling back.")
    lines.append(" */")
    lines.append(f"static const ut32 undefined_ranges_skip_entries = {skip_entries};")
    lines.append("")
    return "\n".join(lines)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--author-name", required=True, help="Name for the SPDX-FileCopyrightText header")
    parser.add_argument("--author-email", required=True, help="Email for the SPDX-FileCopyrightText header")
    parser.add_argument("--unicode-version", default="16.0.0", help="Unicode version this table was generated from")
    parser.add_argument("--input", type=pathlib.Path, default=DEFAULT_UNICODE_C,
                         help=f"Path to unicode.c containing `{TABLE_NAME}` (default: {DEFAULT_UNICODE_C})")
    parser.add_argument("--output", type=pathlib.Path, default=DEFAULT_OUT_INC,
                         help=f"Path to write the generated .inc file (default: {DEFAULT_OUT_INC})")
    parser.add_argument("--size", type=lambda s: int(s, 0), default=0x110000,
                         help="Bitmap size in bits, i.e. how many code points it covers (default: 0x110000)")
    return parser.parse_args()


def main():
    args = parse_args()
    src = args.input.read_bytes()
    ranges = extract_ranges(src)
    bitmap = build_bitmap(ranges, args.size)
    skip_entries = compute_skip_entries(ranges, args.size)
    args.output.write_text(emit_inc(bitmap, skip_entries, args.unicode_version, args.author_name, args.author_email))
    print(f"wrote {args.output} ({len(bitmap)} words, {len(ranges)} ranges)")


if __name__ == "__main__":
    sys.exit(main())
