#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
# SPDX-License-Identifier: LGPL-3.0-only

"""Extract register names from RzAnalysisPlugin.get_reg_profile string.

Usage:
    python extract_reg_names.py <input.c> <output.inc>

Dependencies:
    pip install tree-sitter tree-sitter-c
"""

import sys
from datetime import datetime

import tree_sitter_c as ts_c
from tree_sitter import Language, Parser


def get_text(node, source):
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def extract_identifier(node, source):
    """Extract a simple identifier from a declarator/value node, handling *, & etc."""
    if node is None:
        return None
    if node.type == "identifier":
        return get_text(node, source)
    for child in node.children:
        name = extract_identifier(child, source)
        if name:
            return name
    return None


def find_get_reg_profile_value(root, source):
    """Find the value assigned to .get_reg_profile in any struct initializer."""

    def walk(node):
        if node.type == "initializer_pair":
            field_name = None
            value_node = None
            for child in node.children:
                if child.type == "field_designator":
                    for sub in child.children:
                        if sub.type == "field_identifier":
                            field_name = get_text(sub, source)
                elif child.type == "field_identifier":
                    field_name = get_text(child, source)
                elif child.type == "=":
                    continue
                elif child.type not in (".", ","):
                    value_node = child
            if field_name == "get_reg_profile" and value_node is not None:
                return value_node
        for child in node.children:
            result = walk(child)
            if result is not None:
                return result
        return None

    return walk(root)


def get_function_name(func_def, source):
    decl = func_def.child_by_field_name("declarator")
    return extract_identifier(decl, source) if decl else None


def find_function_by_name(root, source, name):
    for node in root.children:
        if (  # noqa: SIM102
            node.type == "function_definition"
            and get_function_name(node, source) == name
        ):
            return node
    return None


def concat_string_literals(init_node, source):
    parts = []

    def collect(node):
        if node.type == "string_literal":
            raw = get_text(node, source)
            parts.append(raw[1:-1])
        for child in node.children:
            collect(child)

    collect(init_node)
    return "".join(parts)


def decode_c_string(s):
    """Decode C escape sequences like \\n, \\t, etc."""
    return s.encode("utf-8").decode("unicode_escape")


def extract_profile_string(function_node, source):
    body = function_node.child_by_field_name("body")
    if body is None:
        return None

    candidates = []
    for node in body.children:
        if node.type != "declaration":
            continue
        for child in node.children:
            if child.type != "init_declarator":
                continue
            decl = child.child_by_field_name("declarator")
            init = child.child_by_field_name("value")
            if decl is None or init is None:
                continue
            ident = extract_identifier(decl, source)
            s = concat_string_literals(init, source)
            if s:
                candidates.append((ident, s))

    if candidates:
        for ident, s in candidates:
            if ident == "p":
                return decode_c_string(s)
        return decode_c_string(max(candidates, key=lambda x: len(x[1]))[1])

    # Fallback: concatenate all string literals in the function body
    all_strings = concat_string_literals(body, source)
    return decode_c_string(all_strings) if all_strings else None


def parse_register_names(profile):
    names = []
    seen = set()
    for line in profile.splitlines():
        line = line.strip()
        if not line or line.startswith(("=", "#")):
            continue
        tokens = line.split()
        if len(tokens) < 2:
            continue
        name = tokens[1]
        if name not in seen:
            seen.add(name)
            names.append(name)
    return names


def emit_inc(names, output_path):
    with open(output_path, "w") as f:
        f.write(
            f"// SPDX-FileCopyrightText: {datetime.today().year} RizinOrg <info@rizin.re>\n"
        )
        f.write("// SPDX-License-Identifier: LGPL-3.0-only\n\n")

        f.write("// Generated with sys/gen_il_reg_idx_mapping_from_reg_profile.py\n")
        f.write("static const RzILGlobalIdxMapEntry global_idx[] = {\n")
        f.writelines(
            f'\t{{ "{name}", {idx} }},\n' for idx, name in enumerate(sorted(names))
        )
        f.write("};\n")


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.c> <output.inc>", file=sys.stderr)
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    with open(input_path, "rb") as f:
        source = f.read()

    language = Language(ts_c.language())
    parser = Parser(language)
    tree = parser.parse(source)
    root = tree.root_node

    value_node = find_get_reg_profile_value(root, source)
    if value_node is None:
        print("Could not find .get_reg_profile assignment", file=sys.stderr)
        sys.exit(1)

    func_name = extract_identifier(value_node, source)
    if func_name is None:
        print("Could not extract function name from .get_reg_profile", file=sys.stderr)
        sys.exit(1)

    func = find_function_by_name(root, source, func_name)
    if func is None:
        print(f"Function {func_name} not found. Try to move the functio to the top of the file and run again.", file=sys.stderr)
        sys.exit(1)

    profile = extract_profile_string(func, source)
    if profile is None:
        print("Could not extract register profile string", file=sys.stderr)
        sys.exit(1)

    names = parse_register_names(profile)
    emit_inc(names, output_path)
    print(f"Wrote {len(names)} register defines to {output_path}")


if __name__ == "__main__":
    main()
