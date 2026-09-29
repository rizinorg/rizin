#!/usr/bin/env python3

import argparse
import re
import sys
from pathlib import Path

from tree_sitter import Language, Parser


def get_text(node, source_bytes):
    return source_bytes[node.start_byte : node.end_byte].decode(
        "utf-8", errors="replace"
    )


def collect_nodes(root, node_type):
    """Depth-first collection of all nodes of a given type."""
    result = []

    def walk(node):
        if node.type == node_type:
            result.append(node)
        for child in node.children:
            walk(child)

    walk(root)
    return result


def parse_define(source_bytes, node):
    """
    Parse a tree-sitter preproc_def / preproc_function_def node.
    Returns (name, body) where body has backslash-continuations collapsed.
    """
    name = body = None
    for child in node.children:
        if child.type == "identifier":
            name = get_text(child, source_bytes)
        elif child.type in ("preproc_arg", "preproc_params"):
            body = get_text(child, source_bytes)
        elif child.type == "preproc_def":
            # nested? shouldn't happen, but recurse just in case
            pass

    if name and body is not None:
        # collapse line continuations and extra whitespace
        body = re.sub(r"\\\s*\n\s*", " ", body).strip()
    return name, body


def extract_string_literal(text):
    """Extract the raw string contents from a C string literal token."""
    text = text.strip()
    if not text:
        return None
    # Handle concatenated strings: "foo" "bar"
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', text)
    if parts:
        return "".join(parts)
    return None


def tokenize_macro_body(body):
    """
    Tokenize a macro body into top-level comma-separated items.
    Each item is the raw text between commas at the top nesting level.
    """
    items = []
    depth = 0
    current = []
    in_string = False
    escape = False

    for ch in body:
        if in_string:
            current.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            current.append(ch)
            continue

        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth -= 1

        if ch == "," and depth == 0:
            items.append("".join(current).strip())
            current = []
        else:
            current.append(ch)

    if current:
        tail = "".join(current).strip()
        if tail:
            items.append(tail)
    return items


def is_macro_name(name):
    """Heuristic: all-uppercase identifiers are treated as macros."""
    return name.isupper() and name.isidentifier()


def expand_macro_item(item_text, macros, visited=None):
    """
    Expand one macro body item into a list of register name strings.
    Handles string literals, NULL, and nested macro references.
    """
    if visited is None:
        visited = set()
    if item_text.upper() == "NULL":
        return []
    s = extract_string_literal(item_text)
    if s is not None:
        return [s]

    # It might be an unquoted identifier that is a macro.
    if item_text in macros and item_text not in visited:
        visited.add(item_text)
        body = macros[item_text]
        return expand_macro_body(body, macros, visited.copy())

    # If the item is a macro name (uppercase) but not known, warn and skip.
    if is_macro_name(item_text):
        print(f"warning: unresolved macro '{item_text}'", file=sys.stderr)
        return []
    return []


def expand_macro_body(body, macros, visited=None):
    """Expand a macro body (comma-separated items) into register names."""
    if visited is None:
        visited = set()
    names = []
    for item in tokenize_macro_body(body):
        names.extend(expand_macro_item(item, macros, visited.copy()))
    return names


def find_array_initializer(root, source_bytes, array_name):
    """
    Find a global array declaration named array_name and return its
    initializer_list node, or None.
    """

    def first_identifier(node):
        if node.type == "identifier":
            return get_text(node, source_bytes)
        for c in node.children:
            result = first_identifier(c)
            if result is not None:
                return result
        return None

    def extract_init_list(node):
        for child in node.children:
            if child.type == "initializer_list":
                return child
            if child.type == "initializer":
                for sub in child.children:
                    if sub.type == "initializer_list":
                        return sub
        return None

    for decl in collect_nodes(root, "declaration"):
        # Tree-sitter C wraps the declared object in an init_declarator node.
        init_decls = [c for c in decl.children if c.type == "init_declarator"]
        if not init_decls:
            init_decls = [decl]

        for init_decl in init_decls:
            children = init_decl.children

            # Locate the '=' token.
            eq_idx = None
            for i, c in enumerate(children):
                if c.type == "=":
                    eq_idx = i
                    break
            if eq_idx is None:
                continue

            # The declarator is the last non-specifier child before '='.
            declarator = None
            for c in children[:eq_idx]:
                if c.type not in (
                    "storage_class_specifier",
                    "type_qualifier",
                    "type_identifier",
                    "primitive_type",
                    "sized_type_specifier",
                    "struct_specifier",
                    "enum_specifier",
                    "union_specifier",
                    "typedef",
                ):
                    declarator = c

            if declarator is None:
                continue

            if first_identifier(declarator) != array_name:
                continue

            return extract_init_list(init_decl)

    return None


def extract_names_from_initializer(init_list, source_bytes, macros):
    """Extract register names from an initializer_list AST node."""
    names = []
    for child in init_list.children:
        expr = child
        # initializer -> expression? tree-sitter often wraps it directly
        if len(child.children) == 1 and child.children[0].type in (
            "string_literal",
            "concatenated_string",
            "identifier",
        ):
            expr = child.children[0]

        text = get_text(expr, source_bytes).strip()
        names.extend(expand_macro_item(text, macros))
    return names


def find_reg_bindings_assignments(root, source_bytes):
    """
    Find every assignment of the form <something>->reg_bindings = <array_name>
    inside functions. Returns a set of array names.
    """
    arrays = set()

    for func in collect_nodes(root, "function_definition"):
        for assign in collect_nodes(func, "assignment_expression"):
            children = assign.children
            if len(children) < 3:
                continue
            left = children[0]
            op = children[1]
            right = children[2]

            if get_text(op, source_bytes) != "=":
                continue
            if left.type != "field_expression":
                continue

            # field_expression: argument operator field_identifier
            field_id = None
            arrow_op = None
            for c in left.children:
                if c.type == "field_identifier":
                    field_id = c
                elif c.type == "->":
                    arrow_op = c
            if arrow_op is None or field_id is None:
                continue
            if get_text(field_id, source_bytes) != "reg_bindings":
                continue

            if right.type != "identifier":
                continue
            arrays.add(get_text(right, source_bytes))

    return arrays


def build_global_idx(entries, out_path):
    lines = [
        "// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>",
        "// SPDX-License-Identifier: LGPL-3.0-only",
        "",
        "// Generated with sys/gen_il_reg_idx_mapping_from_reg_binding.py"
        "static const RzILGlobalIdxMapEntry global_idx[] = {",
    ]
    for idx, name in enumerate(entries):
        lines.append(f'\t{{ "{name}", {idx} }},')
    lines.append("};")
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(
        description="Extract register binding arrays from a C file and emit a sorted global_idx map.\
        It searches for the array assigned to `<cfg>->reg_bindings = <array name>`, resolves the macros, and writes the generated table to output file."
    )
    parser.add_argument("input", type=Path, help="Input C source file")
    parser.add_argument("output", type=Path, help="Output C file")
    args = parser.parse_args()

    source_bytes = args.input.read_bytes()

    # Build parser for C
    try:
        import tree_sitter_c as ts_c

        language = Language(ts_c.language())
    except ImportError:
        # Fallback for older tree-sitter-c layout
        from tree_sitter_c import C_LANGUAGE

        language = Language(C_LANGUAGE)
    parser = Parser(language)
    tree = parser.parse(source_bytes)
    root = tree.root_node

    # Collect macros
    macros = {}
    for node in collect_nodes(root, "preproc_def"):
        name, body = parse_define(source_bytes, node)
        if name:
            macros[name] = body

    # Find arrays assigned to ->reg_bindings
    array_names = find_reg_bindings_assignments(root, source_bytes)
    print(array_names)

    # Resolve each array
    all_names = []
    for array_name in array_names:
        init_list = find_array_initializer(root, source_bytes, array_name)
        print(init_list)
        if init_list is None:
            print(f"warning: could not find array '{array_name}'", file=sys.stderr)
            continue
        all_names.extend(
            extract_names_from_initializer(init_list, source_bytes, macros)
        )

    # Deduplicate, sort, and emit
    unique_names = sorted(set(all_names))
    build_global_idx(unique_names, args.output)
    print(f"Wrote {len(unique_names)} entries to {args.output}")


if __name__ == "__main__":
    main()
