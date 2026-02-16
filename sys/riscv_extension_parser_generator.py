#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2024-2026 moste00 <ubermenchun@gmail.com>
# SPDX-License-Identifier: BSD-3-Clause

"""
RISC-V Extension Trie-Based Parser Generator

Given a list of RISCV_FeatureStdExt* enums, generates C code that:
1. Parses extension names using a trie data structure
2. ORs the corresponding enum value with a running accumulator
3. Includes an ASCII art tree visualization of the trie
4. Annotates branches with parse state
5. Uses macros to reduce boilerplate
"""

import sys
import os
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class TrieNode:
    children: Dict[str, "TrieNode"]
    enum_name: Optional[str] = None

    def __init__(self):
        self.children = {}
        self.enum_name = None


class Trie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, ext_name: str, enum_name: str):
        """Insert an extension name into the trie"""
        node = self.root
        for char in ext_name:
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        node.enum_name = enum_name

    def generate_ascii_tree(
        self,
        node: Optional[TrieNode] = None,
        prefix: str = "",
        is_last: bool = True,
        char: str = "ROOT",
    ) -> List[str]:
        """Generate ASCII tree representation"""
        if node is None:
            node = self.root

        lines = []

        # Current node
        connector = "└── " if is_last else "├── "
        if char == "ROOT":
            line = "ROOT"
        else:
            line = prefix + connector + char
            if node.enum_name:
                line += f"  [{node.enum_name}]"
        lines.append(line)

        # Children
        if node.children:
            sorted_children = sorted(node.children.items())
            for i, (ch, child) in enumerate(sorted_children):
                is_last_child = i == len(sorted_children) - 1

                if char == "ROOT":
                    child_prefix = ""
                else:
                    extension = "    " if is_last else "│   "
                    child_prefix = prefix + extension

                lines.extend(
                    self.generate_ascii_tree(child, child_prefix, is_last_child, ch)
                )

        return lines


def parse_enum_definitions(enum_text: str) -> List[Tuple[str, str]]:
    """Parse enum definitions and extract extension names"""
    results = []

    for line in enum_text.strip().split("\n"):
        line = line.strip()
        if not line or not line.startswith("RISCV_FeatureStdExt"):
            continue

        # Remove trailing comma and split
        enum_name = line.rstrip(",").split("=")[0].strip()

        # Extract extension name (part after FeatureStdExt)
        if "FeatureStdExt" in enum_name:
            ext_name = enum_name.split("FeatureStdExt")[1].lower()
            if ext_name:  # Skip empty names
                results.append((ext_name, enum_name))

    return results


# pylint: disable=too-many-statements
def generate_c_code(trie: Trie, extensions: List[Tuple[str, str]]) -> str:
    """Generate the complete C parsing function"""

    # Generate ASCII tree
    tree_lines = trie.generate_ascii_tree()
    tree_comment = "\n".join(f" * {line}" for line in tree_lines)

    # Generate function body
    code_lines = []

    def generate_node_code(node: TrieNode, depth: int, path: str) -> List[str]:
        """Recursively generate parsing code for trie nodes"""
        lines = []
        indent = "    " * depth

        if not node.children:
            # Leaf node
            if node.enum_name:
                lines.append(f"{indent}STOP_WITH_MATCH({node.enum_name});")
            else:
                lines.append(f"{indent}STOP_WITHOUT_MATCH();")
            return lines

        # Non-leaf node - check if this is also a valid end point
        if node.enum_name:
            lines.append(f"{indent}STOP_WITH_MATCH({node.enum_name});")
            lines.append("")

        # Process children - add state comment only before branching
        sorted_children = sorted(node.children.items())
        expected_chars = [c for c, _ in sorted_children]
        expected_str = "".join(expected_chars)

        lines.append(f"{indent}/* State: '{path}' expecting [{expected_str}] */")

        for i, (char, child) in enumerate(sorted_children):
            if i == 0:
                lines.append(f"{indent}if (*p == '{char}') {{")
            else:
                lines.append(f"{indent}}} else if (*p == '{char}') {{")

            lines.append(f"{indent}    p++;")
            lines.extend(generate_node_code(child, depth + 1, path + char))

        lines.append(f"{indent}}} else {{")

        # In the else branch, we have an unexpected character
        if node.enum_name:
            # There was a valid match at the previous state
            lines.append(f"{indent}    /* Unexpected char, but '{path}' was valid */")
            lines.append(f"{indent}    STOP_WITH_MATCH({node.enum_name});")
        else:
            # No valid match at this point
            lines.append(f"{indent}    /* Unexpected char at '{path}', no match */")
            lines.append(f"{indent}    STOP_WITHOUT_MATCH();")

        lines.append(f"{indent}}}")

        return lines

    # Start with root's children
    if trie.root.children:
        code_lines.extend(generate_node_code(trie.root, 1, ""))
        code_lines.append("")
        code_lines.append("    /* Should not reach here */")
        code_lines.append("    STOP_WITHOUT_MATCH();")

    # Build the complete function
    full_code = "// SPDX-FileCopyrightText: 2024-2026 moste00 <ubermenchun@gmail.com>\n"
    full_code += "// " + "SPDX" + "-License-Identifier: BSD-3-Clause"
    full_code += "\n\n/*\n"
    full_code += " * \n \n *********************************************** AUTO-GENERATED CODE, DO NOT EDIT BY HAND! "
    full_code += " * *********************************************** \n \n"
    full_code += " * RISC-V Extension Parser Using a Trie trick\n"
    full_code += (
        " * Generated from arch/RISCV/RISCVGenSubtargetInfo.inc in Capstone sources \n"
    )
    full_code += " * \n"
    full_code += " * This function parses a single RISC-V extension name and ORs the corresponding\n"
    full_code += " * feature flags with an accumulator 'mode'.\n"
    full_code += " * \n"
    full_code += " * Trie Diagram:\n"
    full_code += tree_comment + "\n"
    full_code += " */\n\n"

    flags_defs = "\n".join(
        [f"#define {member} {i} \n" for i, (_, member) in enumerate(extensions)]
    )
    full_code += flags_defs

    full_code += "/* Parse result enum - indicates why parsing stopped */\n"
    full_code += "typedef enum {\n"
    full_code += (
        "    RISCV_EXT_PARSE_END_OF_STRING,           "
        "/* Stopped at '\\0' - valid extension found */\n"
    )
    full_code += (
        "    RISCV_EXT_PARSE_STOPPED_AT_NUMBER,       "
        "/* Stopped at a digit - valid extension found */\n"
    )
    full_code += (
        "    RISCV_EXT_PARSE_STOPPED_AT_UNDERSCORE,   "
        "/* Stopped at '_' - valid extension found */\n"
    )
    full_code += (
        "    RISCV_EXT_PARSE_STOPPED_AT_UNEXPECTED,   "
        "/* Stopped at unexpected char - valid extension found */\n"
    )
    full_code += (
        "    RISCV_EXT_PARSE_NO_MATCH_END_OF_STRING,  "
        "/* Reached '\\0' - no valid extension */\n"
    )
    full_code += (
        "    RISCV_EXT_PARSE_NO_MATCH_NUMBER,         "
        "/* Hit number - no valid extension at this point */\n"
    )
    full_code += (
        "    RISCV_EXT_PARSE_NO_MATCH_UNDERSCORE,     "
        "/* Hit underscore - no valid extension at this point */\n"
    )
    full_code += (
        "    RISCV_EXT_PARSE_NO_MATCH_UNEXPECTED,     "
        "/* Hit unexpected char - no valid extension */\n"
    )
    full_code += "} riscv_extension_parse_result_t;\n\n"

    full_code += "/* Macro: Stop parsing with a matched extension */\n"
    full_code += "#ifndef MATCH_CALLBACK\n"
    full_code += "#define MATCH_CALLBACK(feature_enum)\n"
    full_code += "#endif\n\n"
    full_code += "#ifndef FINI_EXT_CALLBACKS\n"
    full_code += "#define FINI_EXT_CALLBACKS()\n"
    full_code += "#endif\n\n"
    full_code += "#define STOP_WITH_MATCH(feature_enum) \\\n"
    full_code += "    do { \\\n"
    full_code += "        MATCH_CALLBACK(feature_enum); \\\n"
    full_code += "        *idx = (size_t)(p - ext_name); \\\n"
    full_code += "        *mode = feature_enum; \\\n"
    full_code += "        FINI_EXT_CALLBACKS(); \\\n"
    full_code += "        if (*p == '\\0') { \\\n"
    full_code += "            return RISCV_EXT_PARSE_END_OF_STRING; \\\n"
    full_code += "        } else if (*p >= '0' && *p <= '9') { \\\n"
    full_code += "            return RISCV_EXT_PARSE_STOPPED_AT_NUMBER; \\\n"
    full_code += "        } else if (*p == '_') { \\\n"
    full_code += "            return RISCV_EXT_PARSE_STOPPED_AT_UNDERSCORE; \\\n"
    full_code += "        } else { \\\n"
    full_code += "            return RISCV_EXT_PARSE_STOPPED_AT_UNEXPECTED; \\\n"
    full_code += "        } \\\n"
    full_code += "    } while (0)\n\n"

    full_code += "/* Macro: Stop parsing without a match */\n"
    full_code += "#define STOP_WITHOUT_MATCH() \\\n"
    full_code += "    do { \\\n"
    full_code += "        *idx = (size_t)(p - ext_name); \\\n"
    full_code += "        if (*p == '\\0') { \\\n"
    full_code += "            return RISCV_EXT_PARSE_NO_MATCH_END_OF_STRING; \\\n"
    full_code += "        } else if (*p >= '0' && *p <= '9') { \\\n"
    full_code += "            return RISCV_EXT_PARSE_NO_MATCH_NUMBER; \\\n"
    full_code += "        } else if (*p == '_') { \\\n"
    full_code += "            return RISCV_EXT_PARSE_NO_MATCH_UNDERSCORE; \\\n"
    full_code += "        } else { \\\n"
    full_code += "            return RISCV_EXT_PARSE_NO_MATCH_UNEXPECTED; \\\n"
    full_code += "        } \\\n"
    full_code += "    } while (0)\n\n"

    full_code += "/**\n"
    full_code += (
        " * Main parse routine: Try to consume a RISC-V extension name "
        "from the architecture string at a given position.\n"
    )
    full_code += " * \n"
    full_code += " * @param arch_str: The full architecture string\n"
    full_code += (
        " * @param idx: Pointer to current index "
        "(will be updated to show consumed length)\n"
    )
    full_code += (
        " * @param mode: Pointer to the feature accumulator "
        "(will be ORed with the feature flag if extension found)\n"
    )
    full_code += " * @return: Parse result indicating why parsing stopped and whether a match was found\n"
    full_code += " * \n"
    full_code += " * Stopping conditions:\n"
    full_code += " *   - '\\0' (end of string)\n"
    full_code += " *   - '0'-'9' (version number)\n"
    full_code += " *   - '_' (extension separator)\n"
    full_code += " *   - Any unexpected character\n"
    full_code += " * \n"
    full_code += " * The function uses a trie-based approach for efficient parsing.\n"
    full_code += " * State comments show the current position in the trie:\n"
    full_code += " *   'abc...' means we've matched 'abc' and are looking for more\n"
    full_code += " *   'abc(!x)' means we've matched 'abc' but encountered unexpected char instead of 'x'\n"
    full_code += " */\n"
    full_code += "#ifndef INIT_EXT_CALLBACKS\n"
    full_code += "#define INIT_EXT_CALLBACKS()\n"
    full_code += "#endif\n\n"
    full_code += "static inline riscv_extension_parse_result_t\n"
    full_code += (
        "try_consume_riscv_ext_from(const char *ext_name, size_t *idx, ut64 *mode)\n"
    )
    full_code += "{\n"
    full_code += "    if (!ext_name || !idx || !mode) {\n"
    full_code += "        return RISCV_EXT_PARSE_NO_MATCH_END_OF_STRING;\n"
    full_code += "    }\n"
    full_code += "    \n"
    full_code += "    INIT_EXT_CALLBACKS();\n"
    full_code += "    const char *p = ext_name + *idx;\n"
    full_code += "    \n"
    full_code += "    if (*p == '\\0') {\n"
    full_code += "        return RISCV_EXT_PARSE_NO_MATCH_END_OF_STRING;\n"
    full_code += "    }\n\n"

    full_code += "\n".join(code_lines)
    full_code += "\n}\n\n"

    full_code += "/* Cleanup macros */\n"
    full_code += "#undef STOP_WITH_MATCH\n"
    full_code += "#undef STOP_WITHOUT_MATCH\n\n"

    # Add example usage
    full_code += "/* Example usage:\n"
    full_code += " *\n"
    full_code += " * ut64 features = 0;\n"
    full_code += " * riscv_extension_parse_result_t result;\n"
    full_code += " * size_t idx = 0;\n"
    full_code += ' * const char *arch = "i2p1_m2p0_zicsr";\n'
    full_code += " * \n"
    full_code += ' * // Parse "i" from "i2p1_m2p0_zicsr"\n'
    full_code += " * result = try_consume_riscv_ext_from(arch, &idx, &features);\n"
    full_code += " * // idx is now 1, result is RISCV_EXT_PARSE_STOPPED_AT_NUMBER\n"
    full_code += " * \n"
    full_code += ' * // Skip version "2p1_" by setting idx = 5\n'
    full_code += " * idx = 5; // now at 'm'\n"
    full_code += " * result = try_consume_riscv_ext_from(arch, &idx, &features);\n"
    full_code += " * // idx is now 6, result is RISCV_EXT_PARSE_STOPPED_AT_NUMBER\n"
    full_code += " * \n"
    full_code += ' * // Skip version "2p0_" by setting idx = 10\n'
    full_code += " * idx = 10; // now at 'z'\n"
    full_code += " * result = try_consume_riscv_ext_from(arch, &idx, &features);\n"
    full_code += " * // idx is now 15, result is RISCV_EXT_PARSE_END_OF_STRING\n"
    full_code += " */\n"

    return full_code


def main():

    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input_header> <output_file>")
        sys.exit(1)

    input_header = sys.argv[1]
    output_file = sys.argv[2]

    if not os.path.exists(input_header):
        print(f"Error: Input file {input_header} not found")
        sys.exit(1)

    with open(input_header, "r", encoding="utf-8") as f:
        enum_text = "\n".join(
            [line for line in f if line.strip().startswith("RISCV_FeatureStdExt")]
        )

    # Parse enum definitions
    extensions = parse_enum_definitions(enum_text)

    if not extensions:
        print(f"Warning: No extensions found in {input_header}")

    # Build trie
    trie = Trie()
    for ext_name, enum_name in extensions:
        trie.insert(ext_name, enum_name)

    # Generate C code
    c_code = generate_c_code(trie, extensions)

    # Output to file
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(c_code)


if __name__ == "__main__":
    main()
