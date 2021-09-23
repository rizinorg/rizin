#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

""" Python script to execute tree-sitter generate in the right output folder,
necessary because tree-sitter generate does not allow to specify it """

import os
import subprocess
import sys


def parse():
    if len(sys.argv) <= 3:
        print(
            "Usage: {} <tree-sitter-path> <output-dir> <grammar.js>".format(sys.argv[0])
        )
        sys.exit(1)

    tree_sitter_exe = sys.argv[1]
    output_dir = sys.argv[2]
    grammar_js = sys.argv[3]

    return tree_sitter_exe, output_dir, grammar_js


def main():
    tree_sitter_exe, output_dir, grammar_js = parse()

    grammar_js = os.path.abspath(grammar_js)
    output_dir = os.path.abspath(output_dir)
    tree_sitter_exe = os.path.abspath(tree_sitter_exe)

    subprocess.run(
        [tree_sitter_exe, "generate", grammar_js], check=True, cwd=output_dir
    )


if __name__ == "__main__":
    main()
