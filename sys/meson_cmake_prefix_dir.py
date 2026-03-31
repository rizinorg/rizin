#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

"""Python script to workaround issue mesonbuild/meson#9702
(https://github.com/mesonbuild/meson/issues/9702). It returns the relative path
of the prefixdir from the cmake directory."""

import os
import sys


def parse():
    if len(sys.argv) <= 2:
        print("Usage: {} <prefixdir> <cmakedir>".format(sys.argv[0]))
        sys.exit(1)

    prefix_dir = sys.argv[1]
    cmake_dir = sys.argv[2]

    return prefix_dir, cmake_dir


def main():
    prefix_dir, cmake_dir = parse()

    prefix_dir = os.path.abspath(prefix_dir)
    if not os.path.isabs(cmake_dir):
        cmake_dir = os.path.abspath(os.path.join(prefix_dir, cmake_dir))

    # always use linux dir separator, CMake will take care of converting it properly
    relpath = os.path.relpath(prefix_dir, cmake_dir).replace(os.sep, "/")
    print("%s" % (relpath,))


if __name__ == "__main__":
    main()
