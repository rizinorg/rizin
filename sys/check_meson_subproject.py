#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only
#
# This script is necessary to make sure people notice a subproject has been
# changed and need to be updated. Meson does not warn you now (0.56.0)

""" Portable python script to check if subproject is up-to-date and warn if not """

import filecmp
import os
import sys

subproject = sys.argv[1]
meson_root = os.environ["MESON_SOURCE_ROOT"]

subproject_filename = os.path.join(meson_root, "subprojects", subproject + ".wrap")

try:
    with open(subproject_filename, "r") as f:

        is_wrap_git = False
        revision = None
        directory = subproject
        patch_directory = subproject
        for l in f:
            if "wrap-git" in l:
                is_wrap_git = True
            elif "wrap-file" in l:
                is_wrap_file = True
            elif l.startswith("revision"):
                revision = l.split("=")[1].strip()
            elif l.startswith("directory"):
                directory = l.split("=")[1].strip()
            elif l.startswith("patch_directory"):
                patch_directory = l.split("=")[1].strip()

        if is_wrap_git:
            if not revision:
                sys.exit(0)

            subproject_dir = os.path.join(meson_root, "subprojects", directory)
            subproject_git_dir = os.path.join(subproject_dir, ".git")
            if os.path.isdir(subproject_dir) and os.path.isdir(subproject_git_dir):
                with open(os.path.join(subproject_git_dir, "HEAD"), "r") as f:
                    head = f.read().strip()
                if head != revision:
                    sys.exit(1)

        if not patch_directory:
            sys.exit(0)

        subproject_dir = os.path.join(meson_root, "subprojects", directory)
        patch_subproject_dir = os.path.join(
            meson_root, "subprojects", "packagefiles", patch_directory
        )
        if os.path.isdir(patch_subproject_dir) and os.path.isdir(subproject_dir):
            for f in os.listdir(patch_subproject_dir):
                subproject_f = os.path.join(subproject_dir, f)
                subproject_p_f = os.path.join(patch_subproject_dir, f)
                if not os.path.isfile(subproject_f):
                    sys.exit(1)

                if not filecmp.cmp(subproject_p_f, subproject_f):
                    sys.exit(1)

        sys.exit(0)
except FileNotFoundError:
    sys.exit(0)
