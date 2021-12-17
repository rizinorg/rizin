#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only
#
# Script used by meson during the `meson dist` step to create a src tarball
# without .git directories for subprojects

import os
import shutil


def traverse_dir(d):
    for i in os.listdir(d):
        # ignore . and ..
        if i in (".", ".."):
            continue

        fulli = os.path.abspath(os.path.join(d, i))
        # avoid possible loops
        if fulli == d:
            continue

        if i == ".git":
            shutil.rmtree(fulli)
        elif os.path.isdir(fulli):
            traverse_dir(fulli)


if __name__ == "__main__":
    dist_dir = os.path.abspath(os.environ["MESON_DIST_ROOT"])
    traverse_dir(dist_dir)
