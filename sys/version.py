#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

""" Portable python script to read version from meson.build until meson provides a proper way """

import os
import sys

meson_file = "meson.build"
if len(sys.argv) > 1:
    meson_file = os.path.join(sys.argv[1], meson_file)

with open(meson_file, "r") as f:
    # Read only first 10 lines of the meson file, looking for 'version: ' string
    for i in range(10):
        fields = [x.strip() for x in f.readline().strip().split(":")]
        if fields[0] == "version":
            fields = fields[1].split("'")
            sys.stdout.write(fields[1] + "\n")
            sys.exit(0)

sys.exit(1)
