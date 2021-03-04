#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

""" Portable python script to read version from configure.acr """

import sys

with open(sys.argv[1], "r") as f:
    for l in f:
        if "SDBVER=" in l:
            version = l.strip("\n").split("=")[1]
            sys.stdout.write(version + "\n")
