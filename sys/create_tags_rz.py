#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

""" Portable python script to create tags.rz file from a list of files """

import os
from sys import argv

for fname in argv[1:]:
    with open(fname) as f:
        text = " ".join(f.read().splitlines())
    print("ft %s %s" % (os.path.basename(fname), text))
