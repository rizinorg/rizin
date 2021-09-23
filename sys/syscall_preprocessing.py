#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

""" Portable python script to preprocess syscall/d files """

import re
import sys

with open(sys.argv[1], encoding="utf8") as inf:
    with open(sys.argv[2], "w", encoding="utf8") as outf:
        for line in inf:
            if not line.startswith("_") and "=" in line:
                arr = re.split("=|,", line)
                print("%s.%s=%s" % (arr[1], arr[2], arr[0]), file=outf)
            print(line, file=outf, end="")
