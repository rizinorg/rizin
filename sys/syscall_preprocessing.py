#!/usr/bin/env python

""" Portable python script to preprocess syscall/d files """

import re
import sys

inf = open(sys.argv[1])
outf = open(sys.argv[2], "w")
for line in inf:
    if not line.startswith("_") and "=" in line:
        arr = re.split("=|,", line)
        print("%s.%s=%s" % (arr[1], arr[2], arr[0]), file=outf)
    print(line, file=outf, end="")
inf.close()
outf.close()
