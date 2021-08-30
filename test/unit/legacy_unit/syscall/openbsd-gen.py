#!/usr/bin/env python
# Auto-generate rizin syscall profile for OpenBSD from syscall.h
# (c) Edd Barrett 2011

import copy
import sys

with open("/usr/include/sys/syscall.h", "r", encoding="utf8") as f:
    rec = {"name": None, "args": None}
    recs = {}

    for line in f:
        if line.startswith("/* syscall:"):
            # extract syscall name
            openq = line.find('"')
            closeq = line.find('"', openq + 1)
            rec["name"] = line[openq + 1 : closeq]

            # extract number of args
            args = line.find("args:")
            args = args + len("args: ")
            rec["args"] = line[args:].count('"') / 2
        elif line.startswith("#define"):

            if "SYS_MAXSYSCALL" in line:
                continue

            # extract syscall number
            sp = line.split("\t")
            callnum = sp[2].rstrip()

            # check required info is there
            for i in rec:
                if i is None:
                    print("missing info for %s" % str(rec))
                    sys.exit(1)

            recs[int(callnum)] = copy.copy(rec)
            rec = {"name": None, "args": None}
with open("openbsd.c", "w", encoding="utf8") as out:
    out.write('#include "r_syscall.h"\n\n/* syscall-openbsd */\n')
    out.write("RSyscallItem syscalls_openbsd_x86[] = {\n")

    keys = recs.keys()
    for call in keys:
        out.write(
            '  { "%s", 0x80, %d, %d },\n'
            % (recs[call]["name"], call, recs[call]["args"])
        )

    out.write("};\n")
