#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2022 kazarmy <kazarmy@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

import subprocess
import sys

if sys.platform.startswith("win32"):
    timestamp_cmd = ["cmd", "/c", "echo %date%__%time%"]
else:
    timestamp_cmd = [
        "sh",
        "-c",
        '''
        SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(date +%s)}";
        FORMAT="+%Y-%m-%d__%H:%M:%S";
        date -u -d "@$SOURCE_DATE_EPOCH" "$FORMAT" 2>/dev/null ||
        date -u -r  "$SOURCE_DATE_EPOCH" "$FORMAT" 2>/dev/null ||
        date -u "$FORMAT"''',
    ]
# getting the timestamp must succeed
timestamp = (
    subprocess.run(timestamp_cmd, check=True, capture_output=True)
    .stdout.decode("UTF-8")
    .strip()
)

rz_build_h = """#ifndef RZ_BUILD_H
#define RZ_BUILD_H

#define RZ_BIRTH "@RZ_BIRTH@"
#endif
""".replace(
    "@RZ_BIRTH@", timestamp
)

f = open("rz_build.h", "w")
f.write(rz_build_h)
f.close()
