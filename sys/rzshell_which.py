#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

import os
import subprocess
import sys

current_path = os.path.dirname(os.path.realpath(__file__))
shell_finder_py = os.path.join(
    current_path, "..", "librz", "core", "cmd_descs", "rzshell_which.py"
)

subprocess.run([shell_finder_py] + sys.argv[1:], check=False)
