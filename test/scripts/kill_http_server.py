#!/usr/bin/env python3

r"""
This script kills the http.server launched by http_server.py.

"""

import psutil

for p in psutil.process_iter(['cmdline']):
    if "python3 -m http.server" in " ".join(p.cmdline()):
        p.kill()
        break
