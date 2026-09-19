#!/usr/bin/env python3

r"""
This script kills the http.server launched by http_server.py.

"""

import sys
import psutil

for p in psutil.process_iter(["cmdline"]):
    try:
        if "python3 -m http.server" in " ".join(p.cmdline()):
            p.kill()
            print("Killed http.server")
            sys.exit(0)
    except psutil.AccessDenied:
        pass

print("ERROR: http.server process not found")
sys.exit(1)
