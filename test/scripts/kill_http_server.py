#!/usr/bin/env python3

r"""
This script kills the http.server launched by http_server.py.

"""

import sys
import psutil

for p in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
    try:
        if sys.platform == "darwin":
            print(p.pid, p.name(), p.exe(), p.cmdline())
        if "python3 -m http.server" in " ".join(p.cmdline()):
            p.kill()
            print("Killed http.server")
            sys.exit(0)
    except psutil.AccessDenied:
        pass

print("ERROR: http.server process not found")
sys.exit(1)
