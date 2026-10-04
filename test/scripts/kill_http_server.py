#!/usr/bin/env python3

r"""
This script kills the http.server launched by http_server.py.

"""

import re
import sys
import psutil

http_server_killed = 0
for p in psutil.process_iter(["cmdline"]):
    try:
        if re.search(r"[Pp]ythonw?3? -m http\.server 9000", " ".join(p.cmdline())):
            p.kill()
            http_server_killed += 1
            if http_server_killed == 2:
                # Not stopping at 1 since what got killed might have been the
                # shell that ran the server
                break
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass

if http_server_killed > 0:
    print("Killed http.server")
    sys.exit(0)
else:
    print("ERROR: http.server process not found")
    sys.exit(1)
