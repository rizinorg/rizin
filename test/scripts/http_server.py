#!/usr/bin/env python3

r"""
This script launches python -m http.server in a subprocess and waits until it's ready to receive
a new connection.

"""

import http.client
import subprocess
import sys


def main():
    args = "-m http.server 9000 --bind 127.0.0.1"
    if sys.platform == "win32":
        cmd = "start /B pythonw3 " + args
    else:
        cmd = "python3 " + args + " &"
    subprocess.run(
        cmd,
        shell=True,
        check=True,
        cwd="www",
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    while True:
        try:
            http.client.HTTPConnection("127.0.0.1", 9000, timeout=5).connect()
        except (ConnectionRefusedError, TimeoutError):
            continue
        break


if __name__ == "__main__":
    main()
