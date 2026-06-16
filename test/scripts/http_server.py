#!/usr/bin/env python3

r"""
This script launches python -m http.server in a subprocess and waits until it's ready to receive
a new connection.

"""

import http.client
import subprocess


def main():
    subprocess.run(
        "python3 -m http.server 9000 --bind 127.0.0.1 --directory www &",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    while True:
        try:
            http.client.HTTPConnection("127.0.0.1", 9000, timeout=5).connect()
        except:
            continue
        break


if __name__ == "__main__":
    main()
