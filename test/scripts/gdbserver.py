#!/usr/bin/env python3

r"""
This script launches gdbserver in a subprocess and waits until it's ready to receive
a new connection since it's not possible to know if gdbserver is ready to connect
to with `oodf` after executing it as a background task using `& !gdbserver ...`.
Example usage in a test:

  !scripts/gdbserver.py --port PORT --binary bins/elf/analysis/calls_x64

It's important to note that PORT has to be unique for each test since all tests
run in parallel and may attempt to open the same port at the same time.

"""

import argparse
import subprocess
import sys


def execute(cmd):
    popen = subprocess.Popen(cmd, stderr=subprocess.PIPE, universal_newlines=True)
    for stderr_line in iter(popen.stderr.readline, ""):
        yield stderr_line


def main():
    parser = argparse.ArgumentParser(
        description="Run gdbserver in a new process with the given arguments and exit "
        "once gdbserver is ready for new connections"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default="1234")
    parser.add_argument("--binary", default="")
    parser.add_argument(
        "--output",
        default=False,
        action="store_true",
        help="print stdout output from gdbserver",
    )
    args = parser.parse_args()

    while True:
        for output in execute(
            ["gdbserver", "{}:{}".format(args.host, args.port), args.binary]
        ):
            if args.output:
                print(output)
            # Exit once gdbserver is ready for connections
            if "Listening on port" in output:
                sys.exit(0)
            # gdbserver might fail to start if the port is taken
            if "Can't bind address" in output:
                print(output)
                sys.exit(1)


if __name__ == "__main__":
    main()
