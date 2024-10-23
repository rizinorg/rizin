#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

""" Portable python script to execute git -C (even on system where -C is not available) """

import os
import subprocess
import sys


def isCArgSupported(executable, path):
    try:
        subprocess.run(
            [executable, "-C", path, "status"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def simple_git_execution(args, output_path=None):
    try:
        called = subprocess.run(args, check=True, stdout=subprocess.PIPE)
        with open(output_path, "w", encoding="utf8") as f:
            f.write(called.stdout.decode("utf8").strip())
        sys.exit(called.returncode)
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)


def parse():
    if len(sys.argv) <= 3:
        print(
            "Usage: {} <git_executable_path> <repo_path> <output_path> [git_args...]".format(
                sys.argv[0]
            )
        )
        sys.exit(1)

    git_exe = sys.argv[1]
    repo_path = sys.argv[2]
    output_path = sys.argv[3]
    args = sys.argv[4:]

    return git_exe, repo_path, output_path, args


def main():
    git_exe, repo_path, output_path, args = parse()

    if isCArgSupported(git_exe, repo_path):
        simple_git_execution([git_exe, "-C", repo_path] + args, output_path=output_path)
    else:
        out_abs_path = os.path.abspath(output_path)
        os.chdir(repo_path)
        simple_git_execution([git_exe] + args, out_abs_path)


if __name__ == "__main__":
    main()
