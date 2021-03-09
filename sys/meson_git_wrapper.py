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


def simple_git_execution(args):
    try:
        called = subprocess.run(args, check=True)
        sys.exit(called.returncode)
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)


def parse():
    if len(sys.argv) <= 3:
        print("Usage: %s <git_executable_path> <repo_path> [git_args...]")
        sys.exit(1)

    git_exe = sys.argv[1]
    repo_path = sys.argv[2]
    args = sys.argv[3:]

    return git_exe, repo_path, args


def main():
    git_exe, repo_path, args = parse()

    if isCArgSupported(git_exe, repo_path):
        simple_git_execution([git_exe, "-C", repo_path] + args)
    else:
        os.chdir(repo_path)
        simple_git_execution([git_exe] + args)


if __name__ == "__main__":
    main()
