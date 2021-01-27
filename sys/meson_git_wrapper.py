#!/usr/bin/env python

""" Portable python script to execute git -C (even on system where -C is not available) """

import os
import sys
import subprocess

if len(sys.argv) <= 3:
    print('Usage: %s <git_executable_path> <repo_path> [git_args...]')
    sys.exit(1)

git_exe = sys.argv[1]
repo_path = sys.argv[2]
args = sys.argv[3:]

def isCArgSupported(git_exe, repo_path):
    r = subprocess.run([git_exe, '-C', repo_path, 'status'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return r.returncode == 0

if isCArgSupported(git_exe, repo_path):
    called = subprocess.run([git_exe, '-C', repo_path] + args)
    sys.exit(called.returncode)
else:
    os.chdir(repo_path)
    called = subprocess.run([git_exe] + args)
    sys.exit(called.returncode)
