#!/usr/bin/env python
#
# This script is necessary to make sure people notice a subproject has been
# changed and need to be updated. Meson does not warn you now (0.56.0)

""" Portable python script to check if subproject is up-to-date and warn if not """

import sys
import os

subproject = sys.argv[1]
meson_root = os.environ['MESON_SOURCE_ROOT']

subproject_filename = os.path.join(meson_root, 'subprojects', subproject + '.wrap')

f = open(subproject_filename, 'r')

is_wrap_git = False
revision = None
directory = subproject
for l in f:
    if 'wrap-git' in l:
        is_wrap_git = True
    elif l.startswith('revision'):
        revision = l.split('=')[1].strip()
    elif l.startswith('directory'):
        directory = l.split('=')[1].strip()

if not is_wrap_git or not revision:
    sys.exit(0)

subproject_dir = os.path.join(meson_root, 'subprojects', directory)
if os.path.isdir(subproject_dir):
    head = open(os.path.join(subproject_dir, '.git', 'HEAD'), 'r').read().strip()
    if head != revision:
        sys.exit(1)

sys.exit(0)