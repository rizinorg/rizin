tags_rz_sources = [
  'dylib',
  'alloc',
  'time',
  'env',
  'fs',
  'network',
  'threads',
  'process',
  'stdout',
  'string'
]

script = '''#script
import os
from sys import argv
for fname in argv[1:]:
    with open(fname) as f:
        text = ' '.join(f.read().splitlines())
    print('ft %s %s' % (os.path.basename(fname), text))
'''

custom_target('tags.rz',
  input: tags_rz_sources,
  output: 'tags.rz',
  command: [py3_exe, '-c', script, '@INPUT@'],
  capture: true,
  build_by_default: true,
  install: true,
  install_dir: rizin_flags
)
