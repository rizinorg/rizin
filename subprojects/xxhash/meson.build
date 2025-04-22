project('xxhash', 'c',
  # library files are BSD licensed. xxhsum utility is GPL licensed.
  version : '0.6.5',
  license: 'BSD-2-Clause AND GPL-2.0-or-later',
  meson_version: '>=0.55.0',
)

cc = meson.get_compiler('c')

if cc.has_argument('--std=c99')
  add_project_arguments('--std=c99', language: ['c'])
endif

inc = include_directories('.')

libxxhash = library('xxhash',
    ['xxhash.c'],
    include_directories : inc,
    version : meson.project_version(),
    install : false)

xxhash_dep = declare_dependency(
    include_directories : inc,
    link_with : libxxhash)
