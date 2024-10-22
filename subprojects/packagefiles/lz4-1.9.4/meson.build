project('lz4', ['c'],
  license: 'BSD-2-Clause-Patent AND GPL-2.0-or-later',
  version: '1.9.4',
  meson_version: '>=0.55.0',
)

cc = meson.get_compiler('c')

if cc.has_argument('--std=c99')
  add_project_arguments('--std=c99', language: ['c'])
endif

lz4_files = [
  'lib/lz4.c',
]

lz4_inc = [include_directories('lib')]

librzlz4 = library('lz4', lz4_files,
  include_directories: lz4_inc,
  implicit_include_directories: false,
  install: false,
)

lz4_dep = declare_dependency(
  link_with: librzlz4,
  include_directories: lz4_inc,
)
