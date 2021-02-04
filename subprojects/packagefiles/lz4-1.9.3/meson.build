project('lz4', ['c'],
  license: ['BSD', 'GPLv2'],
  default_options : ['c_std=c99', 'buildtype=release'],
  version: '1.9.3',
  meson_version: '>=0.47.0')

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
