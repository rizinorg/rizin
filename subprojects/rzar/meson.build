project('rzar', 'c',
  license: 'LGPL-3.0-only',
  meson_version: '>=0.55.0',
  default_options: [
    'c_std=c99',
  ]
)

# handle ar dependency
ar_files = [
  'ar.c'
]

rz_util_dep = dependency('rz_util')
ar_inc = [include_directories(['.'])]

librzar = static_library('rzar', ar_files,
  dependencies: [rz_util_dep],
  include_directories: ar_inc,
  implicit_include_directories: false
)

ar_dep = declare_dependency(
  link_with: librzar,
  include_directories: ar_inc
)
meson.override_dependency('rzar', ar_dep)
