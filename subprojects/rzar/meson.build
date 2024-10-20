project('rzar', 'c',
  license: 'LGPL-3.0-only',
  meson_version: '>=0.55.0',
)

# handle ar dependency
ar_files = [
  'ar.c'
]

cc = meson.get_compiler('c')

if cc.has_argument('--std=gnu99')
  add_project_arguments('--std=gnu99', language: ['c', 'cpp'])
elif cc.has_argument('--std=c99')
  add_project_arguments('--std=c99', language: ['c', 'cpp'])
endif

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
