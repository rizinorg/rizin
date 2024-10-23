project('rzqnx', 'c',
  license: 'GPL-2.0-only',
  meson_version: '>=0.55.0',
)

cc = meson.get_compiler('c')

if cc.has_argument('--std=gnu99')
  add_project_arguments('--std=gnu99', language: ['c'])
elif cc.has_argument('--std=c99')
  add_project_arguments('--std=c99', language: ['c'])
endif

qnx_files = [
  'src/core.c',
  'src/packet.c',
  'src/sigutil.c',
  'src/utils.c',
]

rz_util_dep = dependency('rz_util')
rz_socket_dep = dependency('rz_socket')

qnx_inc = [include_directories('include')]

librzqnx = static_library('rzqnx', qnx_files,
  dependencies: [rz_util_dep, rz_socket_dep],
  include_directories: qnx_inc,
  implicit_include_directories: false
)

qnx_dep = declare_dependency(
  link_with: librzqnx,
  include_directories: qnx_inc
)
meson.override_dependency('rzqnx', qnx_dep)
