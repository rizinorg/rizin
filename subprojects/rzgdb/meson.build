project('rzw32dbg_wrap', 'c')

cc = meson.get_compiler('c')

if cc.has_argument('--std=gnu99')
  add_project_arguments('--std=gnu99', language: ['c'])
elif cc.has_argument('--std=c99')
  add_project_arguments('--std=c99', language: ['c'])
endif

gdb_files = [
  'src/arch.c',
  'src/common.c',
  'src/packet.c',
  'src/utils.c',
  'src/libgdbr.c',

  'src/gdbclient/core.c',
  'src/gdbclient/responses.c',
  'src/gdbclient/xml.c',

  'src/gdbserver/core.c',
]

gdb_inc = [
  include_directories(
    './include',
    './include/gdbclient',
    './include/gdbserver'
  )
]

rz_util_dep = dependency('rz_util')
rz_cons_dep = dependency('rz_cons')
rz_socket_dep = dependency('rz_socket')

librzgdb = static_library('rzgdb', gdb_files,
  include_directories: gdb_inc,
  dependencies: [rz_util_dep, rz_cons_dep, rz_socket_dep],
  implicit_include_directories: false
)

gdb_dep = declare_dependency(
  link_with: librzgdb,
  include_directories: gdb_inc
)
meson.override_dependency('rzgdb', gdb_dep)
