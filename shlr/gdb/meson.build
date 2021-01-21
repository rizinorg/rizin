# handle gdb dependency
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
  platform_inc,
  include_directories(
    './include',
    './include/gdbclient',
    './include/gdbserver'
  )
]

librzgdb = static_library('r2gdb', gdb_files,
  include_directories: gdb_inc,
  dependencies: [rz_util_dep, rz_cons_dep, rz_socket_dep],
  implicit_include_directories: false
)

gdb_dep = declare_dependency(
  link_with: librzgdb,
  include_directories: gdb_inc
)
