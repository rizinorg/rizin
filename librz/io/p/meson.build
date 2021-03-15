io_plugins = [
  'ar',
  'fd',
  'bfdbg',
  'bochs',
  'debug',
  'default',
  'gdb',
  'gprobe',
  'gzip',
  'http',
  'ihex',
  'mach',
  'malloc',
  'null',
  'procpid',
  'ptrace',
  'qnx',
  'rzk',
  'rzpipe',
  'rzweb',
  'rap',
  'self',
  'shm',
  'sparse',
  'tcp',
  'winkd',
  'winedbg',
  'zip'
]

if host_machine.system() == 'windows'
  io_plugins += [
    'windbg',
    'w32dbg',
    'w32',
  ]
endif

io_ar_sources = files(
  'io_ar.c',
)

io_ar_deps = [
  ar_dep,
]

io_fd_sources = files(
  'io_fd.c',
)

io_fd_deps = [
  rz_cons_dep,
]

io_bfdbg_sources = files(
  'io_bfdbg.c',
)

io_bochs_sources = files(
  'io_bochs.c',
)

io_bochs_deps = [
  bochs_dep,
]

io_debug_sources = files(
  'io_debug.c',
)

io_debug_deps = [
  rz_cons_dep,
  rz_socket_dep,
]
if host_machine.system() == 'windows'
  io_debug_deps += [
    w32dbg_wrap_dep
  ]
endif

io_default_sources = files(
  'io_default.c',
)

io_gdb_sources = files(
  'io_gdb.c',
)

io_gdb_deps = [
  gdb_dep,
]

io_gprobe_sources = files(
  'io_gprobe.c',
)

io_gzip_sources = files(
  'io_gzip.c',
)

io_http_sources = files(
  'io_http.c',
  '../io_memory.c',
)

io_http_deps = [
  rz_socket_dep,
]

io_ihex_sources = files(
  'io_ihex.c',
)

io_mach_sources = files(
  'io_mach.c',
)

io_malloc_sources = files(
  'io_malloc.c',
  '../io_memory.c',
)

io_null_sources = files(
  'io_null.c',
)

io_procpid_sources = files(
  'io_procpid.c',
)

io_ptrace_sources = files(
  'io_ptrace.c',
)

io_qnx_sources = files(
  'io_qnx.c',
)

io_qnx_deps = [
  qnx_dep,
]

io_rzk_sources = files(
  'io_rzk.c',
)
if host_machine.system() == 'linux' or host_machine.system() == 'android'
  io_rzk_sources += files(
    'io_rzk_linux.c',
  )
elif host_machine.system() == 'windows'
  io_rzk_sources += files(
    'io_rzk_windows.c',
  )
endif

io_rzpipe_sources = files(
  'io_rzpipe.c',
)

io_rzpipe_deps = [
  rz_socket_dep,
]

io_rzweb_sources = files(
  'io_rzweb.c',
)

io_rzweb_deps = [
  rz_socket_dep,
]

io_rap_sources = files(
  'io_rap.c',
)

io_rap_deps = [
    rz_socket_dep,
]

io_self_sources = files(
  'io_self.c',
)

io_shm_sources = files(
  'io_shm.c',
)

io_sparse_sources = files(
  'io_sparse.c',
)

io_tcp_sources = files(
  'io_tcp.c',
  '../io_memory.c',
)

io_tcp_deps = [
  rz_socket_dep,
]

io_w32_sources = files(
  'io_w32.c',
)

io_w32dbg_sources = files(
  'io_w32dbg.c',
)

if host_machine.system() == 'windows'
  io_w32dbg_deps = [
    w32dbg_wrap_dep
  ]
endif

io_winkd_sources = files(
  'io_winkd.c',
)

io_winkd_deps = [
  winkd_dep,
  rz_cons_dep,
]

io_windbg_sources = files(
  'io_windbg.c',
)

io_winedbg_sources = files(
  'io_winedbg.c',
)

io_winedbg_deps = [
  rz_socket_dep,
]

io_zip_sources = files(
  'io_zip.c',
)

io_zip_deps = [
  libzip_dep,
]
