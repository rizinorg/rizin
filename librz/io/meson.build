rz_io_sources = [
  'io.c',
  'io_fd.c',
  'io_map.c',
  'io_memory.c',
  'io_cache.c',
  'io_desc.c',
  'io_plugin.c',
  'ioutils.c',
  'p_cache.c',
  'serialize_io.c',
  'p/io_ar.c',
  'p/io_fd.c',
  'p/io_bfdbg.c',
  'p/io_bochs.c',
  'p/io_debug.c',
  'p/io_default.c',
  'p/io_gdb.c',
  'p/io_gprobe.c',
  'p/io_gzip.c',
  'p/io_http.c',
  'p/io_ihex.c',
  'p/io_mach.c',
  'p/io_malloc.c',
  'p/io_null.c',
  'p/io_procpid.c',
  'p/io_ptrace.c',
  'p/io_qnx.c',
  'p/io_rzk.c',
  'p/io_rzpipe.c',
  'p/io_rzweb.c',
  'p/io_rap.c',
  'p/io_self.c',
  'p/io_shm.c',
  'p/io_sparse.c',
  'p/io_tcp.c',
  'p/io_winkd.c',
  'p/io_winedbg.c',
  'p/io_zip.c',
]

if host_machine.system() == 'windows'
  rz_io_sources += [
    'p/io_rzk_windows.c',
    'p/io_windbg.c',
    'p/io_w32.c',
    'p/io_w32dbg.c',
  ]
endif


rz_io_deps = [
  bochs_dep,
  gdb_dep,
  winkd_dep,
  qnx_dep,
  libzip_dep,
  ar_dep,
  pth,
  rz_util_dep,
  rz_socket_dep,
  rz_hash_dep,
  rz_crypto_dep,
  rz_cons_dep,
]

if host_machine.system() == 'windows'
  rz_io_deps += w32dbg_wrap_dep
endif

if host_machine.system() == 'linux' or host_machine.system() == 'android'
  rz_io_sources += [
    'p/io_rzk_linux.c',
  ]
  ## only for shm_open
  # rz_io_deps += meson.get_compiler('c').find_library('rt')
endif

if use_ptrace_wrap
  rz_io_deps += ptrace_wrap_dep
endif

rz_io = library('rz_io', rz_io_sources,
  include_directories: platform_inc,
  dependencies: rz_io_deps,
  c_args: library_cflags,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_io_dep = declare_dependency(link_with: rz_io,
                              include_directories: platform_inc)

pkgconfig_mod.generate(rz_io,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_io',
  filebase: 'rz_io',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util',
    'rz_socket'
  ],
  description: 'rizin foundation libraries'
)
