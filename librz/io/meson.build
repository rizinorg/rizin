rz_io_dependencies = [
  pth,
  rz_util_dep,
  rz_socket_dep,
  rz_hash_dep,
  rz_crypto_dep,
  rz_cons_dep,
]

if host_machine.system() == 'windows'
  rz_io_dependencies += w32dbg_wrap_dep
endif

if use_ptrace_wrap
  rz_io_dependencies += ptrace_wrap_dep
endif

rz_io_sources = [
  'io.c',
  'io_fd.c',
  'io_map.c',
  'io_cache.c',
  'io_desc.c',
  'io_plugin.c',
  'ioutils.c',
  'p_cache.c',
  'serialize_io.c',
]

rz_io = library('rz_io', rz_io_sources,
  include_directories: platform_inc,
  dependencies: rz_io_dependencies + rz_io_plugins_dep,
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
