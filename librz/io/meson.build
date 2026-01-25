io_plugins_list = [
  'ar',
  'fd',
  'bochs',
  'debug',
  'default',
  'dmp',
  'gdb',
  'gzip',
  'http',
  'ihex',
  'srec',
  'mach',
  'malloc',
  'null',
  'procpid',
  'ptrace',
  'self',
  'shm',
  'sparse',
  'tcp',
  'titxt',
  'winkd',
  'winedbg',
  'zip'
]

if get_option('use_gpl')
  io_plugins_list += 'qnx'
endif

if host_machine.system() == 'windows'
  io_plugins_list+= [
    'windbg',
    'w32dbg',
    'w32',
  ]
endif

io_plugins = {
  'base_name': 'rz_io',
  'base_struct': 'RzIOPlugin',
  'list': io_plugins_list,
}

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
  'p/io_bochs.c',
  'p/io_debug.c',
  'p/io_dmp.c',
  'p/io_default.c',
  'p/io_gdb.c',
  'p/io_gzip.c',
  'p/io_http.c',
  'p/io_ihex.c',
  'p/io_mach.c',
  'p/io_malloc.c',
  'p/io_null.c',
  'p/io_procpid.c',
  'p/io_ptrace.c',
  'p/io_self.c',
  'p/io_shm.c',
  'p/io_sparse.c',
  'p/io_srec.c',
  'p/io_tcp.c',
  'p/io_winkd.c',
  'p/io_winedbg.c',
  'p/io_zip.c',
  'p/io_titxt.c',
]

if host_machine.system() == 'windows'
  rz_io_sources += [
    'p/io_windbg.c',
    'p/io_w32.c',
    'p/io_w32dbg.c',
  ]
endif

rz_io_deps = [
  dependency('rzgdb'),
  dependency('rzwinkd'),
  libzip_dep,
  dependency('rzar'),
  th,
  lrt,
  rz_util_dep,
  rz_socket_dep,
  rz_hash_dep,
  rz_crypto_dep,
  rz_cons_dep,
  platform_deps,
]

if get_option('use_gpl')
  rz_io_deps += dependency('rzqnx')
  rz_io_sources += 'p/io_qnx.c'
endif

if host_machine.system() == 'windows'
  rz_io_deps += dependency('rzw32dbg_wrap')
endif

if use_ptrace_wrap
  rz_io_deps += dependency('ptrace-wrap', default_options: ['is_static_build=' + is_static_build.to_string()])
endif

rz_io = library('rz_io', rz_io_sources,
  include_directories: platform_inc,
  dependencies: rz_io_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_io_dep = declare_dependency(link_with: rz_io,
                              include_directories: platform_inc)
meson.override_dependency('rz_io', rz_io_dep)

modules += { 'rz_io': {
    'target': rz_io,
    'dependencies': ['rz_util', 'rz_socket', 'rz_hash', 'rz_crypto', 'rz_cons'],
    'plugins': [io_plugins]
}}
