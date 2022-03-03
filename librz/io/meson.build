io_plugins = [
  'ar',
  'fd',
  'bfdbg',
  'bochs',
  'debug',
  'default',
  'dmp',
  'gdb',
  'gprobe',
  'gzip',
  'http',
  'ihex',
  'srec',
  'mach',
  'malloc',
  'null',
  'procpid',
  'ptrace',
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

if get_option('use_gpl')
  io_plugins += 'qnx'
endif

if host_machine.system() == 'windows'
  io_plugins += [
    'windbg',
    'w32dbg',
    'w32',
  ]
endif

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
  'p/io_dmp.c',
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
  'p/io_rzk.c',
  'p/io_rzpipe.c',
  'p/io_rzweb.c',
  'p/io_rap.c',
  'p/io_self.c',
  'p/io_shm.c',
  'p/io_sparse.c',
  'p/io_srec.c',
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
  dependency('rzbochs'),
  dependency('rzgdb'),
  dependency('rzwinkd'),
  libzip_dep,
  dependency('rzar'),
  pth,
  lrt,
  rz_util_dep,
  rz_socket_dep,
  rz_hash_dep,
  rz_crypto_dep,
  rz_cons_dep,
]

if get_option('use_gpl')
  rz_io_deps += dependency('rzqnx')
  rz_io_sources += 'p/io_qnx.c'
endif

if host_machine.system() == 'windows'
  rz_io_deps += dependency('rzw32dbg_wrap')
endif

if host_machine.system() == 'linux' or host_machine.system() == 'android'
  rz_io_sources += [
    'p/io_rzk_linux.c',
  ]
  ## only for shm_open
  # rz_io_deps += meson.get_compiler('c').find_library('rt')
endif

if use_ptrace_wrap
  rz_io_deps += dependency('ptrace-wrap', default_options: ['is_static_build=' + is_static_build.to_string()])
endif

rz_io = library('rz_io', rz_io_sources,
  include_directories: platform_inc,
  dependencies: rz_io_deps,
  c_args: library_cflags,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  link_args: library_linkflags,
  soversion: rizin_libversion,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_io_dep = declare_dependency(link_with: rz_io,
                              include_directories: platform_inc)
meson.override_dependency('rz_io', rz_io_dep)

pkgconfig_mod.generate(rz_io,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_io',
  filebase: 'rz_io',
  requires: [
    'rz_util',
    'rz_socket'
  ],
  description: 'rizin foundation libraries',
  variables: [
    'plugindir=@0@'.format(rizin_plugins),
    'datdir=@0@'.format(rizin_datdir_rz),
  ],
)

if not is_static_libs_only
  conf = configuration_data()
  conf.set('RZ_VERSION', rizin_version)
  conf.set('RIZIN_MODULE', rz_io.name())
  conf.set('RIZIN_MODULE_DEPS', ' '.join(['rz_util', 'rz_socket', 'rz_hash', 'rz_crypto', 'rz_cons']))
  conf.set('PACKAGE_RELATIVE_PATH', cmake_package_relative_path)
  conf.set('INSTALL_INCDIR', rizin_incdir)
  conf.set('INSTALL_LIBDIR', rizin_libdir)
  conf.set('INSTALL_PLUGDIR', rizin_plugins)
  conf.set('rizin_libname', rz_io.name())
  cmake_mod.configure_package_config_file(
    name: conf.get('rizin_libname'),
    input: '../RzModulesConfig.cmake.in',
    install_dir: rizin_cmakedir / conf.get('rizin_libname'),
    configuration: conf,
  )
endif
