rz_socket_sources = [
  'socket.c',
  'socket_http.c',
  'socket_http_server.c',
  'socket_serial.c',
  'socket_proc.c',
  'rzpipe.c',
  'socket_rap_client.c',
  'socket_rap_server.c',
  'run.c',
]

dependencies = [utl, rz_util_dep, platform_deps]

if sys_openssl.found()
  dependencies += [sys_openssl]
endif

rz_socket = library('rz_socket', rz_socket_sources,
  include_directories: [platform_inc],
  dependencies: dependencies,
  c_args: library_cflags,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_socket_dep = declare_dependency(link_with: rz_socket,
  dependencies: [rz_util_dep],
  include_directories: [platform_inc])

pkgconfig_mod.generate(rz_socket,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_socket',
  filebase: 'rz_socket',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util'
  ],
  description: 'rizin foundation libraries'
)
