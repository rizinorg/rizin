executable('rz-hash', 'rz-hash.c',
  include_directories: [platform_inc],
  dependencies: [
    rz_util_dep,
    rz_main_dep,
    rz_hash_dep,
    rz_io_dep,
    rz_crypto_dep,
    rz_socket_dep
  ],
  install: true,
  install_rpath: rpath_exe,
  implicit_include_directories: false
)
