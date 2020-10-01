executable('rz-bin', 'rz-bin.c',
  include_directories: [platform_inc],
  dependencies: [
    rz_util_dep,
    rz_cons_dep,
    rz_main_dep,
    rz_config_dep,
    rz_hash_dep,
    rz_io_dep,
    rz_crypto_dep,
    rz_core_dep,
    rz_magic_dep,
    rz_bin_dep
  ],
  install: true,
  install_rpath: rpath_exe,
  implicit_include_directories: false
)
