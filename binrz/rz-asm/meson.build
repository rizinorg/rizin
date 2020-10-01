executable('rz-asm', 'rz-asm.c',
  include_directories: [platform_inc],
  dependencies: [
    rz_main_dep,
    rz_util_dep,
    rz_asm_dep,
    rz_anal_dep,
    rz_crypto_dep,
    rz_syscall_dep,
    rz_hash_dep
  ],
  install: true,
  install_rpath: rpath_exe,
  implicit_include_directories: false
)
