rizin_exe = executable('rizin', 'rizin.c',
  include_directories: [platform_inc],
  dependencies: [
    rz_util_dep,
    rz_main_dep,
    rz_socket_dep,
    rz_core_dep,
    rz_io_dep,
    rz_bin_dep,
    rz_flag_dep,
    rz_cons_dep,
    rz_asm_dep,
    rz_debug_dep,
    rz_config_dep,
    rz_bp_dep,
    rz_reg_dep,
    rz_syscall_dep,
    rz_analysis_dep,
    rz_parse_dep,
    rz_egg_dep,
    rz_search_dep,
    rz_hash_dep,
    rz_crypto_dep,
    rz_magic_dep
  ],
  install: true,
  install_rpath: rpath_exe,
  implicit_include_directories: false,
)

if host_machine.system() == 'darwin'
  # CodeSign the rizin binary to make debugger work by applying the
  # entitlements
  entitlements = files('rizin_macos.xml')
  macos_sign_sh = meson.current_source_dir() / 'macos_sign.sh'
  custom_target('rizin-signing',
    build_by_default: true,
    build_always_stale: true,
    command: [
      macos_sign_sh,
      'false',
      entitlements,
      rizin_exe.full_path(),
    ],
    depends: rizin_exe,
    output: 'rizin-signing',
    install: false,
  )

  meson.add_install_script(meson.current_source_dir() / 'macos_sign.sh',
    'true',
    entitlements,
    rizin_bindir / 'rizin',
  )
endif