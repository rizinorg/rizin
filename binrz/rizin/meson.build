rizin_link_args = []
rizin_link_depends = []
rizin_name = 'rizin'
rizin_exe_name = rizin_name
if host_machine.system() == 'darwin'
  # NOTE: we do not sign the binary with a certificate for now, so no need for this.
  #       However keep this in mind if/when we will sign rizin binary
  # rizin_link_args += ['-Wl,-sectcreate,__TEXT,__info_plist,' + join_paths(meson.current_source_dir(), 'Info.plist')]
  # rizin_link_args += ['-Wl,-framework,Security']
  # rizin_link_args += ['-Wl,-framework,CoreFoundation']
  # rizin_link_depends += 'Info.plist'
  rizin_exe_name += '-unsigned'
endif

rizin_exe = executable(rizin_exe_name, 'rizin.c',
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
  install: rizin_exe_name == rizin_name,
  install_rpath: rpath_exe,
  implicit_include_directories: false,
  link_args: rizin_link_args,
  link_depends: rizin_link_depends,
)

if host_machine.system() == 'darwin'
  # CodeSign the rizin binary to make debugger work by applying the
  # entitlements
  entitlements = files('rizin_macos.xml')
  macos_sign_sh = meson.current_source_dir() / 'macos_sign.sh'
  custom_target(rizin_name,
    build_by_default: true,
    build_always_stale: true,
    command: [
      macos_sign_sh,
      entitlements,
      rizin_exe.full_path(),
      meson.current_build_dir() / rizin_name,
    ],
    depends: rizin_exe,
    output: rizin_name,
    install: true,
    install_dir: get_option('bindir'),
  )

  meson.add_install_script(meson.current_source_dir() / 'macos_sign.sh',
    entitlements,
    get_option('prefix') / get_option('bindir') / rizin_name,
  )
endif