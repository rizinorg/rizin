rz_main_sources = [
  'main.c',
  'rz-bin.c',
  'rizin.c',
  'rz-diff.c',
  'rz-find.c',
  'rz-gg.c',
  'rz-hash.c',
  'rz-run.c',
  'rz-sign.c',
  'rz-asm.c',
  'rz-ax.c'
]

rz_main_deps = [
  rz_util_dep,
  rz_demangler_dep,
  rz_magic_dep,
  rz_socket_dep,
  rz_flag_dep,
  rz_cons_dep,
  rz_hash_dep,
  rz_crypto_dep,
  rz_il_dep,
  rz_io_dep,
  rz_reg_dep,
  rz_syscall_dep,
  rz_arch_dep,
  rz_egg_dep,
  rz_search_dep,
  rz_debug_dep,
  rz_config_dep,
  rz_bin_dep,
  rz_sign_dep,
  rz_core_dep,
  rz_diff_dep,
]

rz_main = library('rz_main', rz_main_sources,
  include_directories: [platform_inc],
  dependencies: rz_main_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_main_dep = declare_dependency(link_with: rz_main,
                                include_directories: [platform_inc],
                                dependencies: rz_main_deps)
meson.override_dependency('rz_main', rz_main_dep)

modules += { 'rz_main': {
    'target': rz_main,
    'dependencies': [
      'rz_core',
      'rz_demangler',
      'rz_arch',
      'rz_sign',
      'rz_diff',
      'rz_syscall'
    ]
}}
