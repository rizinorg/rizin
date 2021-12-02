rz_main_sources = [
  'main.c',
  'rz-agent.c',
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
  rz_io_dep,
  rz_reg_dep,
  rz_bp_dep,
  rz_syscall_dep,
  rz_parse_dep,
  rz_asm_dep,
  rz_egg_dep,
  rz_search_dep,
  rz_analysis_dep,
  rz_debug_dep,
  rz_config_dep,
  rz_bin_dep,
  rz_sign_dep,
  rz_core_dep,
  rz_diff_dep,
]

rz_main = library('rz_main', rz_main_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: rz_main_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  link_args: library_linkflags,
  soversion: rizin_libversion
)

rz_main_dep = declare_dependency(link_with: rz_main,
                                include_directories: [platform_inc],
                                dependencies: rz_main_deps)

pkgconfig_mod.generate(rz_main,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_main',
  filebase: 'rz_main',
  requires: [
    'rz_core',
    'rz_demangler',
    'rz_asm',
    'rz_sign',
    'rz_diff',
    'rz_syscall'
  ],
  description: 'rizin foundation libraries'
)

conf = configuration_data()
conf.set('RZ_VERSION', rizin_version)
conf.set('RIZIN_MODULE', 'RzMain')
conf.set('RIZIN_MODULE_DEPS', ' '.join(['RzCore']))
conf.set('INSTALL_INCDIR', rizin_incdir)
conf.set('INSTALL_LIBDIR', rizin_libdir)
conf.set('rizin_libname', rz_main.name())
cmake_mod.configure_package_config_file(
  name: conf.get('RIZIN_MODULE'),
  input: '../RzModulesConfig.cmake.in',
  install_dir: rizin_cmakedir,
  configuration: conf,
)
