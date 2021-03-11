rz_parse_dependencies = [
  rz_util_dep,
  rz_flag_dep,
  rz_syscall_dep,
  rz_reg_dep,
  tcc_dep,
  mpc_dep
]

rz_parse_inc = [platform_inc]

rz_parse_sources = [
  'code.c',
  'filter.c',
  'parse.c',
  'ctype.c',
]

rz_parse = library('rz_parse', rz_parse_sources,
  include_directories: rz_parse_inc,
  c_args: library_cflags,
  dependencies: rz_parse_dependencies + rz_parse_plugins_dep,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_parse_dep = declare_dependency(link_with: rz_parse,
                                 include_directories: platform_inc)

pkgconfig_mod.generate(rz_parse,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_parse',
  filebase: 'rz_parse',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util',
    'rz_flag',
    'rz_cons',
    'rz_syscall',
    'rz_reg'
  ],
  description: 'rizin foundation libraries'
)
