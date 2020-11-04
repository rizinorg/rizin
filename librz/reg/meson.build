rz_reg_sources = [
  'arena.c',
  'rcond.c',
  'double.c',
  'profile.c',
  'reg.c',
  'rvalue.c',
]

rz_reg = library('rz_reg', rz_reg_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [rz_util_dep],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_reg_dep = declare_dependency(link_with: rz_reg,
                               include_directories: [platform_inc])

pkgconfig_mod.generate(rz_reg,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_reg',
  filebase: 'rz_reg',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util'
  ],
  description: 'rizin foundation libraries'
)
