rz_reg_sources = [
  'arena.c',
  'rcond.c',
  'profile.c',
  'reg.c',
  'rvalue.c',
]

rz_reg = library('rz_reg', rz_reg_sources,
  include_directories: [platform_inc],
  dependencies: [rz_util_dep],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_reg_dep = declare_dependency(link_with: rz_reg,
                               include_directories: [platform_inc])
meson.override_dependency('rz_reg', rz_reg_dep)

modules += { 'rz_reg': {
    'target': rz_reg,
    'dependencies': ['rz_util']
}}

subdir('d')
