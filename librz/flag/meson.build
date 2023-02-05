rz_flag_sources = [
  'flag.c',
  'tags.c',
  'zones.c',
  'serialize_flag.c'
]

rz_flag = library('rz_flag', rz_flag_sources,
  include_directories: [platform_inc],
  dependencies: [
    rz_util_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_flag_dep = declare_dependency(link_with: rz_flag,
                                include_directories: [platform_inc])
meson.override_dependency('rz_flag', rz_flag_dep)

modules += { 'rz_flag': {
    'target': rz_flag,
    'dependencies': ['rz_util']
}}

subdir('d')
