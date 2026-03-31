mark_sources = [
  'mark.c',
  'serialize_mark.c'
]

rz_mark = library('rz_mark', mark_sources,
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

rz_mark_dep = declare_dependency(
  link_with: rz_mark,
  include_directories: [platform_inc]
)

meson.override_dependency('rz_mark', rz_mark_dep)

modules += { 'rz_mark': {
  'target': rz_mark,
  'dependencies': ['rz_util']
}}
