bookmark_sources = [
  'bookmark.c',
  'serialize_bookmark.c'
]

rz_bookmark = library('rz_bookmark', bookmark_sources,
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

rz_bookmark_dep = declare_dependency(
  link_with: rz_bookmark,
  include_directories: [platform_inc]
)

meson.override_dependency('rz_bookmark', rz_bookmark_dep)

modules += { 'rz_bookmark': {
  'target': rz_bookmark,
  'dependencies': ['rz_util']
}}
