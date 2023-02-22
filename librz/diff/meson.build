rz_diff_sources = [
  'diff.c',
  'distance.c'
]

rz_diff_deps = [rz_util_dep]

rz_diff = library('rz_diff', rz_diff_sources,
  include_directories: [platform_inc],
  dependencies: rz_diff_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_diff_dep = declare_dependency(
  link_with: rz_diff,
  include_directories: [platform_inc],
  variables:  {'name': 'rz_diff'},
)
meson.override_dependency('rz_diff', rz_diff_dep)

modules += { 'rz_diff': {
    'target': rz_diff,
    'dependencies': rz_diff_deps,
}}
