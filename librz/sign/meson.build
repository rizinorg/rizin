rz_sign_sources = [
   'create.c',
   'flirt.c',
   'pat.c',
   'sigdb.c',
   'sign.c',
]

rz_sign_inc = [
  platform_inc,
]

rz_sign_deps = [
  rz_util_dep,
  rz_arch_dep,
  rz_diff_dep,
  rz_hash_dep,
  rz_type_dep,
  rz_search_dep,
  rz_flag_dep,
]

rz_sign = library('rz_sign', rz_sign_sources,
  include_directories: rz_sign_inc,
  dependencies: rz_sign_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_sign_dep = declare_dependency(link_with: rz_sign,
                                include_directories: rz_sign_inc)
meson.override_dependency('rz_sign', rz_sign_dep)

modules += { 'rz_sign': {
    'target': rz_sign,
    'dependencies': [
      'rz_util',
      'rz_arch',
      'rz_diff',
      'rz_hash',
      'rz_type',
      'rz_search',
      'rz_flag',
    ]
}}
