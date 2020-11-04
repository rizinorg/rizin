rz_flag_sources = [
  'flag.c',
  'tags.c',
  'zones.c',
  'serialize_flag.c'
]

rz_flag = library('rz_flag', rz_flag_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [
    rz_util_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_flag_dep = declare_dependency(link_with: rz_flag,
                                include_directories: [platform_inc])

pkgconfig_mod.generate(rz_flag,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_flag',
  filebase: 'rz_flag',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util'
  ],
  description: 'rizin foundation libraries'
)
