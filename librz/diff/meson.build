rz_diff_sources = [
  'diff.c',
  'distance.c',
  'old.c'
]

dependencies = [rz_util_dep]

rz_diff = library('rz_diff', rz_diff_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: dependencies,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_diff_dep = declare_dependency(link_with: rz_diff,
                                include_directories: [platform_inc])

pkgconfig_mod.generate(rz_diff,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_diff',
  filebase: 'rz_diff',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util'
  ],
  description: 'rizin foundation libraries'
)
