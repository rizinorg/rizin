rz_bp_dependencies = [
  rz_util_dep,
]

rz_bp_sources = [
  'bp.c',
  'bp_io.c',
  'bp_plugin.c',
  'bp_traptrace.c',
  'bp_watch.c',
]

rz_bp = library('rz_bp', rz_bp_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: rz_bp_dependencies,
  link_with: rz_bp_static_plugins,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_bp_dep = declare_dependency(link_with: rz_bp,
                              include_directories: [platform_inc])

pkgconfig_mod.generate(rz_bp,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_bp',
  filebase: 'rz_bp',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util'
  ],
  description: 'rizin foundation libraries'
)
