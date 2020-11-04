rz_bp_sources = [
  'bp.c',
  'bp_io.c',
  'bp_plugin.c',
  'bp_traptrace.c',
  'bp_watch.c',
  'p/bp_arm.c',
  'p/bp_bf.c',
  'p/bp_mips.c',
  'p/bp_ppc.c',
  'p/bp_sh.c',
  'p/bp_x86.c'
]

rz_bp = library('rz_bp', rz_bp_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [rz_util_dep],
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
