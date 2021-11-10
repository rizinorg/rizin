rz_flirt_sources = [
   'flirt.c',
]

rz_flirt_inc = [
  platform_inc,
]

rz_flirt = library('rz_flirt', rz_flirt_sources,
  include_directories: rz_flirt_inc,
  c_args: library_cflags,
  dependencies: [
    rz_util_dep,
    rz_analysis_dep,
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_flirt_dep = declare_dependency(link_with: rz_flirt,
                                include_directories: rz_flirt_inc)

pkgconfig_mod.generate(rz_flirt,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_flirt',
  filebase: 'rz_sign',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util',
    'rz_analysis',
  ],
  description: 'rizin foundation libraries'
)
