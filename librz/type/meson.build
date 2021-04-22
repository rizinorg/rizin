rz_type_sources = [
  'base.c',
  'code.c',
  'ctype.c',
  'format.c',
  'function.c',
  'helpers.c',
  'serialize_types.c',
  'type.c',
]

rz_type_inc = [
  platform_inc,
]

rz_type = library('rz_type', rz_type_sources,
  include_directories: rz_type_inc,
  c_args: library_cflags,
  dependencies: [
    rz_util_dep,
    tcc_dep,
    mpc_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_type_dep = declare_dependency(link_with: rz_type,
                                include_directories: rz_type_inc)

pkgconfig_mod.generate(rz_type,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_type',
  filebase: 'rz_type',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util',
  ],
  description: 'rizin foundation libraries'
)
