rz_config_sources = [
  'config.c',
  'hold.c',
  'serialize_config.c'
]

rz_config = library('rz_config', rz_config_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [
    rz_util_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  link_args: library_linkflags,
  soversion: rizin_libversion
)

rz_config_dep = declare_dependency(link_with: rz_config,
                                  include_directories: [platform_inc])

pkgconfig_mod.generate(rz_config,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_config',
  filebase: 'rz_config',
  requires: [
    'rz_util'
  ],
  description: 'rizin foundation libraries'
)
