rz_config_sources = [
  'callback.c',
  'config.c',
  'hold.c',
]

rz_config = library('rz_config', rz_config_sources,
  include_directories: [platform_inc],
  dependencies: [
    rz_util_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_config_dep = declare_dependency(link_with: rz_config,
                                  include_directories: [platform_inc])

pkgconfig_mod.generate(rz_config,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_config',
  filebase: 'rz_config',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util'
  ],
  description: 'radare foundation libraries'
)
