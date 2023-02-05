rz_config_sources = [
  'config.c',
  'hold.c',
  'serialize_config.c'
]

rz_config = library('rz_config', rz_config_sources,
  include_directories: [platform_inc],
  dependencies: [
    rz_util_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_config_dep = declare_dependency(link_with: rz_config,
                                  include_directories: [platform_inc])
meson.override_dependency('rz_config', rz_config_dep)

modules += { 'rz_config': {
    'target': rz_config,
    'dependencies': ['rz_util']
}}
