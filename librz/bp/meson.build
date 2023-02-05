bp_plugins = {
  'conf_name': 'plugins_bp',
  'base_cname': 'rz_bp_plugin_',
  'list': [
    'arm',
    'bf',
    'mips',
    'ppc',
    'sh',
    'x86'
  ],
}

rz_bp_sources = [
  'bp.c',
  'bp_io.c',
  'bp_plugin.c',
  'bp_traptrace.c',
  'bp_watch.c',
  'serialize_bp.c',
  'p/bp_arm.c',
  'p/bp_bf.c',
  'p/bp_mips.c',
  'p/bp_ppc.c',
  'p/bp_sh.c',
  'p/bp_x86.c'
]

rz_bp = library('rz_bp', rz_bp_sources,
  include_directories: [platform_inc],
  dependencies: [rz_util_dep],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_bp_dep = declare_dependency(link_with: rz_bp,
                              include_directories: [platform_inc])
meson.override_dependency('rz_bp', rz_bp_dep)

modules += { 'rz_bp': {
    'target': rz_bp,
    'dependencies': ['rz_util'],
    'plugins': [bp_plugins]
}}
