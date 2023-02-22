egg_plugins = {
  'conf_name': 'plugins_egg',
  'base_cname': 'rz_egg_plugin_',
  'list': [
    'exec',
    #'shya',
    'xor'
  ],
}

rz_egg_sources = [
  'egg.c',
  'egg_Cfile.c',
  'egg_lang.c',
  'emit_arm.c',
  'emit_trace.c',
  'emit_x64.c',
  'emit_x86.c',
  #'p/egg_bind.c',
  #'p/egg_cb.c',
  'p/egg_exec.c',
  #'p/egg_reverse.c',
  #'p/egg_shya.c',
  'p/egg_xor.c'
]

rz_egg_deps = [
  rz_util_dep,
  rz_syscall_dep,
  rz_asm_dep,
  mpc_dep
]

rz_egg = library('rz_egg', rz_egg_sources,
  include_directories: [platform_inc],
  dependencies: rz_egg_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_egg_dep = declare_dependency(
  link_with: rz_egg,
  include_directories: [platform_inc],
  variables:  {'name': 'rz_egg'},
)
meson.override_dependency('rz_egg', rz_egg_dep)

modules += { 'rz_egg': {
    'target': rz_egg,
    'dependencies': rz_egg_deps,
    'plugins': [egg_plugins]
}}
