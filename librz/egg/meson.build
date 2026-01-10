egg_plugins_list = [
  'exec',
  'xor',
]

egg_plugins = {
  'base_name': 'rz_egg',
  'base_struct': 'RzEggPlugin',
  'list': egg_plugins_list,
}

rz_egg_sources = [
  'egg.c',
  'egg_c_compile.c',
  'egg_lang.c',
  'emit/arm.c',
  'emit/trace.c',
  'emit/x64.c',
  'emit/x86.c',
  'p/egg_exec.c',
  'p/egg_xor.c'
]

rz_egg = library('rz_egg', rz_egg_sources,
  include_directories: [platform_inc],
  dependencies: [
    rz_util_dep,
    rz_syscall_dep,
    rz_arch_dep,
    mpc_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_egg_dep = declare_dependency(link_with: rz_egg,
                               include_directories: [platform_inc])
meson.override_dependency('rz_egg', rz_egg_dep)

modules += { 'rz_egg': {
    'target': rz_egg,
    'dependencies': ['rz_util', 'rz_arch', 'rz_syscall'],
    'plugins': [egg_plugins]
}}
