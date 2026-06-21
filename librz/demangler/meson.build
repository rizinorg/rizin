demangler_plugins_list = [
  'java',
  'msvc',
  'objc',
  'pascal',
  'cpp',
  'rust'
]

demangler_plugins = {
  'base_name': 'rz_demangler',
  'base_struct': 'RzDemanglerPlugin',
  'list': demangler_plugins_list,
}

rz_demangler_sources = [
  'demangler.c'
]

dependencies = [rz_util_dep, libdemangle_dep]

rz_demangler = library('rz_demangler', rz_demangler_sources,
  include_directories: [platform_inc],
  dependencies: dependencies,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_demangler_dep = declare_dependency(link_with: rz_demangler, include_directories: [platform_inc])
meson.override_dependency('rz_demangler', rz_demangler_dep)

modules += { 'rz_demangler': {
    'target': rz_demangler,
    'dependencies': ['rz_util'],
    'plugins': [demangler_plugins]
}}
