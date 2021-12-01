rz_demangler_sources = [
  'demangler.c'
]

dependencies = [rz_util_dep, libdemangle_dep]

rz_demangler = library('rz_demangler', rz_demangler_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: dependencies,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  link_args: library_linkflags,
  soversion: rizin_libversion
)

rz_demangler_dep = declare_dependency(link_with: rz_demangler, include_directories: [platform_inc])

pkgconfig_mod.generate(rz_demangler,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_demangler',
  filebase: 'rz_demangler',
  requires: [
    'rz_util'
  ],
  description: 'rizin foundation libraries',
  variables: [
    'plugindir=@0@'.format(rizin_plugins),
  ],
)
