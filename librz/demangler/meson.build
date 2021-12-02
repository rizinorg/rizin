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

conf = configuration_data()
conf.set('RZ_VERSION', rizin_version)
conf.set('RIZIN_MODULE', 'Demangler')
conf.set('INSTALL_INCDIR', rizin_incdir)
conf.set('INSTALL_LIBDIR', rizin_libdir)
conf.set('rizin_libname', rz_demangler.name())
cmake_mod.configure_package_config_file(
  name: 'Rz' + conf.get('RIZIN_MODULE'),
  input: '../RzModulesConfig.cmake.in',
  install_dir: rizin_cmakedir,
  configuration: conf,
)
