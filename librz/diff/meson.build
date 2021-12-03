rz_diff_sources = [
  'diff.c',
  'distance.c'
]

dependencies = [rz_util_dep]

rz_diff = library('rz_diff', rz_diff_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: dependencies,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  link_args: library_linkflags,
  soversion: rizin_libversion
)

rz_diff_dep = declare_dependency(link_with: rz_diff,
                                include_directories: [platform_inc])

pkgconfig_mod.generate(rz_diff,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_diff',
  filebase: 'rz_diff',
  requires: [
    'rz_util'
  ],
  description: 'rizin foundation libraries'
)

conf = configuration_data()
conf.set('RZ_VERSION', rizin_version)
conf.set('RIZIN_MODULE', rz_diff.name())
conf.set('RIZIN_MODULE_DEPS', ' '.join(['rz_util']))
conf.set('INSTALL_INCDIR', rizin_incdir)
conf.set('INSTALL_LIBDIR', rizin_libdir)
conf.set('INSTALL_PLUGDIR', rizin_plugins)
conf.set('rizin_libname', rz_diff.name())
cmake_mod.configure_package_config_file(
  name: conf.get('rizin_libname'),
  input: '../RzModulesConfig.cmake.in',
  install_dir: rizin_cmakedir / conf.get('rizin_libname'),
  configuration: conf,
)
