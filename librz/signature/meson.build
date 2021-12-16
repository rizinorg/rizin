rz_sign_sources = [
   'flirt.c',
   'pac.c',
   'create.c',
   'zignature.c',
   'sign.c',
]

rz_sign_inc = [
  platform_inc,
]

rz_sign_deps = [
  rz_util_dep,
  rz_analysis_dep,
  rz_diff_dep,
  rz_hash_dep,
  rz_type_dep,
  rz_search_dep,
  rz_flag_dep,
]

rz_sign = library('rz_sign', rz_sign_sources,
  include_directories: rz_sign_inc,
  c_args: library_cflags,
  dependencies: rz_sign_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  link_args: library_linkflags,
  soversion: rizin_libversion,
  name_suffix: lib_name_suffix,
)

rz_sign_dep = declare_dependency(link_with: rz_sign,
                                include_directories: rz_sign_inc)

pkgconfig_mod.generate(rz_sign,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_sign',
  filebase: 'rz_sign',
  requires: [
    'rz_util',
    'rz_analysis',
    'rz_diff',
    'rz_hash',
    'rz_search',
    'rz_type',
    'rz_flag',
  ],
  description: 'rizin foundation libraries'
)

conf = configuration_data()
conf.set('RZ_VERSION', rizin_version)
conf.set('RIZIN_MODULE', rz_sign.name())
conf.set('RIZIN_MODULE_DEPS', ' '.join(['rz_util', 'rz_analysis', 'rz_diff', 'rz_hash', 'rz_search', 'rz_type', 'rz_flag']))
conf.set('PACKAGE_RELATIVE_PATH', cmake_package_relative_path)
conf.set('INSTALL_INCDIR', rizin_incdir)
conf.set('INSTALL_LIBDIR', rizin_libdir)
conf.set('INSTALL_PLUGDIR', rizin_plugins)
conf.set('rizin_libname', rz_sign.name())
cmake_mod.configure_package_config_file(
  name: conf.get('rizin_libname'),
  input: '../RzModulesConfig.cmake.in',
  install_dir: rizin_cmakedir / conf.get('rizin_libname'),
  configuration: conf,
)
