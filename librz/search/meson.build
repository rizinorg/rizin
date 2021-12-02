rz_search_sources = [
  'aes-find.c',
  'bytepat.c',
  'keyword.c',
  'regexp.c',
  'privkey-find.c',
  'search.c',
  'strings.c'
]

rz_search = library('rz_search', rz_search_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [rz_util_dep],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  link_args: library_linkflags,
  soversion: rizin_libversion
)

rz_search_dep = declare_dependency(link_with: rz_search,
                                  include_directories: [platform_inc])

pkgconfig_mod.generate(rz_search,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_search',
  filebase: 'rz_search',
  requires: [
    'rz_util'
  ],
  description: 'rizin foundation libraries'
)

conf = configuration_data()
conf.set('RZ_VERSION', rizin_version)
conf.set('RIZIN_MODULE', 'RzSearch')
conf.set('RIZIN_MODULE_DEPS', ' '.join(['RzUtil']))
conf.set('INSTALL_INCDIR', rizin_incdir)
conf.set('INSTALL_LIBDIR', rizin_libdir)
conf.set('rizin_libname', rz_search.name())
cmake_mod.configure_package_config_file(
  name: conf.get('RIZIN_MODULE'),
  input: '../RzModulesConfig.cmake.in',
  install_dir: rizin_cmakedir,
  configuration: conf,
)
