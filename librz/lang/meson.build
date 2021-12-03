rz_lang_sources = [
  'lang.c',
  # included in lang.c
  #'p/c.c',
  #'p/cpipe.c',
  #'p/lib.c',
  #'p/pipe.c',
]

rz_lang = library('rz_lang', rz_lang_sources,
  include_directories: platform_inc,
  c_args: library_cflags,
  dependencies: [rz_util_dep, rz_cons_dep],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  link_args: library_linkflags,
  soversion: rizin_libversion
)

rz_lang_dep = declare_dependency(link_with: rz_lang,
                                include_directories: [platform_inc])

pkgconfig_mod.generate(rz_lang,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_lang',
  filebase: 'rz_lang',
  requires: [
    'rz_util',
    'rz_cons'
  ],
  description: 'rizin foundation libraries',
  variables: [
    'plugindir=@0@'.format(rizin_plugins),
  ],
)

conf = configuration_data()
conf.set('RZ_VERSION', rizin_version)
conf.set('RIZIN_MODULE', rz_lang.name())
conf.set('RIZIN_MODULE_DEPS', ' '.join(['rz_util', 'rz_cons']))
conf.set('INSTALL_INCDIR', rizin_incdir)
conf.set('INSTALL_LIBDIR', rizin_libdir)
conf.set('INSTALL_PLUGDIR', rizin_plugins)
conf.set('rizin_libname', rz_lang.name())
cmake_mod.configure_package_config_file(
  name: conf.get('rizin_libname'),
  input: '../RzModulesConfig.cmake.in',
  install_dir: rizin_cmakedir,
  configuration: conf,
)
