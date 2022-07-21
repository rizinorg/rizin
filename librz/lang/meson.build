lang_plugins_list = [
  'lib',
  'pipe',
]
if host_machine.system() != 'windows'
  lang_plugins_list += [
    'c',
    'cpipe'
  ]
endif

lang_plugins = {
  'conf_name': 'plugins_lang',
  'base_cname': 'rz_lang_plugin_',
  'list': lang_plugins_list,
}

rz_lang_sources = [
  'lang.c',
  'p/lib.c',
  'p/pipe.c',
  'p/pipe_helper.c',
]

if host_machine.system() != 'windows'
  rz_lang_sources += [
    'p/c.c',
    'p/cpipe.c',
  ]
endif

rz_lang = library('rz_lang', rz_lang_sources,
  include_directories: platform_inc,
  dependencies: [rz_util_dep, rz_cons_dep],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_lang_dep = declare_dependency(link_with: rz_lang,
                                include_directories: [platform_inc])
meson.override_dependency('rz_lang', rz_lang_dep)

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
    'datdir=@0@'.format(rizin_datdir_rz),
  ],
)

if not is_static_libs_only
  conf = configuration_data()
  conf.set('RZ_VERSION', rizin_version)
  conf.set('RIZIN_MODULE', rz_lang.name())
  conf.set('RIZIN_MODULE_DEPS', ' '.join(['rz_util', 'rz_cons']))
  conf.set('PACKAGE_RELATIVE_PATH', cmake_package_relative_path)
  conf.set('INSTALL_INCDIR', rizin_incdir)
  conf.set('INSTALL_LIBDIR', rizin_libdir)
  conf.set('INSTALL_PLUGDIR', rizin_plugins)
  conf.set('rizin_libname', rz_lang.name())
  cmake_mod.configure_package_config_file(
    name: conf.get('rizin_libname'),
    input: '../RzModulesConfig.cmake.in',
    install_dir: rizin_cmakedir / conf.get('rizin_libname'),
    configuration: conf,
  )
endif
