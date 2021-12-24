rz_lang_sources = [
  'lang.c',
]

rz_lang_dependencies = [rz_util_dep, rz_cons_dep]

subdir('p')

rz_lang = library('rz_lang', rz_lang_sources,
  include_directories: platform_inc,
  c_args: library_cflags,
  dependencies: rz_lang_dependencies,
  link_with: lang_static_plugins,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  link_args: library_linkflags,
  soversion: rizin_libversion,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_lang_dep = declare_dependency(link_with: rz_lang,
  dependencies: rz_lang_dependencies,
  include_directories: [platform_inc]
)
meson.override_dependency('rz_lang', rz_lang_dep)

foreach p : lang_shared_plugins
  side_plugin = configure_file(
    input: '../shared_plugin.c.in',
    output: 'shared_plugin_@0@.c'.format(p.name()),
    configuration: {
      'lib_type': 'RZ_LIB_TYPE_LANG',
      'plugin_type': 'RzLangPlugin',
      'plugin_header': 'rz_lang.h',
      'plugin_name': 'rz_lang_plugin_@0@'.format(p.name()),
    },
  )
  shared_library('lang_' + p.name(), [side_plugin],
    link_whole: p,
    dependencies: [rz_lang_dep],
    install: true,
    install_dir: rizin_plugins,
  )
endforeach

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
