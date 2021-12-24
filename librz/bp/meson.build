rz_bp_sources = [
  'bp.c',
  'bp_io.c',
  'bp_plugin.c',
  'bp_traptrace.c',
  'bp_watch.c',
  'serialize_bp.c',
]

rz_bp_dependencies = [rz_util_dep]

subdir('p')

rz_bp = library('rz_bp', rz_bp_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [rz_bp_dependencies],
  link_with: bp_static_plugins,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  link_args: library_linkflags,
  soversion: rizin_libversion,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_bp_dep = declare_dependency(link_with: rz_bp,
  dependencies: rz_bp_dependencies,
  include_directories: [platform_inc]
)
meson.override_dependency('rz_bp', rz_bp_dep)

foreach p : bp_shared_plugins
  side_plugin = configure_file(
    input: '../shared_plugin.c.in',
    output: 'shared_plugin_@0@.c'.format(p.name()),
    configuration: {
      'lib_type': 'RZ_LIB_TYPE_BP',
      'plugin_type': 'RzBreakpointPlugin',
      'plugin_header': 'rz_bp.h',
      'plugin_name': 'rz_bp_plugin_@0@'.format(p.name()),
    },
  )
  shared_library('bp_' + p.name(), [side_plugin],
    link_whole: p,
    dependencies: [rz_bp_dep],
    install: true,
    install_dir: rizin_plugins,
  )
endforeach

pkgconfig_mod.generate(rz_bp,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_bp',
  filebase: 'rz_bp',
  requires: [
    'rz_util'
  ],
  description: 'rizin foundation libraries',
  variables: [
    'plugindir=@0@'.format(rizin_plugins),
  ],
)

if not is_static_libs_only
  conf = configuration_data()
  conf.set('RZ_VERSION', rizin_version)
  conf.set('RIZIN_MODULE', rz_bp.name())
  conf.set('RIZIN_MODULE_DEPS', ' '.join(['rz_util']))
  conf.set('PACKAGE_RELATIVE_PATH', cmake_package_relative_path)
  conf.set('INSTALL_INCDIR', rizin_incdir)
  conf.set('INSTALL_LIBDIR', rizin_libdir)
  conf.set('INSTALL_PLUGDIR', rizin_plugins)
  conf.set('rizin_libname', rz_bp.name())
  cmake_mod.configure_package_config_file(
    name: conf.get('rizin_libname'),
    input: '../RzModulesConfig.cmake.in',
    install_dir: rizin_cmakedir / conf.get('rizin_libname'),
    configuration: conf,
  )
endif
