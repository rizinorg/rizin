demangler_plugins = [
  'java',
  'msvc',
  'objc',
]

if get_option('use_gpl')
  demangler_plugins += ['cpp', 'rust']
endif

if get_option('use_swift_demangler')
  demangler_plugins += 'swift'
endif

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
  soversion: rizin_libversion,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_demangler_dep = declare_dependency(link_with: rz_demangler, include_directories: [platform_inc])
meson.override_dependency('rz_demangler', rz_demangler_dep)

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
    'datdir=@0@'.format(rizin_datdir_rz),
  ],
)

if not is_static_libs_only
  conf = configuration_data()
  conf.set('RZ_VERSION', rizin_version)
  conf.set('RIZIN_MODULE', rz_demangler.name())
  conf.set('RIZIN_MODULE_DEPS', ' '.join(['rz_util']))
  conf.set('PACKAGE_RELATIVE_PATH', cmake_package_relative_path)
  conf.set('INSTALL_INCDIR', rizin_incdir)
  conf.set('INSTALL_LIBDIR', rizin_libdir)
  conf.set('INSTALL_PLUGDIR', rizin_plugins)
  conf.set('rizin_libname', rz_demangler.name())
  cmake_mod.configure_package_config_file(
    name: conf.get('rizin_libname'),
    input: '../RzModulesConfig.cmake.in',
    install_dir: rizin_cmakedir / conf.get('rizin_libname'),
    configuration: conf,
  )
endif
