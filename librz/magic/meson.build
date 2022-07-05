rz_magic_sources = [
  'apprentice.c',
  'ascmagic.c',
  'fsmagic.c',
  'funcs.c',
  'is_tar.c',
  'magic.c',
  # XXX not used? 'print.c',
  'softmagic.c'
]

rz_magic_deps = [rz_util_dep]
if sys_magic.found()
  message('Use system-provided magic library')
  rz_magic_deps += [sys_magic]
else
  message('Use bundled magic library')
endif

rz_magic = library('rz_magic', rz_magic_sources,
  include_directories: platform_inc,
  dependencies: rz_magic_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_magic_dep = declare_dependency(
  link_with: rz_magic,
  include_directories: platform_inc
)
meson.override_dependency('rz_magic', rz_magic_dep)

pkgconfig_mod.generate(rz_magic,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_magic',
  filebase: 'rz_magic',
  requires: [
    'rz_util'
  ],
  description: 'rizin foundation libraries',
  variables: [
    'datdir=@0@'.format(rizin_datdir_rz),
  ],
)
pkgconfig_magic_requires = ['rz_magic']

if not is_static_libs_only
  conf = configuration_data()
  conf.set('RZ_VERSION', rizin_version)
  conf.set('RIZIN_MODULE', rz_magic.name())
  conf.set('RIZIN_MODULE_DEPS', ' '.join(['rz_util']))
  conf.set('PACKAGE_RELATIVE_PATH', cmake_package_relative_path)
  conf.set('INSTALL_INCDIR', rizin_incdir)
  conf.set('INSTALL_LIBDIR', rizin_libdir)
  conf.set('INSTALL_PLUGDIR', rizin_plugins)
  conf.set('rizin_libname', rz_magic.name())
  cmake_mod.configure_package_config_file(
    name: conf.get('rizin_libname'),
    input: '../RzModulesConfig.cmake.in',
    install_dir: rizin_cmakedir / conf.get('rizin_libname'),
    configuration: conf,
  )
endif

subdir('d')
