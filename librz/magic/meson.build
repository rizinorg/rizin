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
  c_args: library_cflags,
  dependencies: rz_magic_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  link_args: library_linkflags,
  soversion: rizin_libversion
)

rz_magic_dep = declare_dependency(
  link_with: rz_magic,
  include_directories: platform_inc
)

pkgconfig_mod.generate(rz_magic,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_magic',
  filebase: 'rz_magic',
  requires: [
    'rz_util'
  ],
  description: 'rizin foundation libraries'
)
pkgconfig_magic_requires = ['rz_magic']

conf = configuration_data()
conf.set('RZ_VERSION', rizin_version)
conf.set('RIZIN_MODULE', 'RzMagic')
conf.set('RIZIN_MODULE_DEPS', ' '.join(['RzUtil']))
conf.set('INSTALL_INCDIR', rizin_incdir)
conf.set('INSTALL_LIBDIR', rizin_libdir)
conf.set('rizin_libname', rz_magic.name())
cmake_mod.configure_package_config_file(
  name: conf.get('RIZIN_MODULE'),
  input: '../RzModulesConfig.cmake.in',
  install_dir: rizin_cmakedir,
  configuration: conf,
)
