rz_egg_sources = [
  'egg.c',
  'egg_Cfile.c',
  'egg_lang.c',
  'emit_arm.c',
  'emit_trace.c',
  'emit_x64.c',
  'emit_x86.c',
  #'p/egg_bind.c',
  #'p/egg_cb.c',
  'p/egg_exec.c',
  #'p/egg_reverse.c',
  #'p/egg_shya.c',
  'p/egg_xor.c'
]

rz_egg = library('rz_egg', rz_egg_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [
    rz_util_dep,
    rz_syscall_dep,
    rz_asm_dep,
    mpc_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  link_args: library_linkflags,
  soversion: rizin_libversion
)

rz_egg_dep = declare_dependency(link_with: rz_egg,
                               include_directories: [platform_inc])

pkgconfig_mod.generate(rz_egg,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_egg',
  filebase: 'rz_egg',
  requires: [
    'rz_util',
    'rz_asm',
    'rz_syscall'
  ],
  description: 'rizin foundation libraries',
  variables: [
    'plugindir=@0@'.format(rizin_plugins),
  ],
)

conf = configuration_data()
conf.set('RZ_VERSION', rizin_version)
conf.set('RIZIN_MODULE', rz_egg.name())
conf.set('RIZIN_MODULE_DEPS', ' '.join(['rz_util', 'rz_asm', 'rz_syscall']))
conf.set('INSTALL_INCDIR', rizin_incdir)
conf.set('INSTALL_LIBDIR', rizin_libdir)
conf.set('INSTALL_PLUGDIR', rizin_plugins)
conf.set('rizin_libname', rz_egg.name())
cmake_mod.configure_package_config_file(
  name: conf.get('rizin_libname'),
  input: '../RzModulesConfig.cmake.in',
  install_dir: rizin_cmakedir,
  configuration: conf,
)
