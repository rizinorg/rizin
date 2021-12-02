rz_il_sources = [
   'definitions/effect.c',
   'definitions/variable.c',
   'definitions/value.c',
   'definitions/bool.c',
   'definitions/mem.c',
   'definitions/bag.c',
   'theory_bitv.c',
   'theory_effect.c',
   'theory_init.c',
   'theory_bool.c',
   'theory_mem.c',
   'rzil_opcodes.c',
   'rzil_export.c',
   'rzil_vm_events.c',
   'rzil_vm.c',
   'vm_layer.c',
]

rz_il_inc = [
  platform_inc,
]

rz_il = library('rz_il', rz_il_sources,
  include_directories: rz_il_inc,
  c_args: library_cflags,
  dependencies: [
    rz_util_dep,
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  link_args: library_linkflags,
  soversion: rizin_libversion
)

rz_il_dep = declare_dependency(link_with: rz_il,
                                include_directories: rz_il_inc)

pkgconfig_mod.generate(rz_il,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_il',
  filebase: 'rz_il',
  requires: [
    'rz_util',
  ],
  description: 'rizin foundation libraries'
)

conf = configuration_data()
conf.set('RZ_VERSION', rizin_version)
conf.set('RIZIN_MODULE', 'RzIl')
conf.set('INSTALL_INCDIR', rizin_incdir)
conf.set('INSTALL_LIBDIR', rizin_libdir)
conf.set('rizin_libname', rz_il.name())
cmake_mod.configure_package_config_file(
  name: conf.get('RIZIN_MODULE'),
  input: '../RzModulesConfig.cmake.in',
  install_dir: rizin_cmakedir,
  configuration: conf,
)
