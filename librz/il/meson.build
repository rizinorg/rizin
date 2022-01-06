rz_il_sources = [
   'definitions/label.c',
   'definitions/variable.c',
   'definitions/value.c',
   'definitions/bool.c',
   'definitions/mem.c',
   'theory_bitv.c',
   'theory_effect.c',
   'theory_init.c',
   'theory_bool.c',
   'theory_mem.c',
   'il_opcodes.c',
   'il_export.c',
   'il_events.c',
   'il_reg.c',
   'il_vm.c',
   'il_vm_eval.c',
]

rz_il_inc = [
  platform_inc,
]

rz_il = library('rz_il', rz_il_sources,
  include_directories: rz_il_inc,
  c_args: library_cflags,
  dependencies: [
    rz_util_dep,
    rz_reg_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  link_args: library_linkflags,
  soversion: rizin_libversion,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_il_dep = declare_dependency(link_with: rz_il,
                                include_directories: rz_il_inc)
meson.override_dependency('rz_il', rz_il_dep)

pkgconfig_mod.generate(rz_il,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_il',
  filebase: 'rz_il',
  requires: [
    'rz_util',
    'rz_reg'
  ],
  description: 'rizin foundation libraries'
)

if not is_static_libs_only
  conf = configuration_data()
  conf.set('RZ_VERSION', rizin_version)
  conf.set('RIZIN_MODULE', rz_il.name())
  conf.set('RIZIN_MODULE_DEPS', ' '.join(['rz_util']))
  conf.set('PACKAGE_RELATIVE_PATH', cmake_package_relative_path)
  conf.set('INSTALL_INCDIR', rizin_incdir)
  conf.set('INSTALL_LIBDIR', rizin_libdir)
  conf.set('INSTALL_PLUGDIR', rizin_plugins)
  conf.set('rizin_libname', rz_il.name())
  cmake_mod.configure_package_config_file(
    name: conf.get('rizin_libname'),
    input: '../RzModulesConfig.cmake.in',
    install_dir: rizin_cmakedir / conf.get('rizin_libname'),
    configuration: conf,
  )
endif
