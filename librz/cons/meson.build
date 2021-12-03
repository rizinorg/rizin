rz_cons_sources = [
  'canvas.c',
  'canvas_line.c',
  'cons.c',
  'html.c',
  # 'dietline.c',
  'grep.c',
  'hud.c',
  'input.c',
  'less.c',
  'line.c',
  'output.c',
  'pager.c',
  'pal.c',
  'cpipe.c',
  'rgb.c',
  'cutf8.c'
]

rz_cons = library('rz_cons', rz_cons_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [rz_util_dep],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  link_args: library_linkflags,
  soversion: rizin_libversion
)

rz_cons_dep = declare_dependency(link_with: rz_cons,
                                include_directories: [platform_inc])

pkgconfig_mod.generate(rz_cons,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_cons',
  filebase: 'rz_cons',
  requires: [
    'rz_util'
  ],
  description: 'rizin foundation libraries'
)

conf = configuration_data()
conf.set('RZ_VERSION', rizin_version)
conf.set('RIZIN_MODULE', rz_cons.name())
conf.set('RIZIN_MODULE_DEPS', ' '.join(['rz_util']))
conf.set('INSTALL_INCDIR', rizin_incdir)
conf.set('INSTALL_LIBDIR', rizin_libdir)
conf.set('INSTALL_PLUGDIR', rizin_plugins)
conf.set('rizin_libname', rz_cons.name())
cmake_mod.configure_package_config_file(
  name: conf.get('rizin_libname'),
  input: '../RzModulesConfig.cmake.in',
  install_dir: rizin_cmakedir,
  configuration: conf,
)
