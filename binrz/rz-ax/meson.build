executable('rz-ax', 'rz-ax.c',
  c_args: executable_cflags,
  include_directories: [platform_inc],
  dependencies: [rz_util_dep, rz_main_dep],
  install: true,
  install_rpath: rpath_exe,
  implicit_include_directories: false,
  link_args: executable_linkflags
)
