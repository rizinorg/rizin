executable('rizin', 'main.c',
  include_directories: [platform_inc],
  dependencies: [
    rz_main_dep,
    rz_util_dep,
  ],
  install: true,
  install_rpath: rpath_exe,
  implicit_include_directories: false
)

meson.add_install_script('meson_install_links.sh')
