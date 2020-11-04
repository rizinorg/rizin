rz_cons_sources = [
  'canvas.c',
  'canvas_line.c',
  'cons.c',
  'html.c',
  # 'dietline.c',
  'editor.c',
  'grep.c',
  'hud.c',
  'input.c',
  'less.c',
  'line.c',
  'more.c',
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
  soversion: rizin_libversion
)

rz_cons_dep = declare_dependency(link_with: rz_cons,
                                include_directories: [platform_inc])

pkgconfig_mod.generate(rz_cons,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_cons',
  filebase: 'rz_cons',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util'
  ],
  description: 'rizin foundation libraries'
)
