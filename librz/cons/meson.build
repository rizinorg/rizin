rz_cons_sources = [
  'bar.c',
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
  'histogram.c',
  'output.c',
  'pager.c',
  'pal.c',
  'prompt.c',
  'cpipe.c',
  'rgb.c',
  'cutf8.c'
]

rz_cons = library('rz_cons', rz_cons_sources,
  include_directories: [platform_inc],
  dependencies: [rz_util_dep],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_cons_dep = declare_dependency(link_with: rz_cons,
                                include_directories: [platform_inc])
meson.override_dependency('rz_cons', rz_cons_dep)

modules += { 'rz_cons': {
    'target': rz_cons,
    'dependencies': ['rz_util']
}}

subdir('d')
