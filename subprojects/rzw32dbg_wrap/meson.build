project('rzw32dbg_wrap', 'c',
  license : [ 'LGPL']
)

w32dbg_wrap_inc = include_directories('include')
w32dbg_wrap_src = ['src/w32dbg_wrap.c']
w32dbg_wrap_lib = static_library(
  'rzw32dbg_wrap',
  w32dbg_wrap_src,
  include_directories : w32dbg_wrap_inc,
)
w32dbg_wrap_dep = declare_dependency(
  link_with : w32dbg_wrap_lib,
  include_directories: w32dbg_wrap_inc,
)
meson.override_dependency('rzw32dbg_wrap', w32dbg_wrap_dep)
