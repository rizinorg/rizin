project('rzbochs', 'c',
  license : [ 'LGPL']
)

bochs_files = [
  'src/libbochs.c'
]

bochs_inc = [include_directories('include')]
rz_util_dep = dependency('rz_util')

librzbochs = static_library('rzbochs', bochs_files,
  dependencies: [rz_util_dep],
  include_directories: bochs_inc,
  implicit_include_directories: false
)

bochs_dep = declare_dependency(
  link_with: librzbochs,
  include_directories: bochs_inc
)
meson.override_dependency('rzbochs', bochs_dep)
