project('mpc', version: 'd59264ae27228176f5b731871df1a87d7abbb5c8')

mpc_files = [
  'mpc.c'
]

mpc_inc = [include_directories(['.'])]

libmpc = library('mpc', mpc_files,
  include_directories: mpc_inc,
  implicit_include_directories: false
)

mpc_dep = declare_dependency(
  link_with: libmpc,
  include_directories: mpc_inc
)