project('rzspp', 'c')
spp_version = '1.2.0'

configure_file(input: 'config.def.h',
  output: 'config.h',
  copy: true)

spp_files = [
  'spp.c',
]

spp_inc = [include_directories('.')]

rz_util_dep = dependency('rz_util')
librzspp = static_library('rzspp', spp_files,
  dependencies: [rz_util_dep],
  include_directories: spp_inc,
  c_args: ['-DHAVE_R_UTIL', '-DUSE_R2=1'],
  implicit_include_directories: false
)

spp_static_dep = declare_dependency(
  link_whole: librzspp,
  include_directories: spp_inc,
)
meson.override_dependency('rzspp', spp_static_dep)
