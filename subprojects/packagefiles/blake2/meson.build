project('blake2', 'c',
  version : '0.0.1',
  license : 'CC0',
  meson_version : '>=0.57.0',
)

blake2_inc = include_directories('ref')

blake2_sources = files(
  'ref/blake2b-ref.c',
  'ref/blake2s-ref.c',
  'ref/blake2bp-ref.c',
  'ref/blake2sp-ref.c',
  'ref/blake2xb-ref.c',
  'ref/blake2xs-ref.c',
)

blake2_lib = static_library('blake2',
  blake2_sources,
  include_directories : blake2_inc,
  install : false,
)

libblake2_dep = declare_dependency(
  link_with : blake2_lib,
  include_directories : blake2_inc,
)

meson.override_dependency('libblake2', libblake2_dep)