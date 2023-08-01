project('rzwinkd', 'c',
  license: 'LGPL-3.0-only',
  meson_version: '>=0.55.0',
  default_options: [
    'c_std=c99',
  ]
)

cc = meson.get_compiler('c')

winkd_files = [
  'iob_pipe.c',
  'iob_net.c',
  'kd.c',
  'transport.c',
  'winkd.c',
]

winkd_inc = [include_directories('.')]

rz_util_dep = dependency('rz_util')
rz_socket_dep = dependency('rz_socket')
rz_hash_dep = dependency('rz_hash')
rz_crypto_dep = dependency('rz_crypto')

librzwinkd_deps = [rz_util_dep, rz_socket_dep, rz_hash_dep, rz_crypto_dep]
if host_machine.system() == 'haiku'
  librzwinkd_deps += [
    cc.find_library('network')
  ]
endif

librzwinkd = static_library('rzwinkd', winkd_files,
  dependencies: librzwinkd_deps,
  include_directories: winkd_inc,
  implicit_include_directories: false
)

winkd_dep = declare_dependency(
  link_with: librzwinkd,
  include_directories: winkd_inc
)
meson.override_dependency('rzwinkd', winkd_dep)
