project('rz-svd', 'c',
  version: '0.1.0',
  license: 'LGPL3',
  meson_version: '>=0.55.0',
  default_options: [
    'buildtype=debugoptimized',
    'b_vscrt=from_buildtype',
  ]
)

# handle dependencies
rz_util_dep = dependency('rz_util')
yxml_proj = subproject('yxml', default_options: ['default_library=static'])
yxml_dep = yxml_proj.get_variable('yxml_dep')

inc = include_directories('.')

rz_svd = library('rz_svd',
  ['rz_svd.c'],
  dependencies: [
    rz_util_dep,
    yxml_dep,
  ],
  include_directories: inc,
  install: true,
  soversion: '0',
  version: '0.1.0',
)

rz_svd_dep = declare_dependency(
  link_with: rz_svd,
  include_directories: inc,
  dependencies: [rz_util_dep, yxml_dep],
)

meson.override_dependency('rz_svd', rz_svd_dep)

# Install header
install_headers('rz_svd.h', subdir: 'librz')
