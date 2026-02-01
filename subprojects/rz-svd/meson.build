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
yxml_proj = subproject('yxml', default_options: ['default_library=static'])
yxml_dep = yxml_proj.get_variable('yxml_dep')

# TEMPORARY: Include Rizin headers directly until proper dependency management is set up
# These paths generate sandbox warnings but are necessary for compilation
rz_include_dep = declare_dependency(
  include_directories: [
    include_directories('../../librz/include'),
    include_directories('../../'),
    include_directories('../../librz/util/sdb/src'),
  ]
)

inc = include_directories('.')

rz_svd = library('rz_svd',
  ['rz_svd.c'],
  dependencies: [
    yxml_dep,
    rz_include_dep,
  ],
  install: true,
  soversion: '0',
  version: '0.1.0',
)

rz_svd_dep = declare_dependency(
  link_with: rz_svd,
  include_directories: inc,
  dependencies: [yxml_dep],
)

# Install header
install_headers('rz_svd.h', subdir: 'librz')
