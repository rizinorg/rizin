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
rz_util_dep = dependency('rz_util')

inc = include_directories('.')

# Get datadir from parent project if available
if meson.is_subproject()
  rizin_datdir = get_variable('rizin_datdir', get_option('datadir'))
  rizin_datdir_rz = get_variable('rizin_datdir_rz', rizin_datdir / 'rizin')
else
  rizin_datdir_rz = get_option('datadir') / 'rizin'
endif

svd_datadir = rizin_datdir_rz / 'svd'

rz_svd_c_args = [
  '-DRZ_SVD_DATADIR="' + svd_datadir + '"',
]

rz_svd = library('rz_svd',
  ['rz_svd.c'],
  dependencies: [
    yxml_dep,
    rz_util_dep,
  ],
  include_directories: [inc],
  c_args: rz_svd_c_args,
  install: true,
  soversion: '0',
  version: '0.1.0',
)

rz_svd_dep = declare_dependency(
  link_with: rz_svd,
  include_directories: inc,
  dependencies: [yxml_dep, rz_util_dep],
)

meson.override_dependency('rz_svd', rz_svd_dep)

# Install header
install_headers('rz_svd.h', subdir: 'librz')

# Install SVD files
install_subdir('svd',
  install_dir: rizin_datdir_rz,
  strip_directory: false,
  exclude_files: [],
  exclude_directories: []
)
