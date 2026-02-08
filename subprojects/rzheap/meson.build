project('rzheap', 'c')

rzheap_incdir = join_paths(get_option('includedir'), 'librz')
install_headers(
  ['rz_glibc/glibc_types.h', 'rz_glibc/glibc_versions.h'],
  install_dir: join_paths(rzheap_incdir, 'rz_glibc'),
)

rzheap_dep = declare_dependency(
  include_directories: include_directories('.', 'rz_jemalloc', 'rz_glibc', 'rz_windows'),
)
meson.override_dependency('rzheap', rzheap_dep)
