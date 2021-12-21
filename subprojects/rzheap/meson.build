project('rzheap', 'c')

rzheap_dep = declare_dependency(
  include_directories: include_directories('.', 'rz_jemalloc', 'rz_windows'),
)
meson.override_dependency('rzheap', rzheap_dep)
