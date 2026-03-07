
rz_memory_sources = [
  'memory.c',
  'mmap.c',
  'region.c',
]

rz_memory_deps = [
  rz_util_dep,
  platform_deps,
]

rz_memory = library('rz_memory', rz_memory_sources,
  include_directories: platform_inc,
  dependencies: rz_memory_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_memory_dep = declare_dependency(link_with: rz_memory,
                              include_directories: platform_inc)
meson.override_dependency('rz_memory', rz_memory_dep)

modules += { 'rz_memory': {
    'target': rz_memory,
    'dependencies': ['rz_util'],
    'plugins': []
}}
