rz_search_sources = [
  'bytepat.c',
  'keyword.c',
  'regexp.c',
  'search.c',
  'collection.c',
  'options.c',
  'bytes_search.c',
  'cryptographic_search.c',
  'entropy_search.c',
  'hash_search.c',
  'magic_search.c',
  'string_search.c',
  'value_search.c',
]

rz_search = library('rz_search', rz_search_sources,
  include_directories: [platform_inc],
  dependencies: [rz_util_dep, rz_io_dep, rz_magic_dep, rz_crypto_dep, rz_hash_dep],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_search_dep = declare_dependency(link_with: rz_search,
                                  include_directories: [platform_inc])
meson.override_dependency('rz_search', rz_search_dep)

modules += { 'rz_search': {
    'target': rz_search,
    'dependencies': ['rz_util', 'rz_io', 'rz_magic', 'rz_hash', 'rz_crypto']
}}
