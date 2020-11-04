rz_search_sources = [
  'aes-find.c',
  'bytepat.c',
  'keyword.c',
  'regexp.c',
  'privkey-find.c',
  'search.c',
  'strings.c'
]

rz_search = library('rz_search', rz_search_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [rz_util_dep],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_search_dep = declare_dependency(link_with: rz_search,
                                  include_directories: [platform_inc])

pkgconfig_mod.generate(rz_search,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_search',
  filebase: 'rz_search',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util'
  ],
  description: 'rizin foundation libraries'
)
