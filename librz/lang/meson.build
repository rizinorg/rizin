rz_lang_dependencies = [
  rz_util_dep,
  rz_cons_dep,
]

rz_lang_inc = [platform_inc]

rz_lang_sources = [
  'lang.c',
]

rz_lang = library('rz_lang', rz_lang_sources,
  include_directories: rz_lang_inc,
  c_args: library_cflags,
  dependencies: rz_lang_dependencies + rz_lang_plugins_dep,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_lang_dep = declare_dependency(link_with: rz_lang,
                                include_directories: [platform_inc])

pkgconfig_mod.generate(rz_lang,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_lang',
  filebase: 'rz_lang',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util',
    'rz_cons'
  ],
  description: 'rizin foundation libraries'
)
