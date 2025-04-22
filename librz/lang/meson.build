lang_plugins_list = [
  'lib',
  'pipe',
]
if host_machine.system() != 'windows'
  lang_plugins_list += [
    'c',
    'cpipe'
  ]
endif

lang_plugins = {
  'base_name': 'rz_lang',
  'base_struct': 'RzLangPlugin',
  'list': lang_plugins_list,
}

rz_lang_sources = [
  'lang.c',
  'p/lib.c',
  'p/pipe.c',
  'p/pipe_helper.c',
]

if host_machine.system() != 'windows'
  rz_lang_sources += [
    'p/c.c',
    'p/cpipe.c',
  ]
endif

rz_lang = library('rz_lang', rz_lang_sources,
  include_directories: platform_inc,
  dependencies: [rz_util_dep, rz_cons_dep],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_lang_dep = declare_dependency(link_with: rz_lang,
                                include_directories: [platform_inc])
meson.override_dependency('rz_lang', rz_lang_dep)

modules += { 'rz_lang': {
    'target': rz_lang,
    'dependencies': ['rz_util', 'rz_cons'],
    'plugins': [lang_plugins]
}}
