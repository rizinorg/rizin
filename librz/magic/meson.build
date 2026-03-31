rz_magic_sources = [
  'magic-common.c',
  'magic-load.c',
  'magic-test.c',
  'magic.c'
]

rz_magic_deps = [rz_util_dep]
if sys_magic.found()
  message('Use system-provided magic library')
  rz_magic_deps += [sys_magic]
else
  message('Use bundled magic library')
endif

rz_magic = library('rz_magic', rz_magic_sources,
  include_directories: platform_inc,
  dependencies: rz_magic_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_magic_dep = declare_dependency(
  link_with: rz_magic,
  include_directories: platform_inc
)
meson.override_dependency('rz_magic', rz_magic_dep)

modules += { 'rz_magic': {
    'target': rz_magic,
    'dependencies': ['rz_util']
}}

subdir('d')
