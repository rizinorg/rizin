rz_syscall_sources = [
  'syscall.c',
]

rz_syscall = library('rz_syscall', rz_syscall_sources,
  include_directories: [platform_inc],
  dependencies: [rz_util_dep],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_syscall_dep = declare_dependency(link_with: rz_syscall,
                                   include_directories: [platform_inc])
meson.override_dependency('rz_syscall', rz_syscall_dep)

modules += { 'rz_syscall': {
    'target': rz_syscall,
    'dependencies': ['rz_util']
}}

subdir('d')
