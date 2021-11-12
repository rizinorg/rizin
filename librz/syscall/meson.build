rz_syscall_sources = [
  'syscall.c',
]

rz_syscall = library('rz_syscall', rz_syscall_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [rz_util_dep],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  link_args: library_linkflags,
  soversion: rizin_libversion
)

rz_syscall_dep = declare_dependency(link_with: rz_syscall,
                                   include_directories: [platform_inc])

pkgconfig_mod.generate(rz_syscall,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_syscall',
  filebase: 'rz_syscall',
  requires: [
    'rz_util'
  ],
  description: 'rizin foundation libraries'
)
