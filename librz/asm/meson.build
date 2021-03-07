rz_asm_dependencies = [
  rz_util_dep,
  rz_syscall_dep,
  rz_flag_dep,
  rz_parse_dep,
  rz_bin_dep,
]

rz_asm_sources = [
  'asm.c',
  'aop.c',
  'acode.c',
  'binutils_as.c',
]

rz_asm_inc = [
  platform_inc,
]

rz_asm = library('rz_asm', rz_asm_sources,
  include_directories: rz_asm_inc,
  c_args: library_cflags,
  dependencies: rz_asm_dependencies + rz_asm_plugins_dep,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_asm_dep = declare_dependency(link_with: rz_asm,
                               include_directories: rz_asm_inc)

pkgconfig_mod.generate(rz_asm,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_asm',
  filebase: 'rz_asm',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util',
    'rz_syscall',
    'rz_parse',
    'rz_flag',
    'rz_bin',
    'rz_socket'
  ],
  description: 'rizin foundation libraries'
)

subdir('d')
