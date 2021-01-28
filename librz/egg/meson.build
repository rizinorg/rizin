rz_egg_sources = [
  'egg.c',
  'egg_Cfile.c',
  'egg_lang.c',
  'emit_arm.c',
  'emit_trace.c',
  'emit_x64.c',
  'emit_x86.c',
  #'p/egg_bind.c',
  #'p/egg_cb.c',
  'p/egg_exec.c',
  #'p/egg_reverse.c',
  #'p/egg_shya.c',
  'p/egg_xor.c'
]

rz_egg = library('rz_egg', rz_egg_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [
    rz_util_dep,
    rz_syscall_dep,
    rz_asm_dep,
    mpc_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_egg_dep = declare_dependency(link_with: rz_egg,
                               include_directories: [platform_inc])

pkgconfig_mod.generate(rz_egg,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_egg',
  filebase: 'rz_egg',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util',
    'rz_asm',
    'rz_syscall'
  ],
  description: 'rizin foundation libraries'
)
