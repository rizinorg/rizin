rz_debug_dependencies = [
  rz_util_dep,
  rz_cons_dep,
  rz_hash_dep,
  rz_io_dep,
  rz_reg_dep,
  rz_bp_dep,
  rz_syscall_dep,
  rz_egg_dep,
  rz_analysis_dep,
]

rz_debug_sources = [
  'arg.c',
  'ddesc.c',
  'debug.c',
  'dreg.c',
  'desil.c',
  'dmap.c',
  'pid.c',
  'plugin.c',
  'dsession.c',
  'dsignal.c',
  'snap.c',
  'trace.c',
]

if host_machine.system() == 'windows'
  rz_debug_sources += [
    'p/native/windows/windows_message.c',
  ]
endif

rz_debug_inc = [
  platform_inc,
]

rz_debug = library('rz_debug', rz_debug_sources,
  include_directories: rz_debug_inc,
  c_args: library_cflags,
  dependencies: rz_debug_dependencies + rz_debug_plugins_dep,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_debug_dep = declare_dependency(link_with: rz_debug,
                                 include_directories: rz_debug_inc)

pkgconfig_mod.generate(rz_debug,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_debug',
  filebase: 'rz_debug',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util',
    'rz_hash',
    'rz_reg',
    'rz_syscall',
    'rz_analysis',
    'rz_io',
    'rz_bp',
    'rz_cons',
    'rz_egg',
  ],
  description: 'rizin foundation libraries'
)
