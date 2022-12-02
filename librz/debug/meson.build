debug_plugins_list = [
  'bf',
  'bochs',
  'dmp',
  'gdb',
  'io',
  'null',
  'rap',
  'winkd',
]
if get_option('use_gpl')
  debug_plugins_list += 'qnx'
endif
if has_debugger
  debug_plugins_list += ['native']
endif
if host_machine.system() == 'windows'
  debug_plugins_list += 'windbg'
endif

debug_plugins = {
  'conf_name': 'plugins_debug',
  'base_cname': 'rz_debug_plugin_',
  'list': debug_plugins_list,
}

rz_debug_sources = [
  'ddesc.c',
  'debug.c',
  'dreg.c',
  'desil.c',
  'dmap.c',
  'pid.c',
  'plugin.c',
  'dsession.c',
  'dsignal.c',
  'serialize_debug.c',
  'snap.c',
  'trace.c',
  'p/bfvm.c',
  'p/common_windows.c',
  'p/common_winkd.c',
  'p/debug_bf.c',
  'p/debug_bochs.c',
  'p/debug_dmp.c',
  'p/debug_gdb.c',
  'p/debug_io.c',
  'p/debug_null.c',
  'p/debug_rap.c',
  'p/debug_winkd.c',
  #'p/native/arm.c',
  #'p/native/bt/fuzzy-all.c',
  #'p/native/bt/generic-x64.c',
  #'p/native/bt/generic-x86.c',
  #'p/native/bt.c',
  #'p/native/darwin.c',
  #'p/native/drx.c',
  #'p/native/maps/darwin.c',
]

rz_debug_deps = [
  dependency('rzgdb'),
  dependency('rzwinkd'),
  rz_util_dep,
  rz_cons_dep,
  rz_hash_dep,
  rz_io_dep,
  rz_bin_dep,
  rz_reg_dep,
  rz_bp_dep,
  rz_syscall_dep,
  rz_egg_dep,
  rz_analysis_dep,
  rz_type_dep,
  platform_deps
]

if get_option('use_gpl')
  rz_debug_deps += dependency('rzqnx')
  rz_debug_sources += 'p/debug_qnx.c'
endif

if has_debugger
  rz_debug_sources += ['p/debug_native.c']

  if host_machine.system() == 'linux' or host_machine.system() == 'android'
    rz_debug_sources += ['p/native/linux/linux_debug.c']
  endif
  if host_machine.system() == 'linux'
    rz_debug_sources += ['p/native/linux/linux_coredump.c']
  endif

  if host_machine.system() != 'windows'
    rz_debug_sources += [
      'p/native/procfs.c'
    ]
  endif

  if host_machine.system() == 'darwin'
    rz_debug_sources += [
      'p/native/xnu/xnu_debug.c',
      #'p/native/xnu/trap_arm.c',
      #'p/native/xnu/trap_x86.c',
      'p/native/xnu/xnu_excthreads.c',
      'p/native/xnu/xnu_threads.c',
    ]
  endif

  if ['netbsd', 'openbsd', 'freebsd', 'dragonfly'].contains(host_machine.system())
    rz_debug_deps += cc.find_library('kvm', required: true, static: is_static_build)
    rz_debug_sources += [
      'p/native/bsd/bsd_debug.c',
    ]
  endif
endif

if host_machine.system() == 'windows'
  rz_debug_sources += [
    'p/debug_windbg.c',
    'p/native/maps/windows_maps.c',
    'p/native/windows/windows_debug.c',
    'p/native/windows/windows_message.c',
  ]
  rz_debug_deps += dependency('rzw32dbg_wrap')
endif

rz_debug_inc = [
  platform_inc,
  include_directories(
    '../bin/format/elf',
    '../bin/format/dmp',
    '../bin/format/mdmp',
    '../bin/format/pe',
  )
]

rz_debug = library('rz_debug', rz_debug_sources,
  include_directories: rz_debug_inc,
  dependencies: rz_debug_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_debug_dep = declare_dependency(link_with: rz_debug,
                                 include_directories: rz_debug_inc)
meson.override_dependency('rz_debug', rz_debug_dep)

modules += { 'rz_debug': {
    'target': rz_debug,
    'dependencies': [
      'rz_util',
      'rz_hash',
      'rz_reg',
      'rz_syscall',
      'rz_analysis',
      'rz_io',
      'rz_bin',
      'rz_bp',
      'rz_cons',
      'rz_egg',
      'rz_type'
    ],
    'plugins': [debug_plugins]
}}
