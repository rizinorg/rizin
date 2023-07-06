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
  'old/ddesc.c',
  'old/debug.c',
  'old/dreg.c',
  'old/desil.c',
  'old/dmap.c',
  'old/pid.c',
  'old/plugin.c',
  'old/dsession.c',
  'old/dsignal.c',
  'old/serialize_debug.c',
  'old/snap.c',
  'old/trace.c',
  'old/p/bfvm.c',
  'old/p/common_windows.c',
  'old/p/common_winkd.c',
  'old/p/debug_bf.c',
  'old/p/debug_bochs.c',
  'old/p/debug_dmp.c',
  'old/p/debug_gdb.c',
  'old/p/debug_io.c',
  'old/p/debug_null.c',
  'old/p/debug_rap.c',
  'old/p/debug_winkd.c',
  #'old/p/native/arm.c',
  #'old/p/native/bt/fuzzy-all.c',
  #'old/p/native/bt/generic-x64.c',
  #'old/p/native/bt/generic-x86.c',
  #'old/p/native/bt.c',
  #'old/p/native/darwin.c',
  #'old/p/native/drx.c',
  #'old/p/native/maps/darwin.c',

  # New debugger code.
  'debugger.c',
  'p/debugger_native.c',
  'p/debugger_null.c',
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
  rz_debug_sources += 'old/p/debug_qnx.c'
endif

if has_debugger
  rz_debug_sources += ['old/p/debug_native.c']

  if host_machine.system() == 'linux' or host_machine.system() == 'android'
    rz_debug_sources += ['old/p/native/linux/linux_debug.c']
  endif
  if host_machine.system() == 'linux'
    rz_debug_sources += ['old/p/native/linux/linux_coredump.c']
  endif

  if host_machine.system() != 'windows'
    rz_debug_sources += [
      'old/p/native/procfs.c'
    ]
  endif

  if host_machine.system() == 'darwin'
    rz_debug_sources += [
      'old/p/native/xnu/xnu_debug.c',
      #'old/p/native/xnu/trap_arm.c',
      #'old/p/native/xnu/trap_x86.c',
      'old/p/native/xnu/xnu_excthreads.c',
      'old/p/native/xnu/xnu_threads.c',
    ]
  endif

  if ['netbsd', 'openbsd', 'freebsd', 'dragonfly'].contains(host_machine.system())
    rz_debug_deps += cc.find_library('kvm', required: true, static: is_static_build)
    rz_debug_sources += [
      'old/p/native/bsd/bsd_debug.c',
    ]
  endif
endif

if host_machine.system() == 'windows'
  rz_debug_sources += [
    'old/p/debug_windbg.c',
    'old/p/native/maps/windows_maps.c',
    'old/p/native/windows/windows_debug.c',
    'old/p/native/windows/windows_message.c',
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
