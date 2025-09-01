debug_plugins_list = [
  'bf',
  'bochs',
  'dmp',
  'gdb',
  'io',
  'null',
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
  'p/debug_winkd.c',
  #'p/native/arm.c',
  #'p/native/bt/fuzzy-all.c',
  #'p/native/bt/generic-x64.c',
  #'p/native/bt/generic-x86.c',
  #'p/native/bt.c',
  #'p/native/darwin.c',
  #'p/native/drx.c',
  #'p/native/maps/darwin.c',
  'bp.c',
  'bp_io.c',
  'bp_traptrace.c',
  'bp_watch.c',
  'serialize_bp.c',
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
  rz_syscall_dep,
  rz_egg_dep,
  rz_arch_dep,
  rz_type_dep,
  platform_deps
]

if get_option('use_gpl')
  rz_debug_deps += dependency('rzqnx')
  rz_debug_sources += 'p/debug_qnx.c'
endif

if has_debugger

  if host_machine.system() == 'linux' or host_machine.system() == 'android'
    rz_debug_sources += ['p/native/linux/linux_debug.c']
  endif
  if host_machine.system() == 'linux'
    rz_debug_sources += ['p/native/linux/linux_coredump.c']
  endif

  # Linux OS
  if host_machine.system() == 'linux'
    if host_machine.cpu_family() == 'x86_64' or host_machine.cpu_family() == 'x86'
      rz_debug_sources += ['p/native/linux_x86_64.c']
    elif host_machine.cpu_family() == 'arm'
      rz_debug_sources += ['p/native/linux_arm.c']
    elif host_machine.cpu_family() == 'aarch64'
      rz_debug_sources += ['p/native/linux_arm64.c']
    elif host_machine.cpu_family() == 'ppc' or host_machine.cpu_family() == 'ppc64'
      rz_debug_sources += ['p/native/linux_ppc.c']
    elif host_machine.cpu_family() == 'mips'
      rz_debug_sources += ['p/native/linux_mips32.c']
    elif host_machine.cpu_family() == 'mips64'
      rz_debug_sources += ['p/native/linux_mips64.c']
    else
      rz_debug_sources += ['p/native/linux_other.c']
    endif

  # Windows OS
  elif host_machine.system() == 'windows'
    if host_machine.cpu_family() == 'x86' or host_machine.cpu_family() == 'x86_64' or host_machine.cpu_family() == 'arm' or host_machine.cpu_family() == 'aarch64'
      rz_debug_sources += ['p/native/windows.c']
    else
      rz_debug_sources += ['p/native/unsupported.c']
    endif

  # FreeBSD OS
  elif host_machine.system() == 'freebsd'
    if host_machine.cpu_family() == 'x86' or host_machine.cpu_family() == 'x86_64' or host_machine.cpu_family() == 'aarch64'
      rz_debug_sources += ['p/native/kfbsd.c']
    else
      rz_debug_sources += ['p/native/unsupported.c']
    endif

  # OpenBSD OS
  elif host_machine.system() == 'openbsd'
    if host_machine.cpu_family() == 'x86_64'
      rz_debug_sources += ['p/native/openbsd.c']
    else
      rz_debug_sources += ['p/native/unsupported.c']
    endif

  # NetBSD OS
  elif host_machine.system() == 'netbsd'
    if host_machine.cpu_family() == 'x86' or host_machine.cpu_family() == 'x86_64'
      rz_debug_sources += ['p/native/netbsd.c']
    else
      rz_debug_sources += ['p/native/unsupported.c']
    endif

  # DragonFlyBSD OS
  elif host_machine.system() == 'dragonfly'
    if host_machine.cpu_family() == 'x86_64'
      rz_debug_sources += ['p/native/dragonfly.c']
    else
      rz_debug_sources += ['p/native/unsupported.c']
    endif

  # Darwin (macOS/iPadOS/iOS)
  elif host_machine.system() == 'darwin'
    if host_machine.cpu_family() == 'x86_64' or host_machine.cpu_family() == 'x86'
      rz_debug_sources += ['p/native/apple_x86_64.c']
    elif host_machine.cpu_family() == 'aarch64'
      rz_debug_sources += ['p/native/apple_aarch64.c']
    elif host_machine.cpu_family() == 'arm'
      rz_debug_sources += ['p/native/apple_arm.c']
    elif host_machine.cpu_family() == 'ppc'
      rz_debug_sources += ['p/native/apple_ppc.c']
    else
      rz_debug_sources += ['p/native/unsupported.c']
    endif

  # Android
  elif host_machine.system() == 'android'
    if host_machine.cpu_family() == 'x86_64' or host_machine.cpu_family() == 'x86'
      rz_debug_sources += ['p/native/android_x86_64.c']
    elif host_machine.cpu_family() == 'arm'
      rz_debug_sources += ['p/native/android_arm.c']
    elif host_machine.cpu_family() == 'aarch64'
      rz_debug_sources += ['p/native/android_arm64.c']
    else
      rz_debug_sources += ['p/native/unsupported.c']
    endif

  # Other OS
  else
    rz_debug_sources += ['p/native/unsupported.c']
  endif

  if host_machine.system() != 'windows'
    rz_debug_sources += [
      'p/native/procfs.c',
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

  if host_machine.system() == 'freebsd'
    rz_debug_deps += cc.find_library('util', required: true, static: is_static_build)
    rz_debug_sources += ['p/native/bsd/kfbsd_debug.c']
  elif host_machine.system() == 'netbsd'
    rz_debug_sources += ['p/native/bsd/netbsd_debug.c']
  elif host_machine.system() == 'openbsd'
    rz_debug_sources += ['p/native/bsd/openbsd_debug.c']
  elif host_machine.system() == 'dragonfly'
    rz_debug_sources += ['p/native/bsd/bsd_debug.c']
  endif

  if ['netbsd', 'openbsd', 'freebsd', 'dragonfly'].contains(host_machine.system())
    rz_debug_deps += cc.find_library('kvm', required: true, static: is_static_build)
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

debug_plugins = {
  'base_name': 'rz_debug',
  'base_struct': 'RzDebugPlugin',
  'list': debug_plugins_list,
}

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
      'rz_arch',
      'rz_io',
      'rz_bin',
      'rz_cons',
      'rz_egg',
      'rz_type'
    ],
    'plugins': [debug_plugins]
}}
