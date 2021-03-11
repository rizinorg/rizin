debug_plugins = [
  'bf',
  'bochs',
  'esil',
  'gdb',
  'io',
  'native',
  'null',
  'qnx',
  'rap',
  'winkd'
]

if host_machine.system() == 'windows'
  debug_plugins += 'windbg'
endif

debug_enabled_static_plugins = debug_plugins
debug_enabled_shared_plugins = []

debug_bf_sources = files(
  'debug_bf.c',
  'bfvm.c',
)

debug_bochs_sources = files(
  'debug_bochs.c',
)

debug_bochs_deps = [
  bochs_dep,
  rz_cons_dep,
]

debug_esil_sources = files(
  'debug_esil.c',
)

debug_esil_deps = [
  rz_reg_dep,
  rz_analysis_dep,
]

debug_gdb_sources = files(
  'debug_gdb.c',
)

debug_gdb_deps = [
  gdb_dep,
  rz_reg_dep,
  rz_analysis_dep,
]

debug_io_sources = files(
  'debug_io.c',
)

debug_io_deps = [
  rz_cons_dep,
  rz_analysis_dep,
]

debug_native_sources = files(
  'debug_native.c',
)
debug_native_headers = []
debug_native_deps = []
if host_machine.system() == 'linux' or host_machine.system() == 'android'
  debug_native_sources += files('native/linux/linux_debug.c')
endif
if host_machine.system() == 'linux'
  debug_native_sources += files('native/linux/linux_coredump.c')
  debug_native_headers += ['../../bin/format/elf/']
endif
if host_machine.system() == 'darwin'
  debug_native_sources += files('native/xnu/xnu_debug.c')
endif
if ['netbsd', 'openbsd', 'freebsd', 'dragonfly'].contains(host_machine.system())
  debug_native_deps += [cc.find_library('kvm', required: true, static: is_static_build)]
  debug_native_sources += files('native/bsd/bsd_debug.c')
endif
if host_machine.system() == 'windows'
  debug_native_sources += files(
    'native/windows/windows_debug.c',
    'native/maps/windows_maps.c',
  )
  debug_native_deps += [w32dbg_wrap_dep]
else
  debug_native_sources += files('native/procfs.c')
endif
debug_native_headers = include_directories(debug_native_headers)
debug_native_deps += [
  rz_reg_dep,
  rz_cons_dep,
  rz_egg_dep,
  rz_syscall_dep,
  rz_bp_dep,
  rz_analysis_dep,
]

debug_null_sources = files(
  'debug_null.c',
)

debug_qnx_sources = files(
  'debug_qnx.c',
)

debug_qnx_deps = [
  qnx_dep,
  rz_reg_dep,
]

debug_rap_sources = files(
  'debug_rap.c',
)

debug_rap_deps = [
  rz_io_dep,
  rz_cons_dep,
]

debug_winkd_sources = files(
  'debug_winkd.c',
)

debug_winkd_deps = [
  winkd_dep,
  rz_cons_dep,
  rz_reg_dep,
]

debug_windbg_sources = files(
  'debug_windbg.c',
)
