subdir('cmd_descs')

rz_core_sources = [
  'analysis_tp.c',
  'analysis_objc.c',
  'casm.c',
  'cagraph.c',
  'canalysis.c',
  'ctypes.c',
  'carg.c',
  'cautocmpl.c',
  'cbin.c',
  'cconfig.c',
  'cdebug.c',
  'cio.c',
  'cmd.c',
  cmd_descs_c,
  #'cmd_analysis.c',
  'cmd_api.c',
  #'cmd_cmp.c',
  #'cmd_debug.c',
  #'cmd_egg.c',
  #'cmd_eval.c',
  #'cmd_flag.c',
  #'cmd_hash.c',
  #'cmd_help.c',
  #'cmd_info.c',
  #'cmd_log.c',
  #'cmd_macro.c',
  #'cmd_magic.c',
  #'cmd_meta.c',
  #'cmd_open.c',
  #'cmd_print.c',
  #'cmd_project.c',
  #'cmd_quit.c',
  #'cmd_search.c',
  #'cmd_search_rop.c',
  #'cmd_seek.c',
  #'cmd_type.c',
  #'cmd_write.c',
  #'cmd_zign.c',
  'core.c',
  'disasm.c',
  'cfile.c',
  'fortune.c',
  'gdiff.c',
  'zdiff.c',
  'agraph.c',
  'hack.c',
  'libs.c',
  #'linux_heap_glibc.c',
  'panels.c',
  'cplugin.c',
  'project.c',
  'rtr.c',
  #'rtr_http.c',
  #'rtr_shell.c',
  'seek.c',
  'task.c',
  'vasm.c',
  'visual.c',
  'vmarks.c',
  'vmenus.c',
  'vmenus_graph.c',
  'vmenus_zigns.c',
  'yank.c',
  'p/core_java.c',
  'cannotated_code.c',
  'serialize_core.c'
]

rz_core_inc = []
if host_machine.system() != 'windows'
  rz_core_inc += ['../../shlr/heap/include']
else
  rz_core_sources += 'windows_heap.c'
  rz_core_inc += ['../../shlr/heap/include/rz_windows']
endif
rz_core_inc = [platform_inc, include_directories(rz_core_inc)]

rz_core_deps = [
  rz_util_dep,
  rz_magic_dep,
  rz_socket_dep,
  rz_flag_dep,
  rz_cons_dep,
  rz_lang_dep,
  rz_hash_dep,
  rz_crypto_dep,
  rz_io_dep,
  rz_reg_dep,
  rz_bp_dep,
  rz_syscall_dep,
  rz_parse_dep,
  rz_asm_dep,
  rz_egg_dep,
  rz_search_dep,
  rz_analysis_dep,
  rz_debug_dep,
  rz_config_dep,
  rz_bin_dep,
  platform_deps,
  gdb_dep,
  lrt,
  shell_parser_dep
]

if libuv_dep.found()
  rz_core_deps += libuv_dep
endif

rz_core = library('rz_core', rz_core_sources,
  include_directories: rz_core_inc,
  c_args: library_cflags,
  dependencies: rz_core_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_core_dep = declare_dependency(link_with: rz_core,
                                include_directories: rz_core_inc)

pkgconfig_mod.generate(
  rz_core,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_core',
  filebase: 'rz_core',
  libraries: pkgcfg_sanitize_libs,
  requires: pkgconfig_magic_requires + [
    'rz_util',
    'rz_reg',
    'rz_syscall',
    'rz_search',
    'rz_cons',
    'rz_analysis',
    'rz_socket',
    'rz_io',
    'rz_lang',
    'rz_hash',
    'rz_flag',
    'rz_parse',
    'rz_egg',
    'rz_debug',
    'rz_crypto',
    'rz_config',
    'rz_bin',
    'rz_asm',
    'rz_bp'
  ],
  description: 'rizin foundation libraries'
)
