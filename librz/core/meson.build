subdir('cmd_descs')

rz_core_sources = [
  'agraph.c',
  'analysis_objc.c',
  'analysis_tp.c',
  'basefind.c',
  'cagraph.c',
  'canalysis.c',
  'cannotated_code.c',
  'carg.c',
  'casm.c',
  'cautocmpl.c',
  'cbin.c',
  'cconfig.c',
  'cdebug.c',
  'cdwarf.c',
  'cfile.c',
  'chash.c',
  'cheap.c',
  'cil.c',
  'cio.c',
  'clang.c',
  'cmeta.c',
  'cmp.c',
  'core.c',
  'cparser.c',
  'cpdb.c',
  'cplugin.c',
  'creg.c',
  'csign.c',
  'ctypes.c',
  'cvfile.c',
  'disasm.c',
  'fortune.c',
  'gdiff.c',
  'hack.c',
  'libs.c',
  #'linux_heap_glibc.c',
  'project.c',
  'project_migrate.c',
  'rtr.c',
  #'rtr_http.c',
  #'rtr_shell.c',
  'seek.c',
  'serialize_core.c',
  'task.c',
  'vmarks.c',
  'yank.c',
  'p/core_java.c',
  cmd_descs_ch,
  'cmd/cmd.c',
  #'cmd/cmd_analysis.c',
  'cmd/cmd_api.c',
  #'cmd/cmd_cmp.c',
  #'cmd/cmd_debug.c',
  #'cmd/cmd_egg.c',
  #'cmd/cmd_eval.c',
  #'cmd/cmd_flag.c',
  #'cmd/cmd_help.c',
  #'cmd/cmd_info.c',
  #'cmd/cmd_log.c',
  #'cmd/cmd_macro.c',
  #'cmd/cmd_magic.c',
  #'cmd/cmd_meta.c',
  #'cmd/cmd_open.c',
  #'cmd/cmd_plugins.c',
  #'cmd/cmd_print.c',
  #'cmd/cmd_project.c',
  #'cmd/cmd_quit.c',
  #'cmd/cmd_search.c',
  #'cmd/cmd_search_rop.c',
  #'cmd/cmd_seek.c',
  #'cmd/cmd_type.c',
  #'cmd/cmd_write.c',
  #'cmd/cmd_zign.c',
  'tui/visual.c',
  'tui/vmenus.c',
  'tui/vmenus_graph.c',
  'tui/vmenus_zigns.c',
  'tui/vasm.c',
  'tui/panels.c'
]

rz_core_inc = []
if host_machine.system() != 'windows'
  rz_core_inc += ['../../shlr/heap/include']
else
  rz_core_sources += 'windows_heap.c'
  rz_core_inc += ['../../shlr/heap/include/rz_windows']
endif
rz_core_inc = [platform_inc, include_directories(rz_core_inc), 'cmd_descs']

rz_core_deps = [
  rz_util_dep,
  rz_demangler_dep,
  rz_diff_dep,
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
  rz_sign_dep,
  rz_il_dep,
  rz_analysis_dep,
  rz_type_dep,
  rz_debug_dep,
  rz_config_dep,
  rz_bin_dep,
  platform_deps,
  gdb_dep,
  shell_parser_dep,
  lrt,
  mth
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
  link_args: library_linkflags,
  soversion: rizin_libversion,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_core_dep = declare_dependency(link_with: rz_core,
                                include_directories: rz_core_inc)

pkgconfig_mod.generate(
  rz_core,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_core',
  filebase: 'rz_core',
  requires: pkgconfig_magic_requires + [
    'rz_util',
    'rz_demangler',
    'rz_diff',
    'rz_reg',
    'rz_syscall',
    'rz_search',
    'rz_cons',
    'rz_analysis',
    'rz_socket',
    'rz_type',
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
    'rz_bp',
    'rz_sign',
    'rz_il'
  ],
  description: 'rizin foundation libraries',
  variables: [
    'plugindir=@0@'.format(rizin_plugins),
  ],
)

if not is_static_libs_only
  conf = configuration_data()
  conf.set('RZ_VERSION', rizin_version)
  conf.set('RIZIN_MODULE', rz_core.name())
  conf.set('RIZIN_MODULE_DEPS', ' '.join(['rz_util', 'rz_demangler', 'rz_diff', 'rz_magic',
    'rz_socket', 'rz_flag', 'rz_cons', 'rz_lang', 'rz_hash', 'rz_crypto', 'rz_io', 'rz_reg',
    'rz_bp', 'rz_syscall', 'rz_parse', 'rz_asm', 'rz_egg', 'rz_search', 'rz_sign', 'rz_il',
    'rz_analysis', 'rz_type', 'rz_debug', 'rz_config', 'rz_bin']))
  conf.set('PACKAGE_RELATIVE_PATH', cmake_package_relative_path)
  conf.set('INSTALL_INCDIR', rizin_incdir)
  conf.set('INSTALL_LIBDIR', rizin_libdir)
  conf.set('INSTALL_PLUGDIR', rizin_plugins)
  conf.set('rizin_libname', rz_core.name())
  cmake_mod.configure_package_config_file(
    name: conf.get('rizin_libname'),
    input: '../RzModulesConfig.cmake.in',
    install_dir: rizin_cmakedir / conf.get('rizin_libname'),
    configuration: conf,
  )
endif
