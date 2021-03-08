rz_analysis_dependencies = [
  rz_util_dep,
  rz_crypto_dep,
  rz_reg_dep,
  rz_syscall_dep,
  rz_search_dep,
  rz_cons_dep,
  rz_flag_dep,
  rz_hash_dep,
  rz_parse_dep,
  rz_asm_dep,
  rz_bin_dep,
]

rz_analysis_sources = [
  'analysis.c',
  'block.c',
  'function.c',
  'jmptbl.c',
  'cc.c',
  'class.c',
  'cond.c',
  'cycles.c',
  'data.c',
  'diff.c',
  'esil.c',
  'esil_stats.c',
  'esil_trace.c',
  'esil_interrupt.c',
  'esil_sources.c',
  'esil_cfg.c',
  'esil_dfg.c',
  'fcn.c',
  'flirt.c',
  'hint.c',
  'labels.c',
  'meta.c',
  'op.c',
  'pin.c',
  'reflines.c',
  'rtti.c',
  'rtti_msvc.c',
  'rtti_itanium.c',
  'sign.c',
  'switch.c',
  'type.c',
  'type_pdb.c',
  'dwarf_process.c',
  'value.c',
  'var.c',
  'vtable.c',
  'xrefs.c',
  'serialize_analysis.c',
]

rz_analysis_inc = [platform_inc]

rz_analysis = library('rz_analysis', rz_analysis_sources,
  include_directories: rz_analysis_inc,
  c_args: library_cflags,
  dependencies: rz_analysis_dependencies,
  link_with: rz_analysis_static_plugins,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_analysis_dep = declare_dependency(link_with: rz_analysis,
                                include_directories: rz_analysis_inc)

pkgconfig_mod.generate(rz_analysis,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_analysis',
  filebase: 'rz_analysis',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util',
    'rz_crypto',
    'rz_reg',
    'rz_asm',
    'rz_parse',
    'rz_syscall',
    'rz_search',
    'rz_cons',
    'rz_bin',
    'rz_flag'
  ],
  description: 'rizin foundation libraries'
)

subdir('d')
