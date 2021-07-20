rz_il_sources = [
   'definitions/effect.c',
   'definitions/bitvector.c',
   'definitions/vm_defines.c',
   'definitions/bool.c',
   'definitions/mem.c',
   'definitions/wrapper.c',
   'core_theory_bitv.c',
   'core_theory_effect.c',
   'core_theory_init.c',
   'core_theory_bool.c',
   'core_theory_mem.c',
   'core_theory_opcodes.c',
   'core_theory_vm.c',
   'internal_ct_cmd.c',
]

rz_il_inc = [
  platform_inc,
]

rz_il = library('rz_il', rz_il_sources,
  include_directories: rz_il_inc,
  c_args: library_cflags,
  dependencies: [
    rz_util_dep,
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_il_dep = declare_dependency(link_with: rz_il,
                                include_directories: rz_il_inc)

pkgconfig_mod.generate(rz_il,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_il',
  filebase: 'rz_il',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util',
  ],
  description: 'rizin foundation libraries'
)
