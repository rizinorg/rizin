rz_il_sources = [
   'definitions/label.c',
   'definitions/variable.c',
   'definitions/value.c',
   'definitions/bool.c',
   'definitions/mem.c',
   'definitions/float.c',
   'theory_bitv.c',
   'theory_effect.c',
   'theory_init.c',
   'theory_bool.c',
   'theory_mem.c',
   'theory_fbasic.c',
   'il_opcodes.c',
   'il_export.c',
   'il_events.c',
   'il_reg.c',
   'il_validate.c',
   'il_vm.c',
   'il_vm_eval.c',
]

rz_il_inc = [
  platform_inc,
]

rz_il_deps = [
  rz_util_dep,
  rz_reg_dep
]

rz_il = library('rz_il', rz_il_sources,
  include_directories: rz_il_inc,
  dependencies: rz_il_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_il_dep = declare_dependency(
  link_with: rz_il,
  include_directories: rz_il_inc,
  variables:  {'name': 'rz_il'},
)
meson.override_dependency('rz_il', rz_il_dep)

modules += { 'rz_il': {
    'target': rz_il,
    'dependencies': rz_il_deps,
}}
