parse_plugins_list = [
  '6502_pseudo',
  'arm_pseudo',
  'att2intel',
  'avr_pseudo',
  'chip8_pseudo',
  'dalvik_pseudo',
  'm68k_pseudo',
  'mips_pseudo',
  'ppc_pseudo',
  'sh_pseudo',
  'tms320_pseudo',
  'v850_pseudo',
  'wasm_pseudo',
  'x86_pseudo',
]

rz_parse_sources = [
  'filter.c',
  'parse.c',
  'p/parse_6502_pseudo.c',
  'p/parse_arm_pseudo.c',
  'p/parse_att2intel.c',
  'p/parse_avr_pseudo.c',
  'p/parse_chip8_pseudo.c',
  'p/parse_dalvik_pseudo.c',
  'p/parse_m68k_pseudo.c',
  'p/parse_mips_pseudo.c',
  'p/parse_ppc_pseudo.c',
  'p/parse_sh_pseudo.c',
  'p/parse_tms320_pseudo.c',
  'p/parse_v850_pseudo.c',
  'p/parse_wasm_pseudo.c',
  'p/parse_x86_pseudo.c',
]

if get_option('use_gpl')
  parse_plugins_list += [
    'riscv_pseudo',
    'z80_pseudo',
  ]

  rz_parse_sources += [
    'p/parse_riscv_pseudo.c',
    'p/parse_z80_pseudo.c',
  ]
endif

parse_plugins = {
  'base_name': 'rz_parse',
  'base_struct': 'RzParsePlugin',
  'list': parse_plugins_list,
}

rz_parse = library('rz_parse', rz_parse_sources,
  include_directories: platform_inc,
  dependencies: [
    rz_util_dep,
    rz_flag_dep,
    rz_syscall_dep,
    rz_reg_dep,
    rz_cons_dep,
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_parse_dep = declare_dependency(link_with: rz_parse,
                                 include_directories: platform_inc)
meson.override_dependency('rz_parse', rz_parse_dep)

modules += { 'rz_parse': {
    'target': rz_parse,
    'dependencies': ['rz_util', 'rz_flag', 'rz_syscall', 'rz_reg', 'rz_cons'],
    'plugins': [parse_plugins]
}}
