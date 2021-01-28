rz_parse_sources = [
  'code.c',
  'filter.c',
  'parse.c',
  'ctype.c',
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
  'p/parse_riscv_pseudo.c',
  'p/parse_z80_pseudo.c'
]

rz_parse = library('rz_parse', rz_parse_sources,
  include_directories: platform_inc,
  c_args: library_cflags,
  dependencies: [
    rz_util_dep,
    rz_flag_dep,
    rz_syscall_dep,
    rz_reg_dep,
    rz_cons_dep,
    tcc_dep,
    mpc_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_parse_dep = declare_dependency(link_with: rz_parse,
                                 include_directories: platform_inc)

pkgconfig_mod.generate(rz_parse,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_parse',
  filebase: 'rz_parse',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util',
    'rz_flag',
    'rz_cons',
    'rz_syscall',
    'rz_reg'
  ],
  description: 'rizin foundation libraries'
)
