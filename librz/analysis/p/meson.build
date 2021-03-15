analysis_plugins = [
  '6502',
  '8051',
  'amd29k',
  'arc',
  'arm_cs',
  'arm_gnu',
  'avr',
  'bf',
  'chip8',
  'cr16',
  'cris',
  'dalvik',
  'ebc',
  'gb',
  'h8300',
  'hexagon',
  'i4004',
  'i8080',
  'java',
  'm68k_cs',
  'm680x_cs',
  'malbolge',
  'mcore',
  'mips_cs',
  'mips_gnu',
  'msp430',
  'nios2',
  'null',
  'or1k',
  'pic',
  'ppc_cs',
  'ppc_gnu',
  'propeller',
  'pyc',
  'riscv',
  'rsp',
  'sh',
  'snes',
  'sparc_cs',
  'sparc_gnu',
  'spc700',
  'sysz',
  'tms320',
  'tricore',
  'v810',
  'v850',
  'vax',
  'wasm',
  'ws',
  'x86_cs',
  'xap',
  'xcore_cs',
  'xtensa',
  'z80',
]

analysis_6502_sources = files(
  'analysis_6502.c',
)

analysis_6502_headers = include_directories(
  '../../asm/arch/6502/',
)

analysis_6502_deps = [
  rz_reg_dep,
]

analysis_6502_cs_sources = files(
  'analysis_6502_cs.c',
)

analysis_6502_cs_deps = [
  capstone_dep,
]

analysis_8051_sources = files(
  'analysis_8051.c',
)

analysis_8051_headers = include_directories(
  '../../asm/arch/8051/',
)

analysis_8051_deps = [
  rz_reg_dep,
]

analysis_amd29k_sources = files(
  'analysis_amd29k.c',
  '../../asm/arch/amd29k/amd29k.c',
)

analysis_amd29k_deps = [
  rz_reg_dep,
]

analysis_arc_sources = files(
  'analysis_arc.c',
)

analysis_arc_deps = [
  rz_reg_dep,
]

analysis_arm_cs_sources = files(
  'analysis_arm_cs.c',
)

analysis_arm_cs_deps = [
  capstone_dep,
  rz_reg_dep,
  rz_search_dep,
]

analysis_arm_gnu_sources = files(
  'analysis_arm_gnu.c',
  '../../asm/arch/arm/winedbg/be_arm.c',
)

analysis_arm_gnu_headers = include_directories(
  '../../asm/arch/arm/',
  '../../asm/arch/include/',
)

analysis_arm_gnu_deps = [
  rz_reg_dep,
]

analysis_avr_sources = files(
  'analysis_avr.c',
  '../../asm/arch/avr/avr_disasm.c',
  '../../asm/arch/avr/format.c',
  '../../asm/arch/avr/disasm.c',
)

analysis_avr_deps = [
  rz_reg_dep,
  rz_crypto_dep,
]

analysis_bf_sources = files(
  'analysis_bf.c',
)

analysis_chip8_sources = files(
  'analysis_chip8.c',
)

analysis_cr16_sources = files(
  'analysis_cr16.c',
  '../../asm/arch/cr16/cr16_disas.c',
)

analysis_cr16_headers = include_directories(
  '../../asm/arch/cr16/',
)

analysis_cris_sources = files(
  'analysis_cris.c',
)

analysis_cris_deps = [
  rz_reg_dep,
]

analysis_dalvik_sources = files(
  'analysis_dalvik.c',
)

analysis_dalvik_deps = [
  rz_reg_dep,
]

analysis_ebc_sources = files(
  'analysis_ebc.c',
  '../../asm/arch/ebc/ebc_disas.c',
)

analysis_ebc_headers = include_directories(
  '../../asm/arch/ebc/',
)

analysis_gb_sources = files(
  'analysis_gb.c',
)

analysis_gb_headers = include_directories(
  '../arch/gb/',
  '../../asm/arch/gb/',
)

analysis_gb_deps = [
  rz_reg_dep,
]

analysis_h8300_sources = files(
  'analysis_h8300.c',
  '../../asm/arch/h8300/h8300_disas.c',
)

analysis_h8300_headers = include_directories(
  '../../asm/arch/h8300/',
)

analysis_h8300_deps = [
  rz_reg_dep,
]

analysis_hexagon_sources = files(
  'analysis_hexagon.c',
  '../arch/hexagon/hexagon_analysis.c',
  '../../asm/arch/hexagon/hexagon.c',
  '../../asm/arch/hexagon/hexagon_disas.c',
)

analysis_hexagon_headers = include_directories(
  '../arch/hexagon/',
  '../../asm/arch/hexagon/',
)

analysis_hexagon_deps = [
  rz_reg_dep,
]

analysis_i4004_sources = files(
  'analysis_i4004.c',
)

analysis_i4004_deps = [
  rz_reg_dep,
]

analysis_i8080_sources = files(
  'analysis_i8080.c',
)

analysis_java_sources = files(
  'analysis_java.c',
  '../../asm/arch/java/code.c',
  '../../asm/arch/java/ops.c',
  '../../bin/format/java/class.c',
  '../../bin/format/java/print.c',
)

analysis_java_headers = include_directories(
  '../../bin/format/',
)

analysis_java_deps = [
  rz_reg_dep,
]

analysis_m68k_cs_sources = files(
  'analysis_m68k_cs.c',
)

analysis_m68k_cs_deps = [
  capstone_dep,
  rz_reg_dep,
]

analysis_m680x_cs_sources = files(
  'analysis_m680x_cs.c',
)

analysis_m680x_cs_deps = [
  capstone_dep,
  rz_reg_dep,
]

analysis_malbolge_sources = files(
  'analysis_malbolge.c',
)

analysis_mcore_sources = files(
  'analysis_mcore.c',
  '../../asm/arch/mcore/mcore.c',
)

analysis_mcore_deps = [
  rz_reg_dep,
]

analysis_mips_cs_sources = files(
  'analysis_mips_cs.c',
)

analysis_mips_cs_deps = [
  capstone_dep,
  rz_reg_dep,
  rz_search_dep,
]

analysis_mips_gnu_sources = files(
  'analysis_mips_gnu.c',
)

analysis_mips_gnu_deps = [
  rz_reg_dep,
]

analysis_msp430_sources = files(
  'analysis_msp430.c',
  '../../asm/arch/msp430/msp430_disas.c',
)

analysis_msp430_headers = include_directories(
  '../../asm/arch/msp430/',
)

analysis_nios2_sources = files(
  'analysis_nios2.c',
)

analysis_null_sources = files(
  'analysis_null.c',
)

analysis_null_deps = [
  rz_reg_dep,
]

analysis_or1k_sources = files(
  'analysis_or1k.c',
  '../../asm/arch/or1k/or1k_disas.c',
)

analysis_or1k_headers = include_directories(
  '../../asm/arch/or1k/',
)

analysis_pic_sources = files(
  'analysis_pic.c',
  '../../asm/arch/pic/pic_midrange.c',
)

analysis_pic_deps = [
  rz_reg_dep,
]

analysis_ppc_cs_sources = files(
  'analysis_ppc_cs.c',
  '../../asm/arch/ppc/libvle/vle.c',
)

analysis_ppc_cs_deps = [
  capstone_dep,
  rz_reg_dep,
  rz_search_dep,
]

analysis_ppc_gnu_sources = files(
  'analysis_ppc_gnu.c',
  '../../asm/arch/ppc/libvle/vle.c',
)

analysis_ppc_gnu_deps = [
  rz_reg_dep,
]

analysis_propeller_sources = files(
  'analysis_propeller.c',
  '../../asm/arch/propeller/propeller_disas.c',
)

analysis_propeller_headers = include_directories(
  '../../asm/arch/propeller/',
)

analysis_pyc_sources = files(
  'analysis_pyc.c',
  '../../asm/arch/pyc/opcode_10.c',
  '../../asm/arch/pyc/opcode_11.c',
  '../../asm/arch/pyc/opcode_12.c',
  '../../asm/arch/pyc/opcode_13.c',
  '../../asm/arch/pyc/opcode_14.c',
  '../../asm/arch/pyc/opcode_15.c',
  '../../asm/arch/pyc/opcode_16.c',
  '../../asm/arch/pyc/opcode_20.c',
  '../../asm/arch/pyc/opcode_21.c',
  '../../asm/arch/pyc/opcode_22.c',
  '../../asm/arch/pyc/opcode_23.c',
  '../../asm/arch/pyc/opcode_24.c',
  '../../asm/arch/pyc/opcode_25.c',
  '../../asm/arch/pyc/opcode_26.c',
  '../../asm/arch/pyc/opcode_27.c',
  '../../asm/arch/pyc/opcode_2x.c',
  '../../asm/arch/pyc/opcode_30.c',
  '../../asm/arch/pyc/opcode_31.c',
  '../../asm/arch/pyc/opcode_32.c',
  '../../asm/arch/pyc/opcode_33.c',
  '../../asm/arch/pyc/opcode_34.c',
  '../../asm/arch/pyc/opcode_35.c',
  '../../asm/arch/pyc/opcode_36.c',
  '../../asm/arch/pyc/opcode_37.c',
  '../../asm/arch/pyc/opcode_38.c',
  '../../asm/arch/pyc/opcode_39.c',
  '../../asm/arch/pyc/opcode_3x.c',
  '../../asm/arch/pyc/opcode_analysis.c',
  '../../asm/arch/pyc/opcode_arg_fmt.c',
  '../../asm/arch/pyc/opcode.c',
  '../../asm/arch/pyc/pyc_dis.c'
)

analysis_riscv_sources = files(
  'analysis_riscv.c',
)

analysis_riscv_deps = [
  rz_reg_dep,
]

analysis_rsp_sources = files(
  'analysis_rsp.c',
  '../../asm/arch/rsp/rsp_idec.c',
)

analysis_rsp_deps = [
  rz_reg_dep,
]

analysis_sh_sources = files(
  'analysis_sh.c',
)

analysis_sh_deps = [
  rz_reg_dep,
]

analysis_snes_sources = files(
  'analysis_snes.c',
)

analysis_sparc_cs_sources = files(
  'analysis_sparc_cs.c',
)

analysis_sparc_cs_deps = [
  capstone_dep,
  rz_reg_dep,
]

analysis_sparc_gnu_sources = files(
  'analysis_sparc_gnu.c',
)

analysis_sparc_gnu_deps = [
  rz_reg_dep,
]

analysis_spc700_sources = files(
  'analysis_spc700.c',
)

analysis_spc700_deps = [
  rz_reg_dep,
]

analysis_sysz_sources = files(
  'analysis_sysz.c',
)

analysis_sysz_deps = [
  capstone_dep,
  rz_reg_dep,
]

analysis_tms320_sources = files(
  'analysis_tms320.c',
  'analysis_tms320_c55x_plus.c',
  '../../asm/arch/tms320/tms320_dasm.c',
  '../../asm/arch/tms320/c55x_plus/ins.c',
  '../../asm/arch/tms320/c55x_plus/c55plus.c',
  '../../asm/arch/tms320/c55x_plus/c55plus_decode.c',
  '../../asm/arch/tms320/c55x_plus/decode_funcs.c',
  '../../asm/arch/tms320/c55x_plus/hashtable.c',
  '../../asm/arch/tms320/c55x_plus/utils.c',
)

analysis_tms320_deps = [
  capstone_dep,
]

analysis_tricore_sources = files(
  'analysis_tricore.c',
)

analysis_tricore_deps = [
  rz_reg_dep,
]

analysis_v810_sources = files(
  'analysis_v810.c',
  '../../asm/arch/v810/v810_disas.c',
)

analysis_v810_headers = include_directories(
  '../../asm/arch/v810/',
)

analysis_v810_deps = [
  rz_reg_dep,
]

analysis_v850_sources = files(
  'analysis_v850.c',
  '../../asm/arch/v850/v850_disas.c',
)

analysis_v850_headers = include_directories(
  '../../asm/arch/v850/',
)

analysis_v850_deps = [
  rz_reg_dep,
  rz_search_dep,
]

analysis_vax_sources = files(
  'analysis_vax.c',
)

analysis_wasm_sources = files(
  'analysis_wasm.c',
  '../../asm/arch/wasm/wasm.c',
)

analysis_wasm_deps = [
  rz_cons_dep,
]

analysis_ws_sources = files(
  'analysis_ws.c',
)

analysis_x86_cs_sources = files(
  'analysis_x86_cs.c',
)

analysis_x86_cs_deps = [
  capstone_dep,
  rz_reg_dep,
  rz_search_dep,
]

analysis_xap_sources = files(
  'analysis_xap.c',
  '../../asm/arch/xap/dis.c',
)

analysis_xap_headers = include_directories(
  '../../asm/arch',
)

analysis_xcore_cs_sources = files(
  'analysis_xcore_cs.c',
)

analysis_xcore_cs_deps = [
  capstone_dep,
]

analysis_xtensa_sources = files(
  'analysis_xtensa.c',
  '../../asm/arch/xtensa/gnu/xtensa-dis.c',
  '../../asm/arch/xtensa/gnu/elf32-xtensa.c',
  '../../asm/arch/xtensa/gnu/xtensa-isa.c',
  '../../asm/arch/xtensa/gnu/xtensa-modules.c',
)

analysis_xtensa_headers = include_directories(
  '../../asm/arch/include/',
)

analysis_z80_sources = files(
  'analysis_z80.c',
)

analysis_z80_deps = [
  rz_reg_dep,
]
