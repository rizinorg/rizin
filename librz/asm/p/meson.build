asm_plugins = [
  '6502',
  '8051',
  'amd29k',
  'arc',
  'arm_as',
  'arm_cs',
  'arm_gnu',
  'arm_winedbg',
  'avr',
  'bf',
  'chip8',
  'cr16',
  'cris_gnu',
  'dalvik',
  'dcpu16',
  'ebc',
  'gb',
  'h8300',
  'hexagon',
  'hppa_gnu',
  'i4004',
  'i8080',
  'java',
  'lanai_gnu',
  'lh5801',
  'lm32',
  'm68k_cs',
  'm680x_cs',
  'malbolge',
  'mcore',
  'mcs96',
  'mips_cs',
  'mips_gnu',
  'msp430',
  'nios2',
  'or1k',
  'pic',
  'ppc_as',
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
  'tms320c64x',
  'tricore',
  'v810',
  'v850',
  'vax',
  'wasm',
  'ws',
  'x86_as',
  'x86_cs',
  'x86_nasm',
  'x86_nz',
  'xap',
  'xcore_cs',
  'xtensa',
  'z80',
]

asm_enabled_static_plugins = asm_plugins
asm_enabled_shared_plugins = []

asm_6502_sources = files(
  'asm_6502.c',
)

asm_6502_cs_sources = files(
  'asm_6502_cs.c',
)

asm_6502_cs_deps = [
  capstone_dep,
]

asm_8051_sources = files(
  'asm_8051.c',
  '../arch/8051/8051_ass.c',
)

asm_8051_headers = include_directories(
  '../arch/8051',
)

asm_amd29k_sources = files(
  'asm_amd29k.c',
  '../arch/amd29k/amd29k.c',
)

asm_arc_sources = files(
  'asm_arc.c',
  '../arch/arc/gnu/arc-dis.c',
  '../arch/arc/gnu/arc-ext.c',
  '../arch/arc/gnu/arc-opc.c',
  '../arch/arc/gnu/arcompact-dis.c',
)

asm_arc_headers = include_directories(
  '../arch/include',
)

asm_arm_as_sources = files(
  'asm_arm_as.c',
)

asm_arm_cs_sources = files(
  'asm_arm_cs.c',
  '../arch/arm/armass.c',
  '../arch/arm/armass64.c',
)

asm_arm_cs_deps = [
  capstone_dep,
]

asm_arm_gnu_sources = files(
  'asm_arm_gnu.c',
  '../arch/arm/aarch64/aarch64-dis-2.c',
  '../arch/arm/aarch64/aarch64-dis.c',
  '../arch/arm/aarch64/aarch64-opc-2.c',
  '../arch/arm/aarch64/aarch64-opc.c',
  '../arch/arm/armass.c',
  '../arch/arm/armass64.c',
  '../arch/arm/gnu/arm-dis.c',
  '../arch/arm/gnu/floatformat.c',
)

asm_arm_gnu_headers = include_directories(
  '../arch/arm/',
  '../arch/include/',
)

asm_arm_winedbg_sources = files(
  'asm_arm_winedbg.c',
  '../arch/arm/winedbg/be_arm.c',
)

asm_avr_sources = files(
  'asm_avr.c',
  '../arch/avr/avr_disasm.c',
  '../arch/avr/format.c',
  '../arch/avr/disasm.c',
)

asm_bf_sources = files(
  'asm_bf.c',
)

asm_chip8_sources = files(
  'asm_chip8.c',
)

asm_cr16_sources = files(
  'asm_cr16.c',
  '../arch/cr16/cr16_disas.c',
)

asm_cr16_headers = include_directories(
  '../arch/cr16',
)

asm_cris_gnu_sources = files(
  'asm_cris_gnu.c',
  '../arch/cris/gnu/cris-dis.c',
  '../arch/cris/gnu/cris-opc.c',
)

asm_cris_gnu_headers = include_directories(
  '../arch/include/',
)

asm_dalvik_sources = files(
  'asm_dalvik.c',
)

asm_dalvik_headers = include_directories(
  '../arch/',
)

asm_dcpu16_sources = files(
  'asm_dcpu16.c',
)

asm_ebc_sources = files(
  'asm_ebc.c',
  '../arch/ebc/ebc_disas.c',
)

asm_ebc_headers = include_directories(
  '../arch/ebc',
)

asm_gb_sources = files(
  'asm_gb.c',
)

asm_h8300_sources = files(
  'asm_h8300.c',
  '../arch/h8300/h8300_disas.c',
)

asm_h8300_headers = include_directories(
  '../arch/h8300',
)

asm_hexagon_sources = files(
  'asm_hexagon.c',
  '../arch/hexagon/hexagon.c',
  '../arch/hexagon/hexagon_disas.c',
)

asm_hexagon_headers = include_directories(
  '../arch/hexagon',
)

asm_hppa_gnu_sources = files(
  'asm_hppa_gnu.c',
  '../arch/hppa/gnu/hppa-dis.c',
)

asm_hppa_gnu_headers = include_directories(
  '../arch/include',
)

asm_i4004_sources = files(
  'asm_i4004.c',
)

asm_i8080_sources = files(
  'asm_i8080.c',
)

asm_java_sources = files(
  'asm_java.c',
  '../arch/java/code.c',
  '../arch/java/ops.c',
  '../../bin/format/java/class.c',
  '../../bin/format/java/print.c',
)

asm_java_headers = include_directories(
  '../../bin/format/',
)

asm_lanai_gnu_sources = files(
  'asm_lanai_gnu.c',
  '../arch/lanai/gnu/lanai-dis.c',
  '../arch/lanai/gnu/lanai-opc.c',
)

asm_lanai_gnu_headers = include_directories(
  '../arch/include',
)

asm_lh5801_sources = files(
  'asm_lh5801.c',
  '../arch/lh5801/lh5801.c',
)

asm_lh5801_headers = include_directories(
  '../arch/lh5801/',
)

asm_lm32_sources = files(
  'asm_lm32.c',
)

asm_m68k_cs_sources = files(
  'asm_m68k_cs.c',
)

asm_m68k_cs_deps = [
  capstone_dep,
]

asm_m680x_cs_sources = files(
  'asm_m680x_cs.c',
)

asm_m680x_cs_deps = [
  capstone_dep,
]

asm_malbolge_sources = files(
  'asm_malbolge.c',
)

asm_mcs96_sources = files(
  'asm_mcs96.c',
)

asm_mips_cs_sources = files(
  'asm_mips_cs.c',
  '../arch/mips/mipsasm.c',
)

asm_mips_cs_deps = [
  capstone_dep,
]

asm_mips_gnu_sources = files(
  'asm_mips_gnu.c',
  '../arch/mips/gnu/mips-dis.c',
  '../arch/mips/gnu/mips-opc.c',
  '../arch/mips/gnu/mips16-opc.c',
  '../arch/mips/mipsasm.c',
)

asm_mips_gnu_headers = include_directories(
  '../arch/include',
)

asm_msp430_sources = files(
  'asm_msp430.c',
  '../arch/msp430/msp430_disas.c',
)

asm_msp430_headers = include_directories(
  '../arch/msp430',
)

asm_nios2_sources = files(
  'asm_nios2.c',
  '../arch/nios/gnu/nios2-dis.c',
  '../arch/nios/gnu/nios2-opc.c',
)

asm_nios2_headers = include_directories(
  '../arch/include',
)

asm_or1k_sources = files(
  'asm_or1k.c',
  '../arch/or1k/or1k_disas.c',
)

asm_or1k_headers = include_directories(
  '../arch/or1k',
)

asm_pic_sources = files(
  'asm_pic.c',
  '../arch/pic/pic_baseline.c',
  '../arch/pic/pic_midrange.c',
  '../arch/pic/pic_pic18.c',
)

asm_mcore_sources = files(
  'asm_mcore.c',
  '../arch/mcore/mcore.c',
)

asm_mcore_headers = include_directories(
  '../arch/mcore',
)

asm_ppc_as_sources = files(
  'asm_ppc_as.c',
)

asm_ppc_cs_sources = files(
  'asm_ppc_cs.c',
  '../arch/ppc/libvle/vle.c',
  '../arch/ppc/libps/libps.c',
)

asm_ppc_cs_deps = [
  capstone_dep,
]

asm_ppc_gnu_sources = files(
  'asm_ppc_gnu.c',
  '../arch/ppc/gnu/ppc-dis.c',
  '../arch/ppc/gnu/ppc-opc.c',
  '../arch/ppc/libvle/vle.c',
  '../arch/ppc/libps/libps.c',
)

asm_ppc_gnu_headers = include_directories(
  '../arch/include',
)

asm_propeller_sources = files(
  'asm_propeller.c',
  '../arch/propeller/propeller_disas.c',
)

asm_propeller_headers = include_directories(
  '../arch/propeller',
)

asm_pyc_sources = files(
  'asm_pyc.c',
  '../arch/pyc/opcode_10.c',
  '../arch/pyc/opcode_11.c',
  '../arch/pyc/opcode_12.c',
  '../arch/pyc/opcode_13.c',
  '../arch/pyc/opcode_14.c',
  '../arch/pyc/opcode_15.c',
  '../arch/pyc/opcode_16.c',
  '../arch/pyc/opcode_20.c',
  '../arch/pyc/opcode_21.c',
  '../arch/pyc/opcode_22.c',
  '../arch/pyc/opcode_23.c',
  '../arch/pyc/opcode_24.c',
  '../arch/pyc/opcode_25.c',
  '../arch/pyc/opcode_26.c',
  '../arch/pyc/opcode_27.c',
  '../arch/pyc/opcode_2x.c',
  '../arch/pyc/opcode_30.c',
  '../arch/pyc/opcode_31.c',
  '../arch/pyc/opcode_32.c',
  '../arch/pyc/opcode_33.c',
  '../arch/pyc/opcode_34.c',
  '../arch/pyc/opcode_35.c',
  '../arch/pyc/opcode_36.c',
  '../arch/pyc/opcode_37.c',
  '../arch/pyc/opcode_38.c',
  '../arch/pyc/opcode_39.c',
  '../arch/pyc/opcode_3x.c',
  '../arch/pyc/opcode_analysis.c',
  '../arch/pyc/opcode_arg_fmt.c',
  '../arch/pyc/opcode.c',
  '../arch/pyc/pyc_dis.c',
)

asm_riscv_sources = files(
  'asm_riscv.c',
)

asm_rsp_sources = files(
  'asm_rsp.c',
  '../arch/rsp/rsp_idec.c',
)

asm_rsp_headers = include_directories(
  '../arch/rsp',
)

asm_sh_sources = files(
  'asm_sh.c',
  '../arch/sh/gnu/sh-dis.c',
)

asm_sh_headers = include_directories(
  '../arch/include',
)

asm_snes_sources = files(
  'asm_snes.c',
)

asm_sparc_cs_sources = files(
  'asm_sparc_cs.c',
)

asm_sparc_cs_deps = [
  capstone_dep,
]

asm_sparc_gnu_sources = files(
  'asm_sparc_gnu.c',
  '../arch/sparc/gnu/sparc-dis.c',
  '../arch/sparc/gnu/sparc-opc.c',
)

asm_sparc_gnu_headers = include_directories(
  '../arch/include',
)

asm_spc700_sources = files(
  'asm_spc700.c',
)

asm_sysz_sources = files(
  'asm_sysz.c',
)

asm_sysz_deps = [
  capstone_dep,
]

asm_tms320_sources = files(
  'asm_tms320.c',
  '../arch/tms320/c55x_plus/c55plus.c',
  '../arch/tms320/c55x_plus/c55plus_decode.c',
  '../arch/tms320/c55x_plus/decode_funcs.c',
  '../arch/tms320/c55x_plus/hashtable.c',
  '../arch/tms320/c55x_plus/ins.c',
  '../arch/tms320/c55x_plus/utils.c',
  '../arch/tms320/tms320_dasm.c',
)

asm_tms320_deps = [
  capstone_dep,
]

asm_tms320c64x_sources = files(
  'asm_tms320c64x.c',
)

asm_tms320c64x_deps = [
  capstone_dep,
]

asm_tricore_sources = files(
  'asm_tricore.c',
  '../arch/tricore/gnu/cpu-tricore.c',
  '../arch/tricore/gnu/tricore-dis.c',
  '../arch/tricore/gnu/tricore-opc.c',
)

asm_tricore_headers = include_directories(
  '../arch/include',
)

asm_v810_sources = files(
  'asm_v810.c',
  '../arch/v810/v810_disas.c',
)

asm_v810_headers = include_directories(
  '../arch/v810',
)

asm_v850_sources = files(
  'asm_v850.c',
  '../arch/v850/v850_disas.c',
)

asm_v850_headers = include_directories(
  '../arch/v850',
)

asm_vax_sources = files(
  'asm_vax.c',
  '../arch/vax/vax-dis.c',
)

asm_vax_headers = include_directories(
  '../arch/include',
)

asm_wasm_sources = files(
  'asm_wasm.c',
  '../arch/wasm/wasm.c',
)

asm_ws_sources = files(
  'asm_ws.c',
  '../arch/whitespace/wsdis.c',
)

asm_x86_as_sources = files(
  'asm_x86_as.c',
)

asm_x86_cs_sources = files(
  'asm_x86_cs.c',
)

asm_x86_cs_deps = [
  capstone_dep,
]

asm_x86_nasm_sources = files(
  'asm_x86_nasm.c',
)

asm_x86_nz_sources = files(
  'asm_x86_nz.c',
)

asm_x86_nz_deps = [
  rz_flag_dep,
]

asm_xap_sources = files(
  'asm_xap.c',
  '../arch/xap/dis.c',
)

asm_xap_headers = include_directories(
  '../arch',
)

asm_xcore_cs_sources = files(
  'asm_xcore_cs.c',
)

asm_xcore_cs_deps = [
  capstone_dep,
]

asm_xtensa_sources = files(
  'asm_xtensa.c',
  '../arch/xtensa/gnu/elf32-xtensa.c',
  '../arch/xtensa/gnu/xtensa-dis.c',
  '../arch/xtensa/gnu/xtensa-isa.c',
  '../arch/xtensa/gnu/xtensa-modules.c',
)

asm_xtensa_headers = include_directories(
  '../arch/include',
)

asm_z80_sources = files(
  'asm_z80.c',
  '../arch/z80/z80.c',
)
