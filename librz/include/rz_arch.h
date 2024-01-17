// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ARCH_H
#define RZ_ARCH_H

#include <rz_types.h>
#include <rz_analysis.h>
#include <rz_asm.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_arch_plugin_t {
	RZ_DEPRECATE RzAsmPlugin *p_asm; ///< Assembly Plugin
	RZ_DEPRECATE RzAnalysisPlugin *p_analysis; ///< Analysis Plugin
} RzArchPlugin;

/* plugin pointers */
extern RzArchPlugin rz_arch_plugin_6502;
extern RzArchPlugin rz_arch_plugin_8051;
extern RzArchPlugin rz_arch_plugin_amd29k;
extern RzArchPlugin rz_arch_plugin_arc;
extern RzArchPlugin rz_arch_plugin_arm_as;
extern RzArchPlugin rz_arch_plugin_arm_cs;
extern RzArchPlugin rz_arch_plugin_avr;
extern RzArchPlugin rz_arch_plugin_bf;
extern RzArchPlugin rz_arch_plugin_chip8;
extern RzArchPlugin rz_arch_plugin_cil;
extern RzArchPlugin rz_arch_plugin_cr16;
extern RzArchPlugin rz_arch_plugin_cris;
extern RzArchPlugin rz_arch_plugin_cris_gnu;
extern RzArchPlugin rz_arch_plugin_dalvik;
extern RzArchPlugin rz_arch_plugin_dcpu16;
extern RzArchPlugin rz_arch_plugin_ebc;
extern RzArchPlugin rz_arch_plugin_gb;
extern RzArchPlugin rz_arch_plugin_h8300;
extern RzArchPlugin rz_arch_plugin_hexagon;
extern RzArchPlugin rz_arch_plugin_hexagon_gnu;
extern RzArchPlugin rz_arch_plugin_hppa_gnu;
extern RzArchPlugin rz_arch_plugin_i4004;
extern RzArchPlugin rz_arch_plugin_i8080;
extern RzArchPlugin rz_arch_plugin_java;
extern RzArchPlugin rz_arch_plugin_lanai_gnu;
extern RzArchPlugin rz_arch_plugin_lh5801;
extern RzArchPlugin rz_arch_plugin_lm32;
extern RzArchPlugin rz_arch_plugin_luac;
extern RzArchPlugin rz_arch_plugin_m680x_cs;
extern RzArchPlugin rz_arch_plugin_m68k_cs;
extern RzArchPlugin rz_arch_plugin_malbolge;
extern RzArchPlugin rz_arch_plugin_mcore;
extern RzArchPlugin rz_arch_plugin_mcs96;
extern RzArchPlugin rz_arch_plugin_mips_cs;
extern RzArchPlugin rz_arch_plugin_mips_gnu;
extern RzArchPlugin rz_arch_plugin_msp430;
extern RzArchPlugin rz_arch_plugin_nios2;
extern RzArchPlugin rz_arch_plugin_null;
extern RzArchPlugin rz_arch_plugin_or1k;
extern RzArchPlugin rz_arch_plugin_pic;
extern RzArchPlugin rz_arch_plugin_ppc_as;
extern RzArchPlugin rz_arch_plugin_ppc_cs;
extern RzArchPlugin rz_arch_plugin_propeller;
extern RzArchPlugin rz_arch_plugin_pyc;
extern RzArchPlugin rz_arch_plugin_riscv_gnu;
extern RzArchPlugin rz_arch_plugin_riscv_cs;
extern RzArchPlugin rz_arch_plugin_rl78;
extern RzArchPlugin rz_arch_plugin_rsp;
extern RzArchPlugin rz_arch_plugin_sh;
extern RzArchPlugin rz_arch_plugin_snes;
extern RzArchPlugin rz_arch_plugin_sparc_cs;
extern RzArchPlugin rz_arch_plugin_sparc_gnu;
extern RzArchPlugin rz_arch_plugin_spc700;
extern RzArchPlugin rz_arch_plugin_sysz;
extern RzArchPlugin rz_arch_plugin_tms320;
extern RzArchPlugin rz_arch_plugin_tms320c64x;
extern RzArchPlugin rz_arch_plugin_tricore;
extern RzArchPlugin rz_arch_plugin_tricore_cs;
extern RzArchPlugin rz_arch_plugin_v810;
extern RzArchPlugin rz_arch_plugin_v850;
extern RzArchPlugin rz_arch_plugin_vax;
extern RzArchPlugin rz_arch_plugin_wasm;
extern RzArchPlugin rz_arch_plugin_x86;
extern RzArchPlugin rz_arch_plugin_x86_as;
extern RzArchPlugin rz_arch_plugin_x86_cs;
extern RzArchPlugin rz_arch_plugin_x86_im;
extern RzArchPlugin rz_arch_plugin_x86_nasm;
extern RzArchPlugin rz_arch_plugin_x86_nz;
extern RzArchPlugin rz_arch_plugin_x86_simple;
extern RzArchPlugin rz_arch_plugin_x86_udis;
extern RzArchPlugin rz_arch_plugin_xap;
extern RzArchPlugin rz_arch_plugin_xcore_cs;
extern RzArchPlugin rz_arch_plugin_xtensa;
extern RzArchPlugin rz_arch_plugin_z80;

#ifdef __cplusplus
}
#endif

#endif /* RZ_ARCH_H */
