// SPDX-FileCopyrightText: 2021 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

// LLVM commit: b6f51787f6c8e77143f0aef6b58ddc7c55741d5c
// LLVM commit date: 2023-11-15 07:10:59 -0800 (ISO 8601 format)
// Date of code generation: 2024-03-16 06:22:39-05:00
//========================================
// The following code is generated.
// Do not edit. Repository of code generator:
// https://github.com/rizinorg/rz-hexagon

#ifndef HEXAGON_REG_TABLES_H
#define HEXAGON_REG_TABLES_H

#include <hexagon/hexagon.h>

/**
 * \brief Lookup table for register alias.
 *
 */
HexRegAliasMapping hex_alias_reg_lt_v69[] = {
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C0 }, // HEX_REG_ALIAS_SA0
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C1 }, // HEX_REG_ALIAS_LC0
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C2 }, // HEX_REG_ALIAS_SA1
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C3 }, // HEX_REG_ALIAS_LC1
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C4 }, // HEX_REG_ALIAS_P3_0
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C5 }, // HEX_REG_ALIAS_C5
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C6 }, // HEX_REG_ALIAS_M0
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C7 }, // HEX_REG_ALIAS_M1
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C8 }, // HEX_REG_ALIAS_USR
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C9 }, // HEX_REG_ALIAS_PC
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C10 }, // HEX_REG_ALIAS_UGP
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C11 }, // HEX_REG_ALIAS_GP
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C12 }, // HEX_REG_ALIAS_CS0
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C13 }, // HEX_REG_ALIAS_CS1
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C14 }, // HEX_REG_ALIAS_UPCYCLELO
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C15 }, // HEX_REG_ALIAS_UPCYCLEHI
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C16 }, // HEX_REG_ALIAS_FRAMELIMIT
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C17 }, // HEX_REG_ALIAS_FRAMEKEY
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C18 }, // HEX_REG_ALIAS_PKTCOUNTLO
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C19 }, // HEX_REG_ALIAS_PKTCOUNTHI
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C20 }, // HEX_REG_ALIAS_C20
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C30 }, // HEX_REG_ALIAS_UTIMERLO
	{ HEX_REG_CLASS_CTR_REGS, HEX_REG_CTR_REGS_C31 }, // HEX_REG_ALIAS_UTIMERHI
	{ HEX_REG_CLASS_CTR_REGS64, HEX_REG_CTR_REGS64_C1_0 }, // HEX_REG_ALIAS_LC0_SA0
	{ HEX_REG_CLASS_CTR_REGS64, HEX_REG_CTR_REGS64_C3_2 }, // HEX_REG_ALIAS_LC1_SA1
	{ HEX_REG_CLASS_CTR_REGS64, HEX_REG_CTR_REGS64_C7_6 }, // HEX_REG_ALIAS_M1_0
	{ HEX_REG_CLASS_CTR_REGS64, HEX_REG_CTR_REGS64_C13_12 }, // HEX_REG_ALIAS_CS1_0
	{ HEX_REG_CLASS_CTR_REGS64, HEX_REG_CTR_REGS64_C15_14 }, // HEX_REG_ALIAS_UPCYCLE
	{ HEX_REG_CLASS_CTR_REGS64, HEX_REG_CTR_REGS64_C19_18 }, // HEX_REG_ALIAS_PKTCOUNT
	{ HEX_REG_CLASS_CTR_REGS64, HEX_REG_CTR_REGS64_C31_30 }, // HEX_REG_ALIAS_UTIMER
	{ HEX_REG_CLASS_DOUBLE_REGS, HEX_REG_DOUBLE_REGS_R31_30 }, // HEX_REG_ALIAS_LR_FP
	{ HEX_REG_CLASS_GUEST_REGS, HEX_REG_GUEST_REGS_G0 }, // HEX_REG_ALIAS_GELR
	{ HEX_REG_CLASS_GUEST_REGS, HEX_REG_GUEST_REGS_G1 }, // HEX_REG_ALIAS_GSR
	{ HEX_REG_CLASS_GUEST_REGS, HEX_REG_GUEST_REGS_G2 }, // HEX_REG_ALIAS_GOSP
	{ HEX_REG_CLASS_GUEST_REGS, HEX_REG_GUEST_REGS_G3 }, // HEX_REG_ALIAS_GBADVA
	{ HEX_REG_CLASS_GUEST_REGS, HEX_REG_GUEST_REGS_G16 }, // HEX_REG_ALIAS_GPMUCNT4
	{ HEX_REG_CLASS_GUEST_REGS, HEX_REG_GUEST_REGS_G17 }, // HEX_REG_ALIAS_GPMUCNT5
	{ HEX_REG_CLASS_GUEST_REGS, HEX_REG_GUEST_REGS_G18 }, // HEX_REG_ALIAS_GPMUCNT6
	{ HEX_REG_CLASS_GUEST_REGS, HEX_REG_GUEST_REGS_G19 }, // HEX_REG_ALIAS_GPMUCNT7
	{ HEX_REG_CLASS_GUEST_REGS, HEX_REG_GUEST_REGS_G24 }, // HEX_REG_ALIAS_GPCYCLELO
	{ HEX_REG_CLASS_GUEST_REGS, HEX_REG_GUEST_REGS_G25 }, // HEX_REG_ALIAS_GPCYCLEHI
	{ HEX_REG_CLASS_GUEST_REGS, HEX_REG_GUEST_REGS_G26 }, // HEX_REG_ALIAS_GPMUCNT0
	{ HEX_REG_CLASS_GUEST_REGS, HEX_REG_GUEST_REGS_G27 }, // HEX_REG_ALIAS_GPMUCNT1
	{ HEX_REG_CLASS_GUEST_REGS, HEX_REG_GUEST_REGS_G28 }, // HEX_REG_ALIAS_GPMUCNT2
	{ HEX_REG_CLASS_GUEST_REGS, HEX_REG_GUEST_REGS_G29 }, // HEX_REG_ALIAS_GPMUCNT3
	{ HEX_REG_CLASS_INT_REGS, HEX_REG_INT_REGS_R29 }, // HEX_REG_ALIAS_SP
	{ HEX_REG_CLASS_INT_REGS, HEX_REG_INT_REGS_R30 }, // HEX_REG_ALIAS_FP
	{ HEX_REG_CLASS_INT_REGS, HEX_REG_INT_REGS_R31 }, // HEX_REG_ALIAS_LR
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S0 }, // HEX_REG_ALIAS_SGP0
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S1 }, // HEX_REG_ALIAS_SGP1
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S2 }, // HEX_REG_ALIAS_STID
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S3 }, // HEX_REG_ALIAS_ELR
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S4 }, // HEX_REG_ALIAS_BADVA0
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S5 }, // HEX_REG_ALIAS_BADVA1
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S6 }, // HEX_REG_ALIAS_SSR
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S7 }, // HEX_REG_ALIAS_CCR
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S8 }, // HEX_REG_ALIAS_HTID
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S9 }, // HEX_REG_ALIAS_BADVA
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S10 }, // HEX_REG_ALIAS_IMASK
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S16 }, // HEX_REG_ALIAS_EVB
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S17 }, // HEX_REG_ALIAS_MODECTL
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S18 }, // HEX_REG_ALIAS_SYSCFG
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S19 }, // HEX_REG_ALIAS_S19
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S20 }, // HEX_REG_ALIAS_S20
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S21 }, // HEX_REG_ALIAS_VID
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S22 }, // HEX_REG_ALIAS_S22
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S27 }, // HEX_REG_ALIAS_CFGBASE
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S28 }, // HEX_REG_ALIAS_DIAG
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S29 }, // HEX_REG_ALIAS_REV
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S30 }, // HEX_REG_ALIAS_PCYCLELO
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S31 }, // HEX_REG_ALIAS_PCYCLEHI
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S32 }, // HEX_REG_ALIAS_ISDBST
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S33 }, // HEX_REG_ALIAS_ISDBCFG0
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S34 }, // HEX_REG_ALIAS_ISDBCFG1
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S36 }, // HEX_REG_ALIAS_BRKPTPC0
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S37 }, // HEX_REG_ALIAS_BRKPTCFG0
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S38 }, // HEX_REG_ALIAS_BRKPTPC1
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S39 }, // HEX_REG_ALIAS_BRKPTCFG1
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S40 }, // HEX_REG_ALIAS_ISDBMBXIN
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S41 }, // HEX_REG_ALIAS_ISDBMBXOUT
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S42 }, // HEX_REG_ALIAS_ISDBEN
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S43 }, // HEX_REG_ALIAS_ISDBGPR
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S48 }, // HEX_REG_ALIAS_PMUCNT0
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S49 }, // HEX_REG_ALIAS_PMUCNT1
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S50 }, // HEX_REG_ALIAS_PMUCNT2
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S51 }, // HEX_REG_ALIAS_PMUCNT3
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S52 }, // HEX_REG_ALIAS_PMUEVTCFG
	{ HEX_REG_CLASS_SYS_REGS, HEX_REG_SYS_REGS_S53 }, // HEX_REG_ALIAS_PMUCFG
	{ HEX_REG_CLASS_SYS_REGS64, HEX_REG_SYS_REGS64_S1_0 }, // HEX_REG_ALIAS_SGP1_0
	{ HEX_REG_CLASS_SYS_REGS64, HEX_REG_SYS_REGS64_S5_4 }, // HEX_REG_ALIAS_BADVA1_0
	{ HEX_REG_CLASS_SYS_REGS64, HEX_REG_SYS_REGS64_S7_6 }, // HEX_REG_ALIAS_CCR_SSR
	{ HEX_REG_CLASS_SYS_REGS64, HEX_REG_SYS_REGS64_S31_30 }, // HEX_REG_ALIAS_PCYCLE
};

/**
 * \brief Lookup table for register names and alias of class CtrRegs.
 */
HexRegNames hexagon_ctrregs_lt_v69[] = {
	{ "C0", "SA0", "C0_tmp", "sa0_tmp" }, // HEX_REG_CTR_REGS_C0
	{ "C1", "LC0", "C1_tmp", "lc0_tmp" }, // HEX_REG_CTR_REGS_C1
	{ "C2", "SA1", "C2_tmp", "sa1_tmp" }, // HEX_REG_CTR_REGS_C2
	{ "C3", "LC1", "C3_tmp", "lc1_tmp" }, // HEX_REG_CTR_REGS_C3
	{ "C4", "P3:0", "C4_tmp", "p3:0_tmp" }, // HEX_REG_CTR_REGS_C4
	{ "C5", "C5", "C5_tmp", "c5_tmp" }, // HEX_REG_CTR_REGS_C5
	{ "C6", "M0", "C6_tmp", "m0_tmp" }, // HEX_REG_CTR_REGS_C6
	{ "C7", "M1", "C7_tmp", "m1_tmp" }, // HEX_REG_CTR_REGS_C7
	{ "C8", "USR", "C8_tmp", "usr_tmp" }, // HEX_REG_CTR_REGS_C8
	{ "C9", "PC", "C9_tmp", "pc_tmp" }, // HEX_REG_CTR_REGS_C9
	{ "C10", "UGP", "C10_tmp", "ugp_tmp" }, // HEX_REG_CTR_REGS_C10
	{ "C11", "GP", "C11_tmp", "gp_tmp" }, // HEX_REG_CTR_REGS_C11
	{ "C12", "CS0", "C12_tmp", "cs0_tmp" }, // HEX_REG_CTR_REGS_C12
	{ "C13", "CS1", "C13_tmp", "cs1_tmp" }, // HEX_REG_CTR_REGS_C13
	{ "C14", "UPCYCLELO", "C14_tmp", "upcyclelo_tmp" }, // HEX_REG_CTR_REGS_C14
	{ "C15", "UPCYCLEHI", "C15_tmp", "upcyclehi_tmp" }, // HEX_REG_CTR_REGS_C15
	{ "C16", "FRAMELIMIT", "C16_tmp", "framelimit_tmp" }, // HEX_REG_CTR_REGS_C16
	{ "C17", "FRAMEKEY", "C17_tmp", "framekey_tmp" }, // HEX_REG_CTR_REGS_C17
	{ "C18", "PKTCOUNTLO", "C18_tmp", "pktcountlo_tmp" }, // HEX_REG_CTR_REGS_C18
	{ "C19", "PKTCOUNTHI", "C19_tmp", "pktcounthi_tmp" }, // HEX_REG_CTR_REGS_C19
	{ "C20", "C20", "C20_tmp", "C20_tmp" }, // HEX_REG_CTR_REGS_C20
	{ "C21", "C21", "C21_tmp", "c21_tmp" }, // HEX_REG_CTR_REGS_C21
	{ "C22", "C22", "C22_tmp", "c22_tmp" }, // HEX_REG_CTR_REGS_C22
	{ "C23", "C23", "C23_tmp", "c23_tmp" }, // HEX_REG_CTR_REGS_C23
	{ "C24", "C24", "C24_tmp", "c24_tmp" }, // HEX_REG_CTR_REGS_C24
	{ "C25", "C25", "C25_tmp", "c25_tmp" }, // HEX_REG_CTR_REGS_C25
	{ "C26", "C26", "C26_tmp", "c26_tmp" }, // HEX_REG_CTR_REGS_C26
	{ "C27", "C27", "C27_tmp", "c27_tmp" }, // HEX_REG_CTR_REGS_C27
	{ "C28", "C28", "C28_tmp", "c28_tmp" }, // HEX_REG_CTR_REGS_C28
	{ "C29", "C29", "C29_tmp", "c29_tmp" }, // HEX_REG_CTR_REGS_C29
	{ "C30", "UTIMERLO", "C30_tmp", "utimerlo_tmp" }, // HEX_REG_CTR_REGS_C30
	{ "C31", "UTIMERHI", "C31_tmp", "utimerhi_tmp" }, // HEX_REG_CTR_REGS_C31
};

/**
 * \brief Lookup table for register names and alias of class CtrRegs64.
 */
HexRegNames hexagon_ctrregs64_lt_v69[] = {
	{ "C1:0", "LC0:SA0", "C1:0_tmp", "lc0:sa0_tmp" }, // HEX_REG_CTR_REGS64_C1_0
	{ NULL, NULL, NULL, NULL }, // -
	{ "C3:2", "LC1:SA1", "C3:2_tmp", "lc1:sa1_tmp" }, // HEX_REG_CTR_REGS64_C3_2
	{ NULL, NULL, NULL, NULL }, // -
	{ "C5:4", "C5:4", "C5:4_tmp", "c5:4_tmp" }, // HEX_REG_CTR_REGS64_C5_4
	{ NULL, NULL, NULL, NULL }, // -
	{ "C7:6", "M1:0", "C7:6_tmp", "m1:0_tmp" }, // HEX_REG_CTR_REGS64_C7_6
	{ NULL, NULL, NULL, NULL }, // -
	{ "C9:8", "C9:8", "C9:8_tmp", "c9:8_tmp" }, // HEX_REG_CTR_REGS64_C9_8
	{ NULL, NULL, NULL, NULL }, // -
	{ "C11:10", "C11:10", "C11:10_tmp", "c11:10_tmp" }, // HEX_REG_CTR_REGS64_C11_10
	{ NULL, NULL, NULL, NULL }, // -
	{ "C13:12", "CS1:0", "C13:12_tmp", "cs1:0_tmp" }, // HEX_REG_CTR_REGS64_C13_12
	{ NULL, NULL, NULL, NULL }, // -
	{ "C15:14", "UPCYCLE", "C15:14_tmp", "upcycle_tmp" }, // HEX_REG_CTR_REGS64_C15_14
	{ NULL, NULL, NULL, NULL }, // -
	{ "C17:16", "C17:16", "C17:16_tmp", "c17:16_tmp" }, // HEX_REG_CTR_REGS64_C17_16
	{ NULL, NULL, NULL, NULL }, // -
	{ "C19:18", "PKTCOUNT", "C19:18_tmp", "pktcount_tmp" }, // HEX_REG_CTR_REGS64_C19_18
	{ NULL, NULL, NULL, NULL }, // -
	{ "C21:20", "C21:20", "C21:20_tmp", "c21:20_tmp" }, // HEX_REG_CTR_REGS64_C21_20
	{ NULL, NULL, NULL, NULL }, // -
	{ "C23:22", "C23:22", "C23:22_tmp", "c23:22_tmp" }, // HEX_REG_CTR_REGS64_C23_22
	{ NULL, NULL, NULL, NULL }, // -
	{ "C25:24", "C25:24", "C25:24_tmp", "c25:24_tmp" }, // HEX_REG_CTR_REGS64_C25_24
	{ NULL, NULL, NULL, NULL }, // -
	{ "C27:26", "C27:26", "C27:26_tmp", "c27:26_tmp" }, // HEX_REG_CTR_REGS64_C27_26
	{ NULL, NULL, NULL, NULL }, // -
	{ "C29:28", "C29:28", "C29:28_tmp", "c29:28_tmp" }, // HEX_REG_CTR_REGS64_C29_28
	{ NULL, NULL, NULL, NULL }, // -
	{ "C31:30", "UTIMER", "C31:30_tmp", "utimer_tmp" }, // HEX_REG_CTR_REGS64_C31_30
};

/**
 * \brief Lookup table for register names and alias of class DoubleRegs.
 */
HexRegNames hexagon_doubleregs_lt_v69[] = {
	{ "R1:0", "R1:0", "R1:0_tmp", "r1:0_tmp" }, // HEX_REG_DOUBLE_REGS_R1_0
	{ NULL, NULL, NULL, NULL }, // -
	{ "R3:2", "R3:2", "R3:2_tmp", "r3:2_tmp" }, // HEX_REG_DOUBLE_REGS_R3_2
	{ NULL, NULL, NULL, NULL }, // -
	{ "R5:4", "R5:4", "R5:4_tmp", "r5:4_tmp" }, // HEX_REG_DOUBLE_REGS_R5_4
	{ NULL, NULL, NULL, NULL }, // -
	{ "R7:6", "R7:6", "R7:6_tmp", "r7:6_tmp" }, // HEX_REG_DOUBLE_REGS_R7_6
	{ NULL, NULL, NULL, NULL }, // -
	{ "R9:8", "R9:8", "R9:8_tmp", "r9:8_tmp" }, // HEX_REG_DOUBLE_REGS_R9_8
	{ NULL, NULL, NULL, NULL }, // -
	{ "R11:10", "R11:10", "R11:10_tmp", "r11:10_tmp" }, // HEX_REG_DOUBLE_REGS_R11_10
	{ NULL, NULL, NULL, NULL }, // -
	{ "R13:12", "R13:12", "R13:12_tmp", "r13:12_tmp" }, // HEX_REG_DOUBLE_REGS_R13_12
	{ NULL, NULL, NULL, NULL }, // -
	{ "R15:14", "R15:14", "R15:14_tmp", "r15:14_tmp" }, // HEX_REG_DOUBLE_REGS_R15_14
	{ NULL, NULL, NULL, NULL }, // -
	{ "R17:16", "R17:16", "R17:16_tmp", "r17:16_tmp" }, // HEX_REG_DOUBLE_REGS_R17_16
	{ NULL, NULL, NULL, NULL }, // -
	{ "R19:18", "R19:18", "R19:18_tmp", "r19:18_tmp" }, // HEX_REG_DOUBLE_REGS_R19_18
	{ NULL, NULL, NULL, NULL }, // -
	{ "R21:20", "R21:20", "R21:20_tmp", "r21:20_tmp" }, // HEX_REG_DOUBLE_REGS_R21_20
	{ NULL, NULL, NULL, NULL }, // -
	{ "R23:22", "R23:22", "R23:22_tmp", "r23:22_tmp" }, // HEX_REG_DOUBLE_REGS_R23_22
	{ NULL, NULL, NULL, NULL }, // -
	{ "R25:24", "R25:24", "R25:24_tmp", "r25:24_tmp" }, // HEX_REG_DOUBLE_REGS_R25_24
	{ NULL, NULL, NULL, NULL }, // -
	{ "R27:26", "R27:26", "R27:26_tmp", "r27:26_tmp" }, // HEX_REG_DOUBLE_REGS_R27_26
	{ NULL, NULL, NULL, NULL }, // -
	{ "R29:28", "R29:28", "R29:28_tmp", "r29:28_tmp" }, // HEX_REG_DOUBLE_REGS_R29_28
	{ NULL, NULL, NULL, NULL }, // -
	{ "R31:30", "LR:FP", "R31:30_tmp", "lr:fp_tmp" }, // HEX_REG_DOUBLE_REGS_R31_30
};

/**
 * \brief Lookup table for register names and alias of class GeneralDoubleLow8Regs.
 */
HexRegNames hexagon_generaldoublelow8regs_lt_v69[] = {
	{ "R1:0", "R1:0", "R1:0_tmp", "r1:0_tmp" }, // HEX_REG_GENERAL_DOUBLE_LOW8_REGS_R1_0
	{ NULL, NULL, NULL, NULL }, // -
	{ "R3:2", "R3:2", "R3:2_tmp", "r3:2_tmp" }, // HEX_REG_GENERAL_DOUBLE_LOW8_REGS_R3_2
	{ NULL, NULL, NULL, NULL }, // -
	{ "R5:4", "R5:4", "R5:4_tmp", "r5:4_tmp" }, // HEX_REG_GENERAL_DOUBLE_LOW8_REGS_R5_4
	{ NULL, NULL, NULL, NULL }, // -
	{ "R7:6", "R7:6", "R7:6_tmp", "r7:6_tmp" }, // HEX_REG_GENERAL_DOUBLE_LOW8_REGS_R7_6
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ "R17:16", "R17:16", "R17:16_tmp", "r17:16_tmp" }, // HEX_REG_GENERAL_DOUBLE_LOW8_REGS_R17_16
	{ NULL, NULL, NULL, NULL }, // -
	{ "R19:18", "R19:18", "R19:18_tmp", "r19:18_tmp" }, // HEX_REG_GENERAL_DOUBLE_LOW8_REGS_R19_18
	{ NULL, NULL, NULL, NULL }, // -
	{ "R21:20", "R21:20", "R21:20_tmp", "r21:20_tmp" }, // HEX_REG_GENERAL_DOUBLE_LOW8_REGS_R21_20
	{ NULL, NULL, NULL, NULL }, // -
	{ "R23:22", "R23:22", "R23:22_tmp", "r23:22_tmp" }, // HEX_REG_GENERAL_DOUBLE_LOW8_REGS_R23_22
};

/**
 * \brief Lookup table for register names and alias of class GeneralSubRegs.
 */
HexRegNames hexagon_generalsubregs_lt_v69[] = {
	{ "R0", "R0", "R0_tmp", "r0_tmp" }, // HEX_REG_GENERAL_SUB_REGS_R0
	{ "R1", "R1", "R1_tmp", "r1_tmp" }, // HEX_REG_GENERAL_SUB_REGS_R1
	{ "R2", "R2", "R2_tmp", "r2_tmp" }, // HEX_REG_GENERAL_SUB_REGS_R2
	{ "R3", "R3", "R3_tmp", "r3_tmp" }, // HEX_REG_GENERAL_SUB_REGS_R3
	{ "R4", "R4", "R4_tmp", "r4_tmp" }, // HEX_REG_GENERAL_SUB_REGS_R4
	{ "R5", "R5", "R5_tmp", "r5_tmp" }, // HEX_REG_GENERAL_SUB_REGS_R5
	{ "R6", "R6", "R6_tmp", "r6_tmp" }, // HEX_REG_GENERAL_SUB_REGS_R6
	{ "R7", "R7", "R7_tmp", "r7_tmp" }, // HEX_REG_GENERAL_SUB_REGS_R7
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ "R16", "R16", "R16_tmp", "r16_tmp" }, // HEX_REG_GENERAL_SUB_REGS_R16
	{ "R17", "R17", "R17_tmp", "r17_tmp" }, // HEX_REG_GENERAL_SUB_REGS_R17
	{ "R18", "R18", "R18_tmp", "r18_tmp" }, // HEX_REG_GENERAL_SUB_REGS_R18
	{ "R19", "R19", "R19_tmp", "r19_tmp" }, // HEX_REG_GENERAL_SUB_REGS_R19
	{ "R20", "R20", "R20_tmp", "r20_tmp" }, // HEX_REG_GENERAL_SUB_REGS_R20
	{ "R21", "R21", "R21_tmp", "r21_tmp" }, // HEX_REG_GENERAL_SUB_REGS_R21
	{ "R22", "R22", "R22_tmp", "r22_tmp" }, // HEX_REG_GENERAL_SUB_REGS_R22
	{ "R23", "R23", "R23_tmp", "r23_tmp" }, // HEX_REG_GENERAL_SUB_REGS_R23
};

/**
 * \brief Lookup table for register names and alias of class GuestRegs.
 */
HexRegNames hexagon_guestregs_lt_v69[] = {
	{ "G0", "GELR", "G0_tmp", "gelr_tmp" }, // HEX_REG_GUEST_REGS_G0
	{ "G1", "GSR", "G1_tmp", "gsr_tmp" }, // HEX_REG_GUEST_REGS_G1
	{ "G2", "GOSP", "G2_tmp", "gosp_tmp" }, // HEX_REG_GUEST_REGS_G2
	{ "G3", "GBADVA", "G3_tmp", "gbadva_tmp" }, // HEX_REG_GUEST_REGS_G3
	{ "G4", "G4", "G4_tmp", "g4_tmp" }, // HEX_REG_GUEST_REGS_G4
	{ "G5", "G5", "G5_tmp", "g5_tmp" }, // HEX_REG_GUEST_REGS_G5
	{ "G6", "G6", "G6_tmp", "g6_tmp" }, // HEX_REG_GUEST_REGS_G6
	{ "G7", "G7", "G7_tmp", "g7_tmp" }, // HEX_REG_GUEST_REGS_G7
	{ "G8", "G8", "G8_tmp", "g8_tmp" }, // HEX_REG_GUEST_REGS_G8
	{ "G9", "G9", "G9_tmp", "g9_tmp" }, // HEX_REG_GUEST_REGS_G9
	{ "G10", "G10", "G10_tmp", "g10_tmp" }, // HEX_REG_GUEST_REGS_G10
	{ "G11", "G11", "G11_tmp", "g11_tmp" }, // HEX_REG_GUEST_REGS_G11
	{ "G12", "G12", "G12_tmp", "g12_tmp" }, // HEX_REG_GUEST_REGS_G12
	{ "G13", "G13", "G13_tmp", "g13_tmp" }, // HEX_REG_GUEST_REGS_G13
	{ "G14", "G14", "G14_tmp", "g14_tmp" }, // HEX_REG_GUEST_REGS_G14
	{ "G15", "G15", "G15_tmp", "g15_tmp" }, // HEX_REG_GUEST_REGS_G15
	{ "G16", "GPMUCNT4", "G16_tmp", "gpmucnt4_tmp" }, // HEX_REG_GUEST_REGS_G16
	{ "G17", "GPMUCNT5", "G17_tmp", "gpmucnt5_tmp" }, // HEX_REG_GUEST_REGS_G17
	{ "G18", "GPMUCNT6", "G18_tmp", "gpmucnt6_tmp" }, // HEX_REG_GUEST_REGS_G18
	{ "G19", "GPMUCNT7", "G19_tmp", "gpmucnt7_tmp" }, // HEX_REG_GUEST_REGS_G19
	{ "G20", "G20", "G20_tmp", "g20_tmp" }, // HEX_REG_GUEST_REGS_G20
	{ "G21", "G21", "G21_tmp", "g21_tmp" }, // HEX_REG_GUEST_REGS_G21
	{ "G22", "G22", "G22_tmp", "g22_tmp" }, // HEX_REG_GUEST_REGS_G22
	{ "G23", "G23", "G23_tmp", "g23_tmp" }, // HEX_REG_GUEST_REGS_G23
	{ "G24", "GPCYCLELO", "G24_tmp", "gpcyclelo_tmp" }, // HEX_REG_GUEST_REGS_G24
	{ "G25", "GPCYCLEHI", "G25_tmp", "gpcyclehi_tmp" }, // HEX_REG_GUEST_REGS_G25
	{ "G26", "GPMUCNT0", "G26_tmp", "gpmucnt0_tmp" }, // HEX_REG_GUEST_REGS_G26
	{ "G27", "GPMUCNT1", "G27_tmp", "gpmucnt1_tmp" }, // HEX_REG_GUEST_REGS_G27
	{ "G28", "GPMUCNT2", "G28_tmp", "gpmucnt2_tmp" }, // HEX_REG_GUEST_REGS_G28
	{ "G29", "GPMUCNT3", "G29_tmp", "gpmucnt3_tmp" }, // HEX_REG_GUEST_REGS_G29
	{ "G30", "G30", "G30_tmp", "g30_tmp" }, // HEX_REG_GUEST_REGS_G30
	{ "G31", "G31", "G31_tmp", "g31_tmp" }, // HEX_REG_GUEST_REGS_G31
};

/**
 * \brief Lookup table for register names and alias of class GuestRegs64.
 */
HexRegNames hexagon_guestregs64_lt_v69[] = {
	{ "G1:0", "G1:0", "G1:0_tmp", "g1:0_tmp" }, // HEX_REG_GUEST_REGS64_G1_0
	{ NULL, NULL, NULL, NULL }, // -
	{ "G3:2", "G3:2", "G3:2_tmp", "g3:2_tmp" }, // HEX_REG_GUEST_REGS64_G3_2
	{ NULL, NULL, NULL, NULL }, // -
	{ "G5:4", "G5:4", "G5:4_tmp", "g5:4_tmp" }, // HEX_REG_GUEST_REGS64_G5_4
	{ NULL, NULL, NULL, NULL }, // -
	{ "G7:6", "G7:6", "G7:6_tmp", "g7:6_tmp" }, // HEX_REG_GUEST_REGS64_G7_6
	{ NULL, NULL, NULL, NULL }, // -
	{ "G9:8", "G9:8", "G9:8_tmp", "g9:8_tmp" }, // HEX_REG_GUEST_REGS64_G9_8
	{ NULL, NULL, NULL, NULL }, // -
	{ "G11:10", "G11:10", "G11:10_tmp", "g11:10_tmp" }, // HEX_REG_GUEST_REGS64_G11_10
	{ NULL, NULL, NULL, NULL }, // -
	{ "G13:12", "G13:12", "G13:12_tmp", "g13:12_tmp" }, // HEX_REG_GUEST_REGS64_G13_12
	{ NULL, NULL, NULL, NULL }, // -
	{ "G15:14", "G15:14", "G15:14_tmp", "g15:14_tmp" }, // HEX_REG_GUEST_REGS64_G15_14
	{ NULL, NULL, NULL, NULL }, // -
	{ "G17:16", "G17:16", "G17:16_tmp", "g17:16_tmp" }, // HEX_REG_GUEST_REGS64_G17_16
	{ NULL, NULL, NULL, NULL }, // -
	{ "G19:18", "G19:18", "G19:18_tmp", "g19:18_tmp" }, // HEX_REG_GUEST_REGS64_G19_18
	{ NULL, NULL, NULL, NULL }, // -
	{ "G21:20", "G21:20", "G21:20_tmp", "g21:20_tmp" }, // HEX_REG_GUEST_REGS64_G21_20
	{ NULL, NULL, NULL, NULL }, // -
	{ "G23:22", "G23:22", "G23:22_tmp", "g23:22_tmp" }, // HEX_REG_GUEST_REGS64_G23_22
	{ NULL, NULL, NULL, NULL }, // -
	{ "G25:24", "G25:24", "G25:24_tmp", "g25:24_tmp" }, // HEX_REG_GUEST_REGS64_G25_24
	{ NULL, NULL, NULL, NULL }, // -
	{ "G27:26", "G27:26", "G27:26_tmp", "g27:26_tmp" }, // HEX_REG_GUEST_REGS64_G27_26
	{ NULL, NULL, NULL, NULL }, // -
	{ "G29:28", "G29:28", "G29:28_tmp", "g29:28_tmp" }, // HEX_REG_GUEST_REGS64_G29_28
	{ NULL, NULL, NULL, NULL }, // -
	{ "G31:30", "G31:30", "G31:30_tmp", "g31:30_tmp" }, // HEX_REG_GUEST_REGS64_G31_30
};

/**
 * \brief Lookup table for register names and alias of class HvxQR.
 */
HexRegNames hexagon_hvxqr_lt_v69[] = {
	{ "Q0", "Q0", "Q0_tmp", "q0_tmp" }, // HEX_REG_HVX_QR_Q0
	{ "Q1", "Q1", "Q1_tmp", "q1_tmp" }, // HEX_REG_HVX_QR_Q1
	{ "Q2", "Q2", "Q2_tmp", "q2_tmp" }, // HEX_REG_HVX_QR_Q2
	{ "Q3", "Q3", "Q3_tmp", "q3_tmp" }, // HEX_REG_HVX_QR_Q3
};

/**
 * \brief Lookup table for register names and alias of class HvxVQR.
 */
HexRegNames hexagon_hvxvqr_lt_v69[] = {
	{ "V3:0", "V3:0", "V3:0_tmp", "v3:0_tmp" }, // HEX_REG_HVX_VQR_V3_0
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ "V7:4", "V7:4", "V7:4_tmp", "v7:4_tmp" }, // HEX_REG_HVX_VQR_V7_4
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ "V11:8", "V11:8", "V11:8_tmp", "v11:8_tmp" }, // HEX_REG_HVX_VQR_V11_8
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ "V15:12", "V15:12", "V15:12_tmp", "v15:12_tmp" }, // HEX_REG_HVX_VQR_V15_12
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ "V19:16", "V19:16", "V19:16_tmp", "v19:16_tmp" }, // HEX_REG_HVX_VQR_V19_16
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ "V23:20", "V23:20", "V23:20_tmp", "v23:20_tmp" }, // HEX_REG_HVX_VQR_V23_20
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ "V27:24", "V27:24", "V27:24_tmp", "v27:24_tmp" }, // HEX_REG_HVX_VQR_V27_24
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ "V31:28", "V31:28", "V31:28_tmp", "v31:28_tmp" }, // HEX_REG_HVX_VQR_V31_28
};

/**
 * \brief Lookup table for register names and alias of class HvxVR.
 */
HexRegNames hexagon_hvxvr_lt_v69[] = {
	{ "V0", "V0", "V0_tmp", "v0_tmp" }, // HEX_REG_HVX_VR_V0
	{ "V1", "V1", "V1_tmp", "v1_tmp" }, // HEX_REG_HVX_VR_V1
	{ "V2", "V2", "V2_tmp", "v2_tmp" }, // HEX_REG_HVX_VR_V2
	{ "V3", "V3", "V3_tmp", "v3_tmp" }, // HEX_REG_HVX_VR_V3
	{ "V4", "V4", "V4_tmp", "v4_tmp" }, // HEX_REG_HVX_VR_V4
	{ "V5", "V5", "V5_tmp", "v5_tmp" }, // HEX_REG_HVX_VR_V5
	{ "V6", "V6", "V6_tmp", "v6_tmp" }, // HEX_REG_HVX_VR_V6
	{ "V7", "V7", "V7_tmp", "v7_tmp" }, // HEX_REG_HVX_VR_V7
	{ "V8", "V8", "V8_tmp", "v8_tmp" }, // HEX_REG_HVX_VR_V8
	{ "V9", "V9", "V9_tmp", "v9_tmp" }, // HEX_REG_HVX_VR_V9
	{ "V10", "V10", "V10_tmp", "v10_tmp" }, // HEX_REG_HVX_VR_V10
	{ "V11", "V11", "V11_tmp", "v11_tmp" }, // HEX_REG_HVX_VR_V11
	{ "V12", "V12", "V12_tmp", "v12_tmp" }, // HEX_REG_HVX_VR_V12
	{ "V13", "V13", "V13_tmp", "v13_tmp" }, // HEX_REG_HVX_VR_V13
	{ "V14", "V14", "V14_tmp", "v14_tmp" }, // HEX_REG_HVX_VR_V14
	{ "V15", "V15", "V15_tmp", "v15_tmp" }, // HEX_REG_HVX_VR_V15
	{ "V16", "V16", "V16_tmp", "v16_tmp" }, // HEX_REG_HVX_VR_V16
	{ "V17", "V17", "V17_tmp", "v17_tmp" }, // HEX_REG_HVX_VR_V17
	{ "V18", "V18", "V18_tmp", "v18_tmp" }, // HEX_REG_HVX_VR_V18
	{ "V19", "V19", "V19_tmp", "v19_tmp" }, // HEX_REG_HVX_VR_V19
	{ "V20", "V20", "V20_tmp", "v20_tmp" }, // HEX_REG_HVX_VR_V20
	{ "V21", "V21", "V21_tmp", "v21_tmp" }, // HEX_REG_HVX_VR_V21
	{ "V22", "V22", "V22_tmp", "v22_tmp" }, // HEX_REG_HVX_VR_V22
	{ "V23", "V23", "V23_tmp", "v23_tmp" }, // HEX_REG_HVX_VR_V23
	{ "V24", "V24", "V24_tmp", "v24_tmp" }, // HEX_REG_HVX_VR_V24
	{ "V25", "V25", "V25_tmp", "v25_tmp" }, // HEX_REG_HVX_VR_V25
	{ "V26", "V26", "V26_tmp", "v26_tmp" }, // HEX_REG_HVX_VR_V26
	{ "V27", "V27", "V27_tmp", "v27_tmp" }, // HEX_REG_HVX_VR_V27
	{ "V28", "V28", "V28_tmp", "v28_tmp" }, // HEX_REG_HVX_VR_V28
	{ "V29", "V29", "V29_tmp", "v29_tmp" }, // HEX_REG_HVX_VR_V29
	{ "V30", "V30", "V30_tmp", "v30_tmp" }, // HEX_REG_HVX_VR_V30
	{ "V31", "V31", "V31_tmp", "v31_tmp" }, // HEX_REG_HVX_VR_V31
};

/**
 * \brief Lookup table for register names and alias of class HvxWR.
 */
HexRegNames hexagon_hvxwr_lt_v69[] = {
	{ "V1:0", "V1:0", "V1:0_tmp", "v1:0_tmp" }, // HEX_REG_HVX_WR_V1_0
	{ NULL, NULL, NULL, NULL }, // -
	{ "V3:2", "V3:2", "V3:2_tmp", "v3:2_tmp" }, // HEX_REG_HVX_WR_V3_2
	{ NULL, NULL, NULL, NULL }, // -
	{ "V5:4", "V5:4", "V5:4_tmp", "v5:4_tmp" }, // HEX_REG_HVX_WR_V5_4
	{ NULL, NULL, NULL, NULL }, // -
	{ "V7:6", "V7:6", "V7:6_tmp", "v7:6_tmp" }, // HEX_REG_HVX_WR_V7_6
	{ NULL, NULL, NULL, NULL }, // -
	{ "V9:8", "V9:8", "V9:8_tmp", "v9:8_tmp" }, // HEX_REG_HVX_WR_V9_8
	{ NULL, NULL, NULL, NULL }, // -
	{ "V11:10", "V11:10", "V11:10_tmp", "v11:10_tmp" }, // HEX_REG_HVX_WR_V11_10
	{ NULL, NULL, NULL, NULL }, // -
	{ "V13:12", "V13:12", "V13:12_tmp", "v13:12_tmp" }, // HEX_REG_HVX_WR_V13_12
	{ NULL, NULL, NULL, NULL }, // -
	{ "V15:14", "V15:14", "V15:14_tmp", "v15:14_tmp" }, // HEX_REG_HVX_WR_V15_14
	{ NULL, NULL, NULL, NULL }, // -
	{ "V17:16", "V17:16", "V17:16_tmp", "v17:16_tmp" }, // HEX_REG_HVX_WR_V17_16
	{ NULL, NULL, NULL, NULL }, // -
	{ "V19:18", "V19:18", "V19:18_tmp", "v19:18_tmp" }, // HEX_REG_HVX_WR_V19_18
	{ NULL, NULL, NULL, NULL }, // -
	{ "V21:20", "V21:20", "V21:20_tmp", "v21:20_tmp" }, // HEX_REG_HVX_WR_V21_20
	{ NULL, NULL, NULL, NULL }, // -
	{ "V23:22", "V23:22", "V23:22_tmp", "v23:22_tmp" }, // HEX_REG_HVX_WR_V23_22
	{ NULL, NULL, NULL, NULL }, // -
	{ "V25:24", "V25:24", "V25:24_tmp", "v25:24_tmp" }, // HEX_REG_HVX_WR_V25_24
	{ NULL, NULL, NULL, NULL }, // -
	{ "V27:26", "V27:26", "V27:26_tmp", "v27:26_tmp" }, // HEX_REG_HVX_WR_V27_26
	{ NULL, NULL, NULL, NULL }, // -
	{ "V29:28", "V29:28", "V29:28_tmp", "v29:28_tmp" }, // HEX_REG_HVX_WR_V29_28
	{ NULL, NULL, NULL, NULL }, // -
	{ "V31:30", "V31:30", "V31:30_tmp", "v31:30_tmp" }, // HEX_REG_HVX_WR_V31_30
};

/**
 * \brief Lookup table for register names and alias of class IntRegs.
 */
HexRegNames hexagon_intregs_lt_v69[] = {
	{ "R0", "R0", "R0_tmp", "r0_tmp" }, // HEX_REG_INT_REGS_R0
	{ "R1", "R1", "R1_tmp", "r1_tmp" }, // HEX_REG_INT_REGS_R1
	{ "R2", "R2", "R2_tmp", "r2_tmp" }, // HEX_REG_INT_REGS_R2
	{ "R3", "R3", "R3_tmp", "r3_tmp" }, // HEX_REG_INT_REGS_R3
	{ "R4", "R4", "R4_tmp", "r4_tmp" }, // HEX_REG_INT_REGS_R4
	{ "R5", "R5", "R5_tmp", "r5_tmp" }, // HEX_REG_INT_REGS_R5
	{ "R6", "R6", "R6_tmp", "r6_tmp" }, // HEX_REG_INT_REGS_R6
	{ "R7", "R7", "R7_tmp", "r7_tmp" }, // HEX_REG_INT_REGS_R7
	{ "R8", "R8", "R8_tmp", "r8_tmp" }, // HEX_REG_INT_REGS_R8
	{ "R9", "R9", "R9_tmp", "r9_tmp" }, // HEX_REG_INT_REGS_R9
	{ "R10", "R10", "R10_tmp", "r10_tmp" }, // HEX_REG_INT_REGS_R10
	{ "R11", "R11", "R11_tmp", "r11_tmp" }, // HEX_REG_INT_REGS_R11
	{ "R12", "R12", "R12_tmp", "r12_tmp" }, // HEX_REG_INT_REGS_R12
	{ "R13", "R13", "R13_tmp", "r13_tmp" }, // HEX_REG_INT_REGS_R13
	{ "R14", "R14", "R14_tmp", "r14_tmp" }, // HEX_REG_INT_REGS_R14
	{ "R15", "R15", "R15_tmp", "r15_tmp" }, // HEX_REG_INT_REGS_R15
	{ "R16", "R16", "R16_tmp", "r16_tmp" }, // HEX_REG_INT_REGS_R16
	{ "R17", "R17", "R17_tmp", "r17_tmp" }, // HEX_REG_INT_REGS_R17
	{ "R18", "R18", "R18_tmp", "r18_tmp" }, // HEX_REG_INT_REGS_R18
	{ "R19", "R19", "R19_tmp", "r19_tmp" }, // HEX_REG_INT_REGS_R19
	{ "R20", "R20", "R20_tmp", "r20_tmp" }, // HEX_REG_INT_REGS_R20
	{ "R21", "R21", "R21_tmp", "r21_tmp" }, // HEX_REG_INT_REGS_R21
	{ "R22", "R22", "R22_tmp", "r22_tmp" }, // HEX_REG_INT_REGS_R22
	{ "R23", "R23", "R23_tmp", "r23_tmp" }, // HEX_REG_INT_REGS_R23
	{ "R24", "R24", "R24_tmp", "r24_tmp" }, // HEX_REG_INT_REGS_R24
	{ "R25", "R25", "R25_tmp", "r25_tmp" }, // HEX_REG_INT_REGS_R25
	{ "R26", "R26", "R26_tmp", "r26_tmp" }, // HEX_REG_INT_REGS_R26
	{ "R27", "R27", "R27_tmp", "r27_tmp" }, // HEX_REG_INT_REGS_R27
	{ "R28", "R28", "R28_tmp", "r28_tmp" }, // HEX_REG_INT_REGS_R28
	{ "R29", "SP", "R29_tmp", "sp_tmp" }, // HEX_REG_INT_REGS_R29
	{ "R30", "FP", "R30_tmp", "fp_tmp" }, // HEX_REG_INT_REGS_R30
	{ "R31", "LR", "R31_tmp", "lr_tmp" }, // HEX_REG_INT_REGS_R31
};

/**
 * \brief Lookup table for register names and alias of class IntRegsLow8.
 */
HexRegNames hexagon_intregslow8_lt_v69[] = {
	{ "R0", "R0", "R0_tmp", "r0_tmp" }, // HEX_REG_INT_REGS_LOW8_R0
	{ "R1", "R1", "R1_tmp", "r1_tmp" }, // HEX_REG_INT_REGS_LOW8_R1
	{ "R2", "R2", "R2_tmp", "r2_tmp" }, // HEX_REG_INT_REGS_LOW8_R2
	{ "R3", "R3", "R3_tmp", "r3_tmp" }, // HEX_REG_INT_REGS_LOW8_R3
	{ "R4", "R4", "R4_tmp", "r4_tmp" }, // HEX_REG_INT_REGS_LOW8_R4
	{ "R5", "R5", "R5_tmp", "r5_tmp" }, // HEX_REG_INT_REGS_LOW8_R5
	{ "R6", "R6", "R6_tmp", "r6_tmp" }, // HEX_REG_INT_REGS_LOW8_R6
	{ "R7", "R7", "R7_tmp", "r7_tmp" }, // HEX_REG_INT_REGS_LOW8_R7
};

/**
 * \brief Lookup table for register names and alias of class ModRegs.
 */
HexRegNames hexagon_modregs_lt_v69[] = {
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ NULL, NULL, NULL, NULL }, // -
	{ "C6", "M0", "C6_tmp", "m0_tmp" }, // HEX_REG_MOD_REGS_C6
	{ "C7", "M1", "C7_tmp", "m1_tmp" }, // HEX_REG_MOD_REGS_C7
};

/**
 * \brief Lookup table for register names and alias of class PredRegs.
 */
HexRegNames hexagon_predregs_lt_v69[] = {
	{ "P0", "P0", "P0_tmp", "p0_tmp" }, // HEX_REG_PRED_REGS_P0
	{ "P1", "P1", "P1_tmp", "p1_tmp" }, // HEX_REG_PRED_REGS_P1
	{ "P2", "P2", "P2_tmp", "p2_tmp" }, // HEX_REG_PRED_REGS_P2
	{ "P3", "P3", "P3_tmp", "p3_tmp" }, // HEX_REG_PRED_REGS_P3
};

/**
 * \brief Lookup table for register names and alias of class SysRegs.
 */
HexRegNames hexagon_sysregs_lt_v69[] = {
	{ "S0", "SGP0", "S0_tmp", "sgp0_tmp" }, // HEX_REG_SYS_REGS_S0
	{ "S1", "SGP1", "S1_tmp", "sgp1_tmp" }, // HEX_REG_SYS_REGS_S1
	{ "S2", "STID", "S2_tmp", "stid_tmp" }, // HEX_REG_SYS_REGS_S2
	{ "S3", "ELR", "S3_tmp", "elr_tmp" }, // HEX_REG_SYS_REGS_S3
	{ "S4", "BADVA0", "S4_tmp", "badva0_tmp" }, // HEX_REG_SYS_REGS_S4
	{ "S5", "BADVA1", "S5_tmp", "badva1_tmp" }, // HEX_REG_SYS_REGS_S5
	{ "S6", "SSR", "S6_tmp", "ssr_tmp" }, // HEX_REG_SYS_REGS_S6
	{ "S7", "CCR", "S7_tmp", "ccr_tmp" }, // HEX_REG_SYS_REGS_S7
	{ "S8", "HTID", "S8_tmp", "htid_tmp" }, // HEX_REG_SYS_REGS_S8
	{ "S9", "BADVA", "S9_tmp", "badva_tmp" }, // HEX_REG_SYS_REGS_S9
	{ "S10", "IMASK", "S10_tmp", "imask_tmp" }, // HEX_REG_SYS_REGS_S10
	{ "S11", "S11", "S11_tmp", "s11_tmp" }, // HEX_REG_SYS_REGS_S11
	{ "S12", "S12", "S12_tmp", "s12_tmp" }, // HEX_REG_SYS_REGS_S12
	{ "S13", "S13", "S13_tmp", "s13_tmp" }, // HEX_REG_SYS_REGS_S13
	{ "S14", "S14", "S14_tmp", "s14_tmp" }, // HEX_REG_SYS_REGS_S14
	{ "S15", "S15", "S15_tmp", "s15_tmp" }, // HEX_REG_SYS_REGS_S15
	{ "S16", "EVB", "S16_tmp", "evb_tmp" }, // HEX_REG_SYS_REGS_S16
	{ "S17", "MODECTL", "S17_tmp", "modectl_tmp" }, // HEX_REG_SYS_REGS_S17
	{ "S18", "SYSCFG", "S18_tmp", "syscfg_tmp" }, // HEX_REG_SYS_REGS_S18
	{ "S19", "S19", "S19_tmp", "s19_tmp" }, // HEX_REG_SYS_REGS_S19
	{ "S20", "S20", "S20_tmp", "s20_tmp" }, // HEX_REG_SYS_REGS_S20
	{ "S21", "VID", "S21_tmp", "vid_tmp" }, // HEX_REG_SYS_REGS_S21
	{ "S22", "S22", "S22_tmp", "s22_tmp" }, // HEX_REG_SYS_REGS_S22
	{ "S23", "S23", "S23_tmp", "s23_tmp" }, // HEX_REG_SYS_REGS_S23
	{ "S24", "S24", "S24_tmp", "s24_tmp" }, // HEX_REG_SYS_REGS_S24
	{ "S25", "S25", "S25_tmp", "s25_tmp" }, // HEX_REG_SYS_REGS_S25
	{ "S26", "S26", "S26_tmp", "s26_tmp" }, // HEX_REG_SYS_REGS_S26
	{ "S27", "CFGBASE", "S27_tmp", "cfgbase_tmp" }, // HEX_REG_SYS_REGS_S27
	{ "S28", "DIAG", "S28_tmp", "diag_tmp" }, // HEX_REG_SYS_REGS_S28
	{ "S29", "REV", "S29_tmp", "rev_tmp" }, // HEX_REG_SYS_REGS_S29
	{ "S30", "PCYCLELO", "S30_tmp", "pcyclelo_tmp" }, // HEX_REG_SYS_REGS_S30
	{ "S31", "PCYCLEHI", "S31_tmp", "pcyclehi_tmp" }, // HEX_REG_SYS_REGS_S31
	{ "S32", "ISDBST", "S32_tmp", "isdbst_tmp" }, // HEX_REG_SYS_REGS_S32
	{ "S33", "ISDBCFG0", "S33_tmp", "isdbcfg0_tmp" }, // HEX_REG_SYS_REGS_S33
	{ "S34", "ISDBCFG1", "S34_tmp", "isdbcfg1_tmp" }, // HEX_REG_SYS_REGS_S34
	{ "S35", "S35", "S35_tmp", "s35_tmp" }, // HEX_REG_SYS_REGS_S35
	{ "S36", "BRKPTPC0", "S36_tmp", "brkptpc0_tmp" }, // HEX_REG_SYS_REGS_S36
	{ "S37", "BRKPTCFG0", "S37_tmp", "brkptcfg0_tmp" }, // HEX_REG_SYS_REGS_S37
	{ "S38", "BRKPTPC1", "S38_tmp", "brkptpc1_tmp" }, // HEX_REG_SYS_REGS_S38
	{ "S39", "BRKPTCFG1", "S39_tmp", "brkptcfg1_tmp" }, // HEX_REG_SYS_REGS_S39
	{ "S40", "ISDBMBXIN", "S40_tmp", "isdbmbxin_tmp" }, // HEX_REG_SYS_REGS_S40
	{ "S41", "ISDBMBXOUT", "S41_tmp", "isdbmbxout_tmp" }, // HEX_REG_SYS_REGS_S41
	{ "S42", "ISDBEN", "S42_tmp", "isdben_tmp" }, // HEX_REG_SYS_REGS_S42
	{ "S43", "ISDBGPR", "S43_tmp", "isdbgpr_tmp" }, // HEX_REG_SYS_REGS_S43
	{ "S44", "S44", "S44_tmp", "s44_tmp" }, // HEX_REG_SYS_REGS_S44
	{ "S45", "S45", "S45_tmp", "s45_tmp" }, // HEX_REG_SYS_REGS_S45
	{ "S46", "S46", "S46_tmp", "s46_tmp" }, // HEX_REG_SYS_REGS_S46
	{ "S47", "S47", "S47_tmp", "s47_tmp" }, // HEX_REG_SYS_REGS_S47
	{ "S48", "PMUCNT0", "S48_tmp", "pmucnt0_tmp" }, // HEX_REG_SYS_REGS_S48
	{ "S49", "PMUCNT1", "S49_tmp", "pmucnt1_tmp" }, // HEX_REG_SYS_REGS_S49
	{ "S50", "PMUCNT2", "S50_tmp", "pmucnt2_tmp" }, // HEX_REG_SYS_REGS_S50
	{ "S51", "PMUCNT3", "S51_tmp", "pmucnt3_tmp" }, // HEX_REG_SYS_REGS_S51
	{ "S52", "PMUEVTCFG", "S52_tmp", "pmuevtcfg_tmp" }, // HEX_REG_SYS_REGS_S52
	{ "S53", "PMUCFG", "S53_tmp", "pmucfg_tmp" }, // HEX_REG_SYS_REGS_S53
	{ "S54", "S54", "S54_tmp", "s54_tmp" }, // HEX_REG_SYS_REGS_S54
	{ "S55", "S55", "S55_tmp", "s55_tmp" }, // HEX_REG_SYS_REGS_S55
	{ "S56", "S56", "S56_tmp", "s56_tmp" }, // HEX_REG_SYS_REGS_S56
	{ "S57", "S57", "S57_tmp", "s57_tmp" }, // HEX_REG_SYS_REGS_S57
	{ "S58", "S58", "S58_tmp", "s58_tmp" }, // HEX_REG_SYS_REGS_S58
	{ "S59", "S59", "S59_tmp", "s59_tmp" }, // HEX_REG_SYS_REGS_S59
	{ "S60", "S60", "S60_tmp", "s60_tmp" }, // HEX_REG_SYS_REGS_S60
	{ "S61", "S61", "S61_tmp", "s61_tmp" }, // HEX_REG_SYS_REGS_S61
	{ "S62", "S62", "S62_tmp", "s62_tmp" }, // HEX_REG_SYS_REGS_S62
	{ "S63", "S63", "S63_tmp", "s63_tmp" }, // HEX_REG_SYS_REGS_S63
	{ "S64", "S64", "S64_tmp", "s64_tmp" }, // HEX_REG_SYS_REGS_S64
	{ "S65", "S65", "S65_tmp", "s65_tmp" }, // HEX_REG_SYS_REGS_S65
	{ "S66", "S66", "S66_tmp", "s66_tmp" }, // HEX_REG_SYS_REGS_S66
	{ "S67", "S67", "S67_tmp", "s67_tmp" }, // HEX_REG_SYS_REGS_S67
	{ "S68", "S68", "S68_tmp", "s68_tmp" }, // HEX_REG_SYS_REGS_S68
	{ "S69", "S69", "S69_tmp", "s69_tmp" }, // HEX_REG_SYS_REGS_S69
	{ "S70", "S70", "S70_tmp", "s70_tmp" }, // HEX_REG_SYS_REGS_S70
	{ "S71", "S71", "S71_tmp", "s71_tmp" }, // HEX_REG_SYS_REGS_S71
	{ "S72", "S72", "S72_tmp", "s72_tmp" }, // HEX_REG_SYS_REGS_S72
	{ "S73", "S73", "S73_tmp", "s73_tmp" }, // HEX_REG_SYS_REGS_S73
	{ "S74", "S74", "S74_tmp", "s74_tmp" }, // HEX_REG_SYS_REGS_S74
	{ "S75", "S75", "S75_tmp", "s75_tmp" }, // HEX_REG_SYS_REGS_S75
	{ "S76", "S76", "S76_tmp", "s76_tmp" }, // HEX_REG_SYS_REGS_S76
	{ "S77", "S77", "S77_tmp", "s77_tmp" }, // HEX_REG_SYS_REGS_S77
	{ "S78", "S78", "S78_tmp", "s78_tmp" }, // HEX_REG_SYS_REGS_S78
	{ "S79", "S79", "S79_tmp", "s79_tmp" }, // HEX_REG_SYS_REGS_S79
	{ "S80", "S80", "S80_tmp", "s80_tmp" }, // HEX_REG_SYS_REGS_S80
};

/**
 * \brief Lookup table for register names and alias of class SysRegs64.
 */
HexRegNames hexagon_sysregs64_lt_v69[] = {
	{ "S1:0", "SGP1:0", "S1:0_tmp", "sgp1:0_tmp" }, // HEX_REG_SYS_REGS64_S1_0
	{ NULL, NULL, NULL, NULL }, // -
	{ "S3:2", "S3:2", "S3:2_tmp", "s3:2_tmp" }, // HEX_REG_SYS_REGS64_S3_2
	{ NULL, NULL, NULL, NULL }, // -
	{ "S5:4", "BADVA1:0", "S5:4_tmp", "badva1:0_tmp" }, // HEX_REG_SYS_REGS64_S5_4
	{ NULL, NULL, NULL, NULL }, // -
	{ "S7:6", "CCR:SSR", "S7:6_tmp", "ccr:ssr_tmp" }, // HEX_REG_SYS_REGS64_S7_6
	{ NULL, NULL, NULL, NULL }, // -
	{ "S9:8", "S9:8", "S9:8_tmp", "s9:8_tmp" }, // HEX_REG_SYS_REGS64_S9_8
	{ NULL, NULL, NULL, NULL }, // -
	{ "S11:10", "S11:10", "S11:10_tmp", "s11:10_tmp" }, // HEX_REG_SYS_REGS64_S11_10
	{ NULL, NULL, NULL, NULL }, // -
	{ "S13:12", "S13:12", "S13:12_tmp", "s13:12_tmp" }, // HEX_REG_SYS_REGS64_S13_12
	{ NULL, NULL, NULL, NULL }, // -
	{ "S15:14", "S15:14", "S15:14_tmp", "s15:14_tmp" }, // HEX_REG_SYS_REGS64_S15_14
	{ NULL, NULL, NULL, NULL }, // -
	{ "S17:16", "S17:16", "S17:16_tmp", "s17:16_tmp" }, // HEX_REG_SYS_REGS64_S17_16
	{ NULL, NULL, NULL, NULL }, // -
	{ "S19:18", "S19:18", "S19:18_tmp", "s19:18_tmp" }, // HEX_REG_SYS_REGS64_S19_18
	{ NULL, NULL, NULL, NULL }, // -
	{ "S21:20", "S21:20", "S21:20_tmp", "s21:20_tmp" }, // HEX_REG_SYS_REGS64_S21_20
	{ NULL, NULL, NULL, NULL }, // -
	{ "S23:22", "S23:22", "S23:22_tmp", "s23:22_tmp" }, // HEX_REG_SYS_REGS64_S23_22
	{ NULL, NULL, NULL, NULL }, // -
	{ "S25:24", "S25:24", "S25:24_tmp", "s25:24_tmp" }, // HEX_REG_SYS_REGS64_S25_24
	{ NULL, NULL, NULL, NULL }, // -
	{ "S27:26", "S27:26", "S27:26_tmp", "s27:26_tmp" }, // HEX_REG_SYS_REGS64_S27_26
	{ NULL, NULL, NULL, NULL }, // -
	{ "S29:28", "S29:28", "S29:28_tmp", "s29:28_tmp" }, // HEX_REG_SYS_REGS64_S29_28
	{ NULL, NULL, NULL, NULL }, // -
	{ "S31:30", "PCYCLE", "S31:30_tmp", "pcycle_tmp" }, // HEX_REG_SYS_REGS64_S31_30
	{ NULL, NULL, NULL, NULL }, // -
	{ "S33:32", "S33:32", "S33:32_tmp", "s33:32_tmp" }, // HEX_REG_SYS_REGS64_S33_32
	{ NULL, NULL, NULL, NULL }, // -
	{ "S35:34", "S35:34", "S35:34_tmp", "s35:34_tmp" }, // HEX_REG_SYS_REGS64_S35_34
	{ NULL, NULL, NULL, NULL }, // -
	{ "S37:36", "S37:36", "S37:36_tmp", "s37:36_tmp" }, // HEX_REG_SYS_REGS64_S37_36
	{ NULL, NULL, NULL, NULL }, // -
	{ "S39:38", "S39:38", "S39:38_tmp", "s39:38_tmp" }, // HEX_REG_SYS_REGS64_S39_38
	{ NULL, NULL, NULL, NULL }, // -
	{ "S41:40", "S41:40", "S41:40_tmp", "s41:40_tmp" }, // HEX_REG_SYS_REGS64_S41_40
	{ NULL, NULL, NULL, NULL }, // -
	{ "S43:42", "S43:42", "S43:42_tmp", "s43:42_tmp" }, // HEX_REG_SYS_REGS64_S43_42
	{ NULL, NULL, NULL, NULL }, // -
	{ "S45:44", "S45:44", "S45:44_tmp", "s45:44_tmp" }, // HEX_REG_SYS_REGS64_S45_44
	{ NULL, NULL, NULL, NULL }, // -
	{ "S47:46", "S47:46", "S47:46_tmp", "s47:46_tmp" }, // HEX_REG_SYS_REGS64_S47_46
	{ NULL, NULL, NULL, NULL }, // -
	{ "S49:48", "S49:48", "S49:48_tmp", "s49:48_tmp" }, // HEX_REG_SYS_REGS64_S49_48
	{ NULL, NULL, NULL, NULL }, // -
	{ "S51:50", "S51:50", "S51:50_tmp", "s51:50_tmp" }, // HEX_REG_SYS_REGS64_S51_50
	{ NULL, NULL, NULL, NULL }, // -
	{ "S53:52", "S53:52", "S53:52_tmp", "s53:52_tmp" }, // HEX_REG_SYS_REGS64_S53_52
	{ NULL, NULL, NULL, NULL }, // -
	{ "S55:54", "S55:54", "S55:54_tmp", "s55:54_tmp" }, // HEX_REG_SYS_REGS64_S55_54
	{ NULL, NULL, NULL, NULL }, // -
	{ "S57:56", "S57:56", "S57:56_tmp", "s57:56_tmp" }, // HEX_REG_SYS_REGS64_S57_56
	{ NULL, NULL, NULL, NULL }, // -
	{ "S59:58", "S59:58", "S59:58_tmp", "s59:58_tmp" }, // HEX_REG_SYS_REGS64_S59_58
	{ NULL, NULL, NULL, NULL }, // -
	{ "S61:60", "S61:60", "S61:60_tmp", "s61:60_tmp" }, // HEX_REG_SYS_REGS64_S61_60
	{ NULL, NULL, NULL, NULL }, // -
	{ "S63:62", "S63:62", "S63:62_tmp", "s63:62_tmp" }, // HEX_REG_SYS_REGS64_S63_62
	{ NULL, NULL, NULL, NULL }, // -
	{ "S65:64", "S65:64", "S65:64_tmp", "s65:64_tmp" }, // HEX_REG_SYS_REGS64_S65_64
	{ NULL, NULL, NULL, NULL }, // -
	{ "S67:66", "S67:66", "S67:66_tmp", "s67:66_tmp" }, // HEX_REG_SYS_REGS64_S67_66
	{ NULL, NULL, NULL, NULL }, // -
	{ "S69:68", "S69:68", "S69:68_tmp", "s69:68_tmp" }, // HEX_REG_SYS_REGS64_S69_68
	{ NULL, NULL, NULL, NULL }, // -
	{ "S71:70", "S71:70", "S71:70_tmp", "s71:70_tmp" }, // HEX_REG_SYS_REGS64_S71_70
	{ NULL, NULL, NULL, NULL }, // -
	{ "S73:72", "S73:72", "S73:72_tmp", "s73:72_tmp" }, // HEX_REG_SYS_REGS64_S73_72
	{ NULL, NULL, NULL, NULL }, // -
	{ "S75:74", "S75:74", "S75:74_tmp", "s75:74_tmp" }, // HEX_REG_SYS_REGS64_S75_74
	{ NULL, NULL, NULL, NULL }, // -
	{ "S77:76", "S77:76", "S77:76_tmp", "s77:76_tmp" }, // HEX_REG_SYS_REGS64_S77_76
	{ NULL, NULL, NULL, NULL }, // -
	{ "S79:78", "S79:78", "S79:78_tmp", "s79:78_tmp" }, // HEX_REG_SYS_REGS64_S79_78
};

#endif