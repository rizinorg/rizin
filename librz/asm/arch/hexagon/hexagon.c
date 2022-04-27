// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

//========================================
// The following code is generated.
// Do not edit. Repository of code generator:
// https://github.com/rizinorg/rz-hexagon

#include <stdio.h>
#include <stdbool.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_util/rz_assert.h>
#include "hexagon.h"
#include "hexagon_insn.h"
#include "hexagon_arch.h"

char *hex_get_ctr_regs(int opcode_reg) {
	switch (opcode_reg) {
	default:
		return "<err>";
	case HEX_REG_CTR_REGS_LC0:
		return "LC0";
	case HEX_REG_CTR_REGS_SA0:
		return "SA0";
	case HEX_REG_CTR_REGS_LC1:
		return "LC1";
	case HEX_REG_CTR_REGS_SA1:
		return "SA1";
	case HEX_REG_CTR_REGS_P3_0:
		return "P3:0";
	case HEX_REG_CTR_REGS_C5:
		return "C5";
	case HEX_REG_CTR_REGS_PC:
		return "PC";
	case HEX_REG_CTR_REGS_UGP:
		return "UGP";
	case HEX_REG_CTR_REGS_GP:
		return "GP";
	case HEX_REG_CTR_REGS_CS0:
		return "CS0";
	case HEX_REG_CTR_REGS_CS1:
		return "CS1";
	case HEX_REG_CTR_REGS_UPCYCLELO:
		return "UPCYCLELO";
	case HEX_REG_CTR_REGS_UPCYCLEHI:
		return "UPCYCLEHI";
	case HEX_REG_CTR_REGS_FRAMELIMIT:
		return "FRAMELIMIT";
	case HEX_REG_CTR_REGS_FRAMEKEY:
		return "FRAMEKEY";
	case HEX_REG_CTR_REGS_PKTCOUNTLO:
		return "PKTCOUNTLO";
	case HEX_REG_CTR_REGS_PKTCOUNTHI:
		return "PKTCOUNTHI";
	case HEX_REG_CTR_REGS_UTIMERLO:
		return "UTIMERLO";
	case HEX_REG_CTR_REGS_UTIMERHI:
		return "UTIMERHI";
	case HEX_REG_CTR_REGS_M0:
		return "M0";
	case HEX_REG_CTR_REGS_M1:
		return "M1";
	case HEX_REG_CTR_REGS_USR:
		return "USR";
	}
}

char *hex_get_ctr_regs64(int opcode_reg) {
	switch (opcode_reg) {
	default:
		return "<err>";
	case HEX_REG_CTR_REGS64_C1_0:
		return "C1:0";
	case HEX_REG_CTR_REGS64_C3_2:
		return "C3:2";
	case HEX_REG_CTR_REGS64_C5_4:
		return "C5:4";
	case HEX_REG_CTR_REGS64_C7_6:
		return "C7:6";
	case HEX_REG_CTR_REGS64_C9_8:
		return "C9:8";
	case HEX_REG_CTR_REGS64_C11_10:
		return "C11:10";
	case HEX_REG_CTR_REGS64_CS:
		return "C13:12";
	case HEX_REG_CTR_REGS64_UPCYCLE:
		return "C15:14";
	case HEX_REG_CTR_REGS64_C17_16:
		return "C17:16";
	case HEX_REG_CTR_REGS64_PKTCOUNT:
		return "C19:18";
	case HEX_REG_CTR_REGS64_UTIMER:
		return "C31:30";
	}
}

char *hex_get_double_regs(int opcode_reg) {
	switch (opcode_reg) {
	default:
		return "<err>";
	case HEX_REG_DOUBLE_REGS_D0:
		return "R1:0";
	case HEX_REG_DOUBLE_REGS_D1:
		return "R3:2";
	case HEX_REG_DOUBLE_REGS_D2:
		return "R5:4";
	case HEX_REG_DOUBLE_REGS_D3:
		return "R7:6";
	case HEX_REG_DOUBLE_REGS_D4:
		return "R9:8";
	case HEX_REG_DOUBLE_REGS_D6:
		return "R13:12";
	case HEX_REG_DOUBLE_REGS_D7:
		return "R15:14";
	case HEX_REG_DOUBLE_REGS_D8:
		return "R17:16";
	case HEX_REG_DOUBLE_REGS_D9:
		return "R19:18";
	case HEX_REG_DOUBLE_REGS_D10:
		return "R21:20";
	case HEX_REG_DOUBLE_REGS_D11:
		return "R23:22";
	case HEX_REG_DOUBLE_REGS_D12:
		return "R25:24";
	case HEX_REG_DOUBLE_REGS_D13:
		return "R27:26";
	case HEX_REG_DOUBLE_REGS_D5:
		return "R11:10";
	case HEX_REG_DOUBLE_REGS_D14:
		return "R29:28";
	case HEX_REG_DOUBLE_REGS_D15:
		return "R31:30";
	}
}

char *hex_get_general_double_low8_regs(int opcode_reg) {
	opcode_reg = opcode_reg << 1;
	if (opcode_reg > 6) { // HEX_REG_D3 == 6
		opcode_reg = (opcode_reg & 0x7) | 0x10;
	}
	switch (opcode_reg) {
	default:
		return "<err>";
	case HEX_REG_GENERAL_DOUBLE_LOW8_REGS_D11:
		return "R23:22";
	case HEX_REG_GENERAL_DOUBLE_LOW8_REGS_D10:
		return "R21:20";
	case HEX_REG_GENERAL_DOUBLE_LOW8_REGS_D9:
		return "R19:18";
	case HEX_REG_GENERAL_DOUBLE_LOW8_REGS_D8:
		return "R17:16";
	case HEX_REG_GENERAL_DOUBLE_LOW8_REGS_D3:
		return "R7:6";
	case HEX_REG_GENERAL_DOUBLE_LOW8_REGS_D2:
		return "R5:4";
	case HEX_REG_GENERAL_DOUBLE_LOW8_REGS_D1:
		return "R3:2";
	case HEX_REG_GENERAL_DOUBLE_LOW8_REGS_D0:
		return "R1:0";
	}
}

char *hex_get_general_sub_regs(int opcode_reg) {
	if (opcode_reg > 7) { // HEX_REG_R7 == 7
		opcode_reg = (opcode_reg & 0x7) | 0x10;
	}
	switch (opcode_reg) {
	default:
		return "<err>";
	case HEX_REG_GENERAL_SUB_REGS_R23:
		return "R23";
	case HEX_REG_GENERAL_SUB_REGS_R22:
		return "R22";
	case HEX_REG_GENERAL_SUB_REGS_R21:
		return "R21";
	case HEX_REG_GENERAL_SUB_REGS_R20:
		return "R20";
	case HEX_REG_GENERAL_SUB_REGS_R19:
		return "R19";
	case HEX_REG_GENERAL_SUB_REGS_R18:
		return "R18";
	case HEX_REG_GENERAL_SUB_REGS_R17:
		return "R17";
	case HEX_REG_GENERAL_SUB_REGS_R16:
		return "R16";
	case HEX_REG_GENERAL_SUB_REGS_R7:
		return "R7";
	case HEX_REG_GENERAL_SUB_REGS_R6:
		return "R6";
	case HEX_REG_GENERAL_SUB_REGS_R5:
		return "R5";
	case HEX_REG_GENERAL_SUB_REGS_R4:
		return "R4";
	case HEX_REG_GENERAL_SUB_REGS_R3:
		return "R3";
	case HEX_REG_GENERAL_SUB_REGS_R2:
		return "R2";
	case HEX_REG_GENERAL_SUB_REGS_R1:
		return "R1";
	case HEX_REG_GENERAL_SUB_REGS_R0:
		return "R0";
	}
}

char *hex_get_guest_regs(int opcode_reg) {
	switch (opcode_reg) {
	default:
		return "<err>";
	case HEX_REG_GUEST_REGS_GELR:
		return "GELR";
	case HEX_REG_GUEST_REGS_GSR:
		return "GSR";
	case HEX_REG_GUEST_REGS_GOSP:
		return "GOSP";
	case HEX_REG_GUEST_REGS_G3:
		return "GBADVA";
	case HEX_REG_GUEST_REGS_G4:
		return "G4";
	case HEX_REG_GUEST_REGS_G5:
		return "G5";
	case HEX_REG_GUEST_REGS_G6:
		return "G6";
	case HEX_REG_GUEST_REGS_G7:
		return "G7";
	case HEX_REG_GUEST_REGS_G8:
		return "G8";
	case HEX_REG_GUEST_REGS_G9:
		return "G9";
	case HEX_REG_GUEST_REGS_G10:
		return "G10";
	case HEX_REG_GUEST_REGS_G11:
		return "G11";
	case HEX_REG_GUEST_REGS_G12:
		return "G12";
	case HEX_REG_GUEST_REGS_G13:
		return "G13";
	case HEX_REG_GUEST_REGS_G14:
		return "G14";
	case HEX_REG_GUEST_REGS_G15:
		return "G15";
	case HEX_REG_GUEST_REGS_GPMUCNT4:
		return "GPMUCNT4";
	case HEX_REG_GUEST_REGS_GPMUCNT5:
		return "GPMUCNT5";
	case HEX_REG_GUEST_REGS_GPMUCNT6:
		return "GPMUCNT6";
	case HEX_REG_GUEST_REGS_GPMUCNT7:
		return "GPMUCNT7";
	case HEX_REG_GUEST_REGS_G20:
		return "G20";
	case HEX_REG_GUEST_REGS_G21:
		return "G21";
	case HEX_REG_GUEST_REGS_G22:
		return "G22";
	case HEX_REG_GUEST_REGS_G23:
		return "G23";
	case HEX_REG_GUEST_REGS_GPCYCLELO:
		return "GPCYCLELO";
	case HEX_REG_GUEST_REGS_GPCYCLEHI:
		return "GPCYCLEHI";
	case HEX_REG_GUEST_REGS_GPMUCNT0:
		return "GPMUCNT0";
	case HEX_REG_GUEST_REGS_GPMUCNT1:
		return "GPMUCNT1";
	case HEX_REG_GUEST_REGS_GPMUCNT2:
		return "GPMUCNT2";
	case HEX_REG_GUEST_REGS_GPMUCNT3:
		return "GPMUCNT3";
	case HEX_REG_GUEST_REGS_G30:
		return "G30";
	case HEX_REG_GUEST_REGS_G31:
		return "G31";
	}
}

char *hex_get_guest_regs64(int opcode_reg) {
	switch (opcode_reg) {
	default:
		return "<err>";
	case HEX_REG_GUEST_REGS64_G1_0:
		return "G1:0";
	case HEX_REG_GUEST_REGS64_G3_2:
		return "G3:2";
	case HEX_REG_GUEST_REGS64_G5_4:
		return "G5:4";
	case HEX_REG_GUEST_REGS64_G7_6:
		return "G7:6";
	case HEX_REG_GUEST_REGS64_G9_8:
		return "G9:8";
	case HEX_REG_GUEST_REGS64_G11_10:
		return "G11:10";
	case HEX_REG_GUEST_REGS64_G13_12:
		return "G13:12";
	case HEX_REG_GUEST_REGS64_G15_14:
		return "G15:14";
	case HEX_REG_GUEST_REGS64_G17_16:
		return "G17:16";
	case HEX_REG_GUEST_REGS64_G19_18:
		return "G19:18";
	case HEX_REG_GUEST_REGS64_G21_20:
		return "G21:20";
	case HEX_REG_GUEST_REGS64_G23_22:
		return "G23:22";
	case HEX_REG_GUEST_REGS64_G25_24:
		return "G25:24";
	case HEX_REG_GUEST_REGS64_G27_26:
		return "G27:26";
	case HEX_REG_GUEST_REGS64_G29_28:
		return "G29:28";
	case HEX_REG_GUEST_REGS64_G31_30:
		return "G31:30";
	}
}

char *hex_get_hvx_qr(int opcode_reg) {
	switch (opcode_reg) {
	default:
		return "<err>";
	case HEX_REG_HVX_QR_Q0:
		return "Q0";
	case HEX_REG_HVX_QR_Q1:
		return "Q1";
	case HEX_REG_HVX_QR_Q2:
		return "Q2";
	case HEX_REG_HVX_QR_Q3:
		return "Q3";
	}
}

char *hex_get_hvx_vqr(int opcode_reg) {
	switch (opcode_reg) {
	default:
		return "<err>";
	case HEX_REG_HVX_VQR_VQ0:
		return "V3:0";
	case HEX_REG_HVX_VQR_VQ1:
		return "V7:4";
	case HEX_REG_HVX_VQR_VQ2:
		return "V11:8";
	case HEX_REG_HVX_VQR_VQ3:
		return "V15:12";
	case HEX_REG_HVX_VQR_VQ4:
		return "V19:16";
	case HEX_REG_HVX_VQR_VQ5:
		return "V23:20";
	case HEX_REG_HVX_VQR_VQ6:
		return "V27:24";
	case HEX_REG_HVX_VQR_VQ7:
		return "V31:28";
	}
}

char *hex_get_hvx_vr(int opcode_reg) {
	switch (opcode_reg) {
	default:
		return "<err>";
	case HEX_REG_HVX_VR_V0:
		return "V0";
	case HEX_REG_HVX_VR_V1:
		return "V1";
	case HEX_REG_HVX_VR_V2:
		return "V2";
	case HEX_REG_HVX_VR_V3:
		return "V3";
	case HEX_REG_HVX_VR_V4:
		return "V4";
	case HEX_REG_HVX_VR_V5:
		return "V5";
	case HEX_REG_HVX_VR_V6:
		return "V6";
	case HEX_REG_HVX_VR_V7:
		return "V7";
	case HEX_REG_HVX_VR_V8:
		return "V8";
	case HEX_REG_HVX_VR_V9:
		return "V9";
	case HEX_REG_HVX_VR_V10:
		return "V10";
	case HEX_REG_HVX_VR_V11:
		return "V11";
	case HEX_REG_HVX_VR_V12:
		return "V12";
	case HEX_REG_HVX_VR_V13:
		return "V13";
	case HEX_REG_HVX_VR_V14:
		return "V14";
	case HEX_REG_HVX_VR_V15:
		return "V15";
	case HEX_REG_HVX_VR_V16:
		return "V16";
	case HEX_REG_HVX_VR_V17:
		return "V17";
	case HEX_REG_HVX_VR_V18:
		return "V18";
	case HEX_REG_HVX_VR_V19:
		return "V19";
	case HEX_REG_HVX_VR_V20:
		return "V20";
	case HEX_REG_HVX_VR_V21:
		return "V21";
	case HEX_REG_HVX_VR_V22:
		return "V22";
	case HEX_REG_HVX_VR_V23:
		return "V23";
	case HEX_REG_HVX_VR_V24:
		return "V24";
	case HEX_REG_HVX_VR_V25:
		return "V25";
	case HEX_REG_HVX_VR_V26:
		return "V26";
	case HEX_REG_HVX_VR_V27:
		return "V27";
	case HEX_REG_HVX_VR_V28:
		return "V28";
	case HEX_REG_HVX_VR_V29:
		return "V29";
	case HEX_REG_HVX_VR_V30:
		return "V30";
	case HEX_REG_HVX_VR_V31:
		return "V31";
	}
}

char *hex_get_hvx_wr(int opcode_reg) {
	switch (opcode_reg) {
	default:
		return "<err>";
	case HEX_REG_HVX_WR_W0:
		return "V1:0";
	case HEX_REG_HVX_WR_W1:
		return "V3:2";
	case HEX_REG_HVX_WR_W2:
		return "V5:4";
	case HEX_REG_HVX_WR_W3:
		return "V7:6";
	case HEX_REG_HVX_WR_W4:
		return "V9:8";
	case HEX_REG_HVX_WR_W5:
		return "V11:10";
	case HEX_REG_HVX_WR_W6:
		return "V13:12";
	case HEX_REG_HVX_WR_W7:
		return "V15:14";
	case HEX_REG_HVX_WR_W8:
		return "V17:16";
	case HEX_REG_HVX_WR_W9:
		return "V19:18";
	case HEX_REG_HVX_WR_W10:
		return "V21:20";
	case HEX_REG_HVX_WR_W11:
		return "V23:22";
	case HEX_REG_HVX_WR_W12:
		return "V25:24";
	case HEX_REG_HVX_WR_W13:
		return "V27:26";
	case HEX_REG_HVX_WR_W14:
		return "V29:28";
	case HEX_REG_HVX_WR_W15:
		return "V31:30";
	}
}

char *hex_get_int_regs(int opcode_reg) {
	switch (opcode_reg) {
	default:
		return "<err>";
	case HEX_REG_INT_REGS_R0:
		return "R0";
	case HEX_REG_INT_REGS_R1:
		return "R1";
	case HEX_REG_INT_REGS_R2:
		return "R2";
	case HEX_REG_INT_REGS_R3:
		return "R3";
	case HEX_REG_INT_REGS_R4:
		return "R4";
	case HEX_REG_INT_REGS_R5:
		return "R5";
	case HEX_REG_INT_REGS_R6:
		return "R6";
	case HEX_REG_INT_REGS_R7:
		return "R7";
	case HEX_REG_INT_REGS_R8:
		return "R8";
	case HEX_REG_INT_REGS_R9:
		return "R9";
	case HEX_REG_INT_REGS_R12:
		return "R12";
	case HEX_REG_INT_REGS_R13:
		return "R13";
	case HEX_REG_INT_REGS_R14:
		return "R14";
	case HEX_REG_INT_REGS_R15:
		return "R15";
	case HEX_REG_INT_REGS_R16:
		return "R16";
	case HEX_REG_INT_REGS_R17:
		return "R17";
	case HEX_REG_INT_REGS_R18:
		return "R18";
	case HEX_REG_INT_REGS_R19:
		return "R19";
	case HEX_REG_INT_REGS_R20:
		return "R20";
	case HEX_REG_INT_REGS_R21:
		return "R21";
	case HEX_REG_INT_REGS_R22:
		return "R22";
	case HEX_REG_INT_REGS_R23:
		return "R23";
	case HEX_REG_INT_REGS_R24:
		return "R24";
	case HEX_REG_INT_REGS_R25:
		return "R25";
	case HEX_REG_INT_REGS_R26:
		return "R26";
	case HEX_REG_INT_REGS_R27:
		return "R27";
	case HEX_REG_INT_REGS_R28:
		return "R28";
	case HEX_REG_INT_REGS_R10:
		return "R10";
	case HEX_REG_INT_REGS_R11:
		return "R11";
	case HEX_REG_INT_REGS_R29:
		return "R29";
	case HEX_REG_INT_REGS_R30:
		return "R30";
	case HEX_REG_INT_REGS_R31:
		return "R31";
	}
}

char *hex_get_int_regs_low8(int opcode_reg) {
	switch (opcode_reg) {
	default:
		return "<err>";
	case HEX_REG_INT_REGS_LOW8_R7:
		return "R7";
	case HEX_REG_INT_REGS_LOW8_R6:
		return "R6";
	case HEX_REG_INT_REGS_LOW8_R5:
		return "R5";
	case HEX_REG_INT_REGS_LOW8_R4:
		return "R4";
	case HEX_REG_INT_REGS_LOW8_R3:
		return "R3";
	case HEX_REG_INT_REGS_LOW8_R2:
		return "R2";
	case HEX_REG_INT_REGS_LOW8_R1:
		return "R1";
	case HEX_REG_INT_REGS_LOW8_R0:
		return "R0";
	}
}

char *hex_get_mod_regs(int opcode_reg) {
	opcode_reg |= 6;

	switch (opcode_reg) {
	default:
		return "<err>";
	case HEX_REG_MOD_REGS_M0:
		return "M0";
	case HEX_REG_MOD_REGS_M1:
		return "M1";
	}
}

char *hex_get_pred_regs(int opcode_reg) {
	switch (opcode_reg) {
	default:
		return "<err>";
	case HEX_REG_PRED_REGS_P0:
		return "P0";
	case HEX_REG_PRED_REGS_P1:
		return "P1";
	case HEX_REG_PRED_REGS_P2:
		return "P2";
	case HEX_REG_PRED_REGS_P3:
		return "P3";
	}
}

char *hex_get_sys_regs(int opcode_reg) {
	switch (opcode_reg) {
	default:
		return "<err>";
	case HEX_REG_SYS_REGS_SGP0:
		return "SGP0";
	case HEX_REG_SYS_REGS_SGP1:
		return "SGP1";
	case HEX_REG_SYS_REGS_STID:
		return "STID";
	case HEX_REG_SYS_REGS_ELR:
		return "ELR";
	case HEX_REG_SYS_REGS_BADVA0:
		return "BADVA0";
	case HEX_REG_SYS_REGS_BADVA1:
		return "BADVA1";
	case HEX_REG_SYS_REGS_SSR:
		return "SSR";
	case HEX_REG_SYS_REGS_CCR:
		return "CCR";
	case HEX_REG_SYS_REGS_HTID:
		return "HTID";
	case HEX_REG_SYS_REGS_BADVA:
		return "BADVA";
	case HEX_REG_SYS_REGS_IMASK:
		return "IMASK";
	case HEX_REG_SYS_REGS_GEVB:
		return "GEVB";
	case HEX_REG_SYS_REGS_S12:
		return "S12";
	case HEX_REG_SYS_REGS_S13:
		return "S13";
	case HEX_REG_SYS_REGS_S14:
		return "S14";
	case HEX_REG_SYS_REGS_S15:
		return "S15";
	case HEX_REG_SYS_REGS_EVB:
		return "EVB";
	case HEX_REG_SYS_REGS_MODECTL:
		return "MODECTL";
	case HEX_REG_SYS_REGS_SYSCFG:
		return "SYSCFG";
	case HEX_REG_SYS_REGS_S19:
		return "S19";
	case HEX_REG_SYS_REGS_IPENDAD:
		return "IPENDAD";
	case HEX_REG_SYS_REGS_VID:
		return "VID";
	case HEX_REG_SYS_REGS_VID1:
		return "VID1";
	case HEX_REG_SYS_REGS_BESTWAIT:
		return "BESTWAIT";
	case HEX_REG_SYS_REGS_S24:
		return "S24";
	case HEX_REG_SYS_REGS_SCHEDCFG:
		return "SCHEDCFG";
	case HEX_REG_SYS_REGS_S26:
		return "S26";
	case HEX_REG_SYS_REGS_CFGBASE:
		return "CFGBASE";
	case HEX_REG_SYS_REGS_DIAG:
		return "DIAG";
	case HEX_REG_SYS_REGS_REV:
		return "REV";
	case HEX_REG_SYS_REGS_PCYCLELO:
		return "PCYCLELO";
	case HEX_REG_SYS_REGS_PCYCLEHI:
		return "PCYCLEHI";
	case HEX_REG_SYS_REGS_ISDBST:
		return "ISDBST";
	case HEX_REG_SYS_REGS_ISDBCFG0:
		return "ISDBCFG0";
	case HEX_REG_SYS_REGS_ISDBCFG1:
		return "ISDBCFG1";
	case HEX_REG_SYS_REGS_LIVELOCK:
		return "LIVELOCK";
	case HEX_REG_SYS_REGS_BRKPTPC0:
		return "BRKPTPC0";
	case HEX_REG_SYS_REGS_BRKPTCFG0:
		return "BRKPTCFG0";
	case HEX_REG_SYS_REGS_BRKPTPC1:
		return "BRKPTPC1";
	case HEX_REG_SYS_REGS_BRKPTCFG1:
		return "BRKPTCFG1";
	case HEX_REG_SYS_REGS_ISDBMBXIN:
		return "ISDBMBXIN";
	case HEX_REG_SYS_REGS_ISDBMBXOUT:
		return "ISDBMBXOUT";
	case HEX_REG_SYS_REGS_ISDBEN:
		return "ISDBEN";
	case HEX_REG_SYS_REGS_ISDBGPR:
		return "ISDBGPR";
	case HEX_REG_SYS_REGS_PMUCNT4:
		return "PMUCNT4";
	case HEX_REG_SYS_REGS_PMUCNT5:
		return "PMUCNT5";
	case HEX_REG_SYS_REGS_PMUCNT6:
		return "PMUCNT6";
	case HEX_REG_SYS_REGS_PMUCNT7:
		return "PMUCNT7";
	case HEX_REG_SYS_REGS_PMUCNT0:
		return "PMUCNT0";
	case HEX_REG_SYS_REGS_PMUCNT1:
		return "PMUCNT1";
	case HEX_REG_SYS_REGS_PMUCNT2:
		return "PMUCNT2";
	case HEX_REG_SYS_REGS_PMUCNT3:
		return "PMUCNT3";
	case HEX_REG_SYS_REGS_PMUEVTCFG:
		return "PMUEVTCFG";
	case HEX_REG_SYS_REGS_S53:
		return "S53";
	case HEX_REG_SYS_REGS_PMUEVTCFG1:
		return "PMUEVTCFG1";
	case HEX_REG_SYS_REGS_PMUSTID1:
		return "PMUSTID1";
	case HEX_REG_SYS_REGS_TIMERLO:
		return "TIMERLO";
	case HEX_REG_SYS_REGS_TIMERHI:
		return "TIMERHI";
	case HEX_REG_SYS_REGS_S58:
		return "S58";
	case HEX_REG_SYS_REGS_S59:
		return "S59";
	case HEX_REG_SYS_REGS_S60:
		return "S60";
	case HEX_REG_SYS_REGS_S61:
		return "S61";
	case HEX_REG_SYS_REGS_S62:
		return "S62";
	case HEX_REG_SYS_REGS_S63:
		return "S63";
	case HEX_REG_SYS_REGS_COMMIT1T:
		return "COMMIT1T";
	case HEX_REG_SYS_REGS_COMMIT2T:
		return "COMMIT2T";
	case HEX_REG_SYS_REGS_COMMIT3T:
		return "COMMIT3T";
	case HEX_REG_SYS_REGS_COMMIT4T:
		return "COMMIT4T";
	case HEX_REG_SYS_REGS_COMMIT5T:
		return "COMMIT5T";
	case HEX_REG_SYS_REGS_COMMIT6T:
		return "COMMIT6T";
	case HEX_REG_SYS_REGS_PCYCLE1T:
		return "PCYCLE1T";
	case HEX_REG_SYS_REGS_PCYCLE2T:
		return "PCYCLE2T";
	case HEX_REG_SYS_REGS_PCYCLE3T:
		return "PCYCLE3T";
	case HEX_REG_SYS_REGS_PCYCLE4T:
		return "PCYCLE4T";
	case HEX_REG_SYS_REGS_PCYCLE5T:
		return "PCYCLE5T";
	case HEX_REG_SYS_REGS_PCYCLE6T:
		return "PCYCLE6T";
	case HEX_REG_SYS_REGS_STFINST:
		return "STFINST";
	case HEX_REG_SYS_REGS_ISDBCMD:
		return "ISDBCMD";
	case HEX_REG_SYS_REGS_ISDBVER:
		return "ISDBVER";
	case HEX_REG_SYS_REGS_BRKPTINFO:
		return "BRKPTINFO";
	case HEX_REG_SYS_REGS_RGDR3:
		return "RGDR3";
	}
}

char *hex_get_sys_regs64(int opcode_reg) {
	switch (opcode_reg) {
	default:
		return "<err>";
	case HEX_REG_SYS_REGS64_S1_0:
		return "S1:0";
	case HEX_REG_SYS_REGS64_S3_2:
		return "S3:2";
	case HEX_REG_SYS_REGS64_S5_4:
		return "S5:4";
	case HEX_REG_SYS_REGS64_S7_6:
		return "S7:6";
	case HEX_REG_SYS_REGS64_S9_8:
		return "S9:8";
	case HEX_REG_SYS_REGS64_S11_10:
		return "S11:10";
	case HEX_REG_SYS_REGS64_S13_12:
		return "S13:12";
	case HEX_REG_SYS_REGS64_S15_14:
		return "S15:14";
	case HEX_REG_SYS_REGS64_S17_16:
		return "S17:16";
	case HEX_REG_SYS_REGS64_S19_18:
		return "S19:18";
	case HEX_REG_SYS_REGS64_S21_20:
		return "S21:20";
	case HEX_REG_SYS_REGS64_S23_22:
		return "S23:22";
	case HEX_REG_SYS_REGS64_S25_24:
		return "S25:24";
	case HEX_REG_SYS_REGS64_S27_26:
		return "S27:26";
	case HEX_REG_SYS_REGS64_S29_28:
		return "S29:28";
	case HEX_REG_SYS_REGS64_S31_30:
		return "S31:30";
	case HEX_REG_SYS_REGS64_S33_32:
		return "S33:32";
	case HEX_REG_SYS_REGS64_S35_34:
		return "S35:34";
	case HEX_REG_SYS_REGS64_S37_36:
		return "S37:36";
	case HEX_REG_SYS_REGS64_S39_38:
		return "S39:38";
	case HEX_REG_SYS_REGS64_S41_40:
		return "S41:40";
	case HEX_REG_SYS_REGS64_S43_42:
		return "S43:42";
	case HEX_REG_SYS_REGS64_S45_44:
		return "S45:44";
	case HEX_REG_SYS_REGS64_S47_46:
		return "S47:46";
	case HEX_REG_SYS_REGS64_S49_48:
		return "S49:48";
	case HEX_REG_SYS_REGS64_S51_50:
		return "S51:50";
	case HEX_REG_SYS_REGS64_S53_52:
		return "S53:52";
	case HEX_REG_SYS_REGS64_S55_54:
		return "S55:54";
	case HEX_REG_SYS_REGS64_S57_56:
		return "S57:56";
	case HEX_REG_SYS_REGS64_S59_58:
		return "S59:58";
	case HEX_REG_SYS_REGS64_S61_60:
		return "S61:60";
	case HEX_REG_SYS_REGS64_S63_62:
		return "S63:62";
	case HEX_REG_SYS_REGS64_S65_64:
		return "S65:64";
	case HEX_REG_SYS_REGS64_S67_66:
		return "S67:66";
	case HEX_REG_SYS_REGS64_S69_68:
		return "S69:68";
	case HEX_REG_SYS_REGS64_S71_70:
		return "S71:70";
	case HEX_REG_SYS_REGS64_S73_72:
		return "S73:72";
	case HEX_REG_SYS_REGS64_S75_74:
		return "S75:74";
	case HEX_REG_SYS_REGS64_S77_76:
		return "S77:76";
	case HEX_REG_SYS_REGS64_S79_78:
		return "S79:78";
	}
}

/**
 * \brief Resolves the 3 bit value of an Nt.new reg to the general register of the producer.
 *
 * \param addr The address of the current instruction.
 * \param reg_num Bits of Nt.new reg.
 * \param p The current packet.
 * \return int The number of the general register. Or UT32_MAX if any error occured.
 */
int resolve_n_register(const int reg_num, const ut32 addr, const HexPkt *p) {
	// .new values are documented in Programmers Reference Manual
	if (reg_num <= 1 || reg_num >= 8) {
		return UT32_MAX;
	}

	ut8 ahead = (reg_num >> 1);
	ut8 i = hexagon_get_pkt_index_of_addr(addr, p);
	if (i == UT8_MAX) {
		return UT32_MAX;
	}

	ut8 prod_i = i; // Producer index
	HexInsn *hi;
	RzListIter *it;
	rz_list_foreach_prev(p->insn, it, hi) {
		if (ahead == 0) {
			break;
		}
		if (hi->addr < addr) {
			if (hi->instruction == HEX_INS_A4_EXT) {
				--prod_i;
				continue;
			}
			--ahead;
			--prod_i;
		}
	}

	hi = rz_list_get_n(p->insn, prod_i);

	if (!hi) {
		return UT32_MAX;
	}
	if (hi->instruction == HEX_INS_A4_EXT) {
		return UT32_MAX;
	}

	for (ut8 i = 0; i < 6; ++i) {
		if (hi->ops[i].attr & HEX_OP_REG_OUT) {
			return hi->ops[i].op.reg;
		}
	}
	return UT32_MAX;
}
