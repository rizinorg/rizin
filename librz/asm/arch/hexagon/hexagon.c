// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
//
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
#include <rz_util/rz_assert.h>
#include "hexagon.h"

char *hex_get_ctr_regs(int opcode_reg) {
	switch (opcode_reg) {
	default:
		rz_warn_if_reached();
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
		rz_warn_if_reached();
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
		rz_warn_if_reached();
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
		rz_warn_if_reached();
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
		rz_warn_if_reached();
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
		rz_warn_if_reached();
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
		rz_warn_if_reached();
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
		rz_warn_if_reached();
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
		rz_warn_if_reached();
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
		rz_warn_if_reached();
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
		rz_warn_if_reached();
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
		rz_warn_if_reached();
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
		rz_warn_if_reached();
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
		rz_warn_if_reached();
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
		rz_warn_if_reached();
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

inline bool hex_if_duplex(uint32_t insn_word) {
	if (((insn_word & 0xc000) >> 18) == 0) {
		return true;
	}
	return false;
}

static inline bool is_last_instr(const ut8 parse_bits) {
	// Duplex instr. (parse bits = 0) are always the last.
	return ((parse_bits == 0x3) || (parse_bits == 0x0));
}

static inline bool is_endloop0_pkt(const ut8 pi_0, const ut8 pi_1) {
	return ((pi_0 == 0x2) && ((pi_1 == 0x1) || (pi_1 == 0x3)));
}

static inline bool is_endloop1_pkt(const ut8 pi_0, const ut8 pi_1) {
	return ((pi_0 == 0x1) && (pi_1 == 0x2));
}

static inline bool is_endloop01_pkt(const ut8 pi_0, const ut8 pi_1) {
	return ((pi_0 == 0x2) && (pi_1 == 0x2));
}

void hex_set_pkt_info(HexPktInfo *i_pkt_info) {
	static HexPkt pkt = { 0 }; // Current packet
	static ut8 i = 0; // Index of the instruction in the current packet.
	static ut8 p0 = 255;
	static ut8 p1 = 255;
	static bool new_pkt_starts = true;

	memcpy(&pkt.i_infos[i], i_pkt_info, sizeof(HexPktInfo));

	// Parse instr. position in pkt
	if (new_pkt_starts && is_last_instr(i_pkt_info->parse_bits)) { // Single instruction packet.
		// TODO No indent in visual mode for "[" without spaces.
		//  Possible cause: 2 extra bytes in UTF-8 chars are printed as spaces?
		strncpy(i_pkt_info->syntax_prefix, "[    ", 8);
		i_pkt_info->first_insn = true;
		i_pkt_info->last_insn = true;
		new_pkt_starts = true;
		i = 0;
	} else if (new_pkt_starts) {
		strncpy(i_pkt_info->syntax_prefix, "/", 8); // TODO Add utf8 option "┌"
		i_pkt_info->first_insn = true;
		new_pkt_starts = false;
		// Just in case evil persons set the parsing bits incorrectly and pkts with more than 4 instr. occur.
		i = (i + 1) % 4;
	} else if (is_last_instr(i_pkt_info->parse_bits)) {
		strncpy(i_pkt_info->syntax_prefix, "\\", 8); // TODO Add utf8 option "└"
		i_pkt_info->last_insn = true;
		new_pkt_starts = true;

		p0 = pkt.i_infos[0].parse_bits;
		p1 = pkt.i_infos[1].parse_bits;

		if (is_endloop01_pkt(p0, p1)) {
			strncpy(i_pkt_info->syntax_postfix, " < endloop01", 16); // TODO Add utf8 option "∎"
			i_pkt_info->loop_attr |= (HEX_ENDS_LOOP_0 | HEX_ENDS_LOOP_1);
		} else if (is_endloop0_pkt(p0, p1)) {
			strncpy(i_pkt_info->syntax_postfix, " < endloop0", 16);
			i_pkt_info->loop_attr |= HEX_ENDS_LOOP_0;
		} else if (is_endloop1_pkt(p0, p1)) {
			strncpy(i_pkt_info->syntax_postfix, " < endloop1", 16);
			i_pkt_info->loop_attr |= HEX_ENDS_LOOP_1;
		}
		i = 0;
	} else {
		strncpy(i_pkt_info->syntax_prefix, "|", 8); // TODO Add utf8 option "│"
		new_pkt_starts = false;
		i = (i + 1) % 4;
	}
}

static inline bool imm_is_extendable(ut32 const_ext, ut8 type) {
	return ((const_ext != 0) && (type == HEX_OP_TYPE_IMM));
}

static inline bool imm_is_scaled(HexOpAttr attr) {
	return (attr & HEX_OP_IMM_SCALED);
}

void hex_op_extend(RZ_INOUT HexOp *op, bool set_new_extender) {
	// Constant extender value
	static ut32 constant_extender = 0;

	if (set_new_extender) {
		constant_extender = op->op.imm;
		return;
	}

	if (imm_is_extendable(constant_extender, op->type)) {
		if (imm_is_scaled(op->attr)) {
			op->op.imm = (op->op.imm >> op->shift); // Extended immediate values won't get scaled. Redo it.
		}
		op->op.imm = ((op->op.imm) & 0x3F) | (constant_extender);
	}
	constant_extender = 0;
}
