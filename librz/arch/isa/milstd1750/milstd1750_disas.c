// SPDX-FileCopyrightText: 2026 godcodehunter
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * Disassembler for the MIL-STD-1750A instruction set architecture.
 *
 * MIL-STD-1750A is a 16-bit military standard ISA originally developed by
 * the US Department of Defense for airborne embedded computers. It features
 * 16 general-purpose registers (R0-R15), 16-bit word-addressable memory,
 * and a mix of one-word (16-bit) and two-word (32-bit) instructions.
 *
 * Architecture: decoding (`rz_milstd1750_decode`) is split from formatting
 * (`rz_milstd1750_stringify`) so the analysis plugin can read the typed
 * fields of `MilStd1750Instruction` directly instead of re-parsing bits.
 *
 * References:
 * - MIL-STD-1750A Military Standard Sixteen-Bit Computer Instruction Set Architecture
 * - UT1750AR RadHard RISC Microprocessor data sheet
 * - https://github.com/okellogg/milstd1750tools/blob/master/as1750/as1750.c#L947
 * - https://github.com/EtchedPixels/sim1750a
 * - https://github.com/WarlockD/Mil-std-1750A-Emulator-C20/tree/master/instructions
 * - binutils for mil-std-1750 https://github.com/okellogg/binutilstd1750
 */

#include "milstd1750_disas.h"
#include <rz_types.h>

typedef struct {
	ut16 opcode;
	const char *mnemonic;
	MilStd1750Format format;
} MilStd1750LongInstruction;

typedef struct {
	ut16 opcode;
	const char *mnemonic;
} MilStd1750XioCommand;

static const MilStd1750XioCommand milstd1750_xio_commands[] = {
	{ MIL_XIO_SMK, "SMK" },
	{ MIL_XIO_CLIR, "CLIR" },
	{ MIL_XIO_ENBL, "ENBL" },
	{ MIL_XIO_DSBL, "DSBL" },
	{ MIL_XIO_RPI, "RPI" },
	{ MIL_XIO_SPI, "SPI" },
	{ MIL_XIO_WSW, "WSW" },
	{ MIL_XIO_RMK, "RMK" },
	{ MIL_XIO_RPIR, "RPIR" },
	{ MIL_XIO_RSW, "RSW" },
	{ MIL_XIO_RCFR, "RCFR" },
	{ MIL_XIO_OD, "OD" },
	{ MIL_XIO_RNS, "RNS" },
	{ MIL_XIO_CO, "CO" },
	{ MIL_XIO_CLC, "CLC" },
	{ MIL_XIO_MPEN, "MPEN" },
	{ MIL_XIO_ESUR, "ESUR" },
	{ MIL_XIO_DSUR, "DSUR" },
	{ MIL_XIO_DMAE, "DMAE" },
	{ MIL_XIO_DMAD, "DMAD" },
	{ MIL_XIO_TAS, "TAS" },
	{ MIL_XIO_TAH, "TAH" },
	{ MIL_XIO_OTA, "OTA" },
	{ MIL_XIO_GO, "GO" },
	{ MIL_XIO_TBS, "TBS" },
	{ MIL_XIO_TBH, "TBH" },
	{ MIL_XIO_OTB, "OTB" },
	{ MIL_XIO_RIC1, "RIC1" },
	{ MIL_XIO_RIC2, "RIC2" },
	{ MIL_XIO_RDOR, "RDOR" },
	{ MIL_XIO_RDI, "RDI" },
	{ MIL_XIO_TPIO, "TPIO" },
	{ MIL_XIO_RMFS, "RMFS" },
	{ MIL_XIO_CI, "CI" },
	{ MIL_XIO_RCS, "RCS" },
	{ MIL_XIO_ITA, "ITA" },
	{ MIL_XIO_ITB, "ITB" },
};

static char *format_xio_command(ut16 cmd) {
	// Parse "PO"
	if ((cmd >> 12) == 0x0) {
		ut8 Y = (cmd >> 8) & 0x0F;
		ut8 X = cmd & 0xFF;

		return rz_str_newf("PO { %d, %d }", Y, X);
	}

	// Parse "PI"
	if ((cmd >> 12) == 0x8) {
		ut8 Y = (cmd >> 8) & 0x0F;
		ut8 X = cmd & 0xFF;

		return rz_str_newf("PI { %d, %d }", Y, X);
	}

	// Parse "LMP"
	if ((cmd >> 8) == 0x50) {
		ut8 X = cmd & 0xFF;

		return rz_str_newf("LMP { %d }", X);
	}

	// Parse "WIPR"
	if ((cmd >> 8) == 0x51) {
		ut8 X = (cmd & 0xFF) >> 4;
		ut8 Y = cmd & 0x0F;

		return rz_str_newf("WIPR { %d, %d }", X, Y);
	}

	// Parse "WOPR"
	if ((cmd >> 8) == 0x52) {
		ut8 X = (cmd & 0xFF) >> 4;
		ut8 Y = cmd & 0x0F;

		return rz_str_newf("WOPR { %d, %d }", X, Y);
	}

	// Parse "RMP"
	if ((cmd >> 8) == 0xD0) {
		ut8 X = cmd & 0xFF;

		return rz_str_newf("RMP { %d }", X);
	}

	// Parse "RIPR"
	if ((cmd >> 8) == 0xD1) {
		ut8 X = (cmd & 0xFF) >> 4;
		ut8 Y = cmd & 0x0F;

		return rz_str_newf("RIPR { %d, %d }", X, Y);
	}

	// Parse "ROPR"
	if ((cmd >> 8) == 0xD2) {
		ut8 X = (cmd & 0xFF) >> 4;
		ut8 Y = cmd & 0x0F;

		return rz_str_newf("ROPR { %d, %d }", X, Y);
	}

	for (size_t i = 0; i < RZ_ARRAY_SIZE(milstd1750_xio_commands); ++i) {
		if (milstd1750_xio_commands[i].opcode == cmd) {
			return rz_str_dup(milstd1750_xio_commands[i].mnemonic);
		}
	}

	return rz_str_newf("0x%04x", cmd);
}

/**
 * \note Some instructions are mentioned but not FULL defined:
 * BRX, CALL, CISP, CISM, CIM, CLC, CMP, CR, DMAD, DMAE,
 * DSUR, EFLX, FB, FBX, FL, FLX, GO, IMM, IMML, INR, ITA,
 * ITB, LBI, LMP, LRI, MOVC, MOVB, MPEN, MULS, OD, OTA,
 * OTB, OTR, POP, PUSH, SL, SM, SMK, SPI, STA, STR, STRI,
 * SUB, SUBB, SWAB, TA
 */
// clang-format off
static const MilStd1750LongInstruction milstd1750_inst_tab[] = {
	{ MIL_OP_ABX, "ABX", MIL_FMT_BX },
	{ MIL_OP_ANDX, "ANDX", MIL_FMT_BX },
	{ MIL_OP_A, "A", MIL_FMT_MEM },
	{ MIL_OP_ABS, "ABS", MIL_FMT_R },
	{ MIL_OP_AIM, "AIM", MIL_FMT_IM_OCX },
	{ MIL_OP_AISP, "AISP", MIL_FMT_IS },
	{ MIL_OP_AND, "AND", MIL_FMT_MEM },
	{ MIL_OP_ANDB, "ANDB", MIL_FMT_B },
	{ MIL_OP_ANDM, "ANDM", MIL_FMT_IM_OCX },
	{ MIL_OP_ANDR, "ANDR", MIL_FMT_R },
	{ MIL_OP_AR, "AR", MIL_FMT_R },
	{ MIL_OP_AB, "AB", MIL_FMT_B },
	{ MIL_OP_BEX, "BEX", MIL_FMT_S },
	{ MIL_OP_BEZ, "BEZ", MIL_FMT_ICR },
	{ MIL_OP_BGE, "BGE", MIL_FMT_ICR },
	{ MIL_OP_BGT, "BGT", MIL_FMT_ICR },
	{ MIL_OP_BIF, "BIF", MIL_FMT_S },
	{ MIL_OP_BLE, "BLE", MIL_FMT_ICR },
	{ MIL_OP_BLT, "BLT", MIL_FMT_ICR },
	{ MIL_OP_BNZ, "BNZ", MIL_FMT_ICR },
	{ MIL_OP_BPT, "BPT", MIL_FMT_NONE },
	{ MIL_OP_BR, "BR", MIL_FMT_ICR },
	{ MIL_OP_C, "C", MIL_FMT_MEM },
	{ MIL_OP_CB, "CB", MIL_FMT_B },
	{ MIL_OP_CBL, "CBL", MIL_FMT_MEM },
	{ MIL_OP_CBX, "CBX", MIL_FMT_BX },
	{ MIL_OP_CR, "CR", MIL_FMT_R },
	{ MIL_OP_CISP, "CISP", MIL_FMT_IS },
	{ MIL_OP_CISN, "CISN", MIL_FMT_IS },
	{ MIL_OP_CIM, "CIM", MIL_FMT_IM_OCX },
	{ MIL_OP_DDR, "DDR", MIL_FMT_R },
	{ MIL_OP_DD, "DD", MIL_FMT_MEM },
	{ MIL_OP_D, "D", MIL_FMT_MEM },
	{ MIL_OP_DA, "DA", MIL_FMT_MEM },
	{ MIL_OP_DABS, "DABS", MIL_FMT_R },
	{ MIL_OP_DAR, "DAR", MIL_FMT_R },
	{ MIL_OP_DB, "DB", MIL_FMT_B },
	{ MIL_OP_DC, "DC", MIL_FMT_MEM },
	{ MIL_OP_DCR, "DCR", MIL_FMT_R },
	{ MIL_OP_DECM, "DECM", MIL_FMT_IM_1_16 },
	{ MIL_OP_DIM, "DIM", MIL_FMT_IM_OCX },
	{ MIL_OP_DISN, "DISN", MIL_FMT_IS },
	{ MIL_OP_DISP, "DISP", MIL_FMT_IS },
	{ MIL_OP_DL, "DL", MIL_FMT_MEM },
	{ MIL_OP_DLB, "DLB", MIL_FMT_B },
	{ MIL_OP_DLBX, "DLBX", MIL_FMT_BX },
	{ MIL_OP_DLE, "DLE", MIL_FMT_MEM },
	{ MIL_OP_DLI, "DLI", MIL_FMT_MEM },
	{ MIL_OP_DLR, "DLR", MIL_FMT_R },
	{ MIL_OP_DM, "DM", MIL_FMT_MEM },
	{ MIL_OP_DMR, "DMR", MIL_FMT_R },
	{ MIL_OP_DNEG, "DNEG", MIL_FMT_R },
	{ MIL_OP_DR, "DR", MIL_FMT_R },
	{ MIL_OP_DS, "DS", MIL_FMT_MEM },
	{ MIL_OP_DSAR, "DSAR", MIL_FMT_R },
	{ MIL_OP_DSCR, "DSCR", MIL_FMT_R },
	{ MIL_OP_DSLL, "DSLL", MIL_FMT_R_IMM },
	{ MIL_OP_DSLC, "DSLC", MIL_FMT_R_IMM },
	{ MIL_OP_DSLR, "DSLR", MIL_FMT_R },
	{ MIL_OP_DSRA, "DSRA", MIL_FMT_R_IMM },
	{ MIL_OP_DSRL, "DSRL", MIL_FMT_R_IMM },
	{ MIL_OP_DSR, "DSR", MIL_FMT_R },
	{ MIL_OP_DST, "DST", MIL_FMT_MEM },
	{ MIL_OP_DSTB, "DSTB", MIL_FMT_B },
	{ MIL_OP_DSTI, "DSTI", MIL_FMT_MEM },
	{ MIL_OP_DSTE, "DSTE", MIL_FMT_MEM },
	{ MIL_OP_DSTX, "DSTX", MIL_FMT_BX },
	{ MIL_OP_DV, "DV", MIL_FMT_MEM },
	{ MIL_OP_DVIM, "DVIM", MIL_FMT_IM_OCX },
	{ MIL_OP_DVR, "DVR", MIL_FMT_R },
	{ MIL_OP_DBX, "DBX", MIL_FMT_BX },
	{ MIL_OP_EFLT, "EFLT", MIL_FMT_R },
	{ MIL_OP_EFIX, "EFIX", MIL_FMT_R },
	{ MIL_OP_EFC, "EFC", MIL_FMT_MEM },
	{ MIL_OP_EFCR, "EFCR", MIL_FMT_R },
	{ MIL_OP_EFA, "EFA", MIL_FMT_MEM },
	{ MIL_OP_EFAR, "EFAR", MIL_FMT_R },
	{ MIL_OP_EFD, "EFD", MIL_FMT_MEM },
	{ MIL_OP_EFDR, "EFDR", MIL_FMT_R },
	{ MIL_OP_EFL, "EFL", MIL_FMT_MEM },
	{ MIL_OP_EFM, "EFM", MIL_FMT_MEM },
	{ MIL_OP_EFMR, "EFMR", MIL_FMT_R },
	{ MIL_OP_EFS, "EFS", MIL_FMT_MEM },
	{ MIL_OP_EFSR, "EFSR", MIL_FMT_R },
	{ MIL_OP_EFST, "EFST", MIL_FMT_MEM },
	{ MIL_OP_FABS, "FABS", MIL_FMT_R },
	{ MIL_OP_FA, "FA", MIL_FMT_MEM },
	{ MIL_OP_FAB, "FAB", MIL_FMT_B },
	{ MIL_OP_FABX, "FABX", MIL_FMT_BX },
	{ MIL_OP_FAR, "FAR", MIL_FMT_R },
	{ MIL_OP_FC, "FC", MIL_FMT_MEM },
	{ MIL_OP_FCB, "FCB", MIL_FMT_B },
	{ MIL_OP_FCBX, "FCBX", MIL_FMT_BX },
	{ MIL_OP_FCR, "FCR", MIL_FMT_R },
	{ MIL_OP_FD, "FD", MIL_FMT_MEM },
	{ MIL_OP_FDB, "FDB", MIL_FMT_B },
	{ MIL_OP_FDBX, "FDBX", MIL_FMT_BX },
	{ MIL_OP_FDR, "FDR", MIL_FMT_R },
	{ MIL_OP_FIX, "FIX", MIL_FMT_R },
	{ MIL_OP_FLT, "FLT", MIL_FMT_R },
	{ MIL_OP_FM, "FM", MIL_FMT_MEM },
	{ MIL_OP_FMB, "FMB", MIL_FMT_B },
	{ MIL_OP_FMBX, "FMBX", MIL_FMT_BX },
	{ MIL_OP_FMR, "FMR", MIL_FMT_R },
	{ MIL_OP_FNEG, "FNEG", MIL_FMT_R },
	{ MIL_OP_FS, "FS", MIL_FMT_MEM },
	{ MIL_OP_FSB, "FSB", MIL_FMT_B },
	{ MIL_OP_FSBX, "FSBX", MIL_FMT_BX },
	{ MIL_OP_FSR, "FSR", MIL_FMT_R },
	{ MIL_OP_INCM, "INCM", MIL_FMT_IM_1_16 },
	{ MIL_OP_JC, "JC", MIL_FMT_JUMP },
	{ MIL_OP_JCI, "JCI", MIL_FMT_JUMP },
	{ MIL_OP_JS, "JS", MIL_FMT_MEM },
	{ MIL_OP_LISN, "LISN", MIL_FMT_IS },
	{ MIL_OP_L, "L", MIL_FMT_MEM },
	{ MIL_OP_LB, "LB", MIL_FMT_B },
	{ MIL_OP_LBX, "LBX", MIL_FMT_BX },
	{ MIL_OP_LE, "LE", MIL_FMT_MEM },
	{ MIL_OP_LI, "LI", MIL_FMT_MEM },
	{ MIL_OP_LIM, "LIM", MIL_FMT_MEM },
	{ MIL_OP_LISP, "LISP", MIL_FMT_IS },
	{ MIL_OP_LLB, "LLB", MIL_FMT_MEM },
	{ MIL_OP_LLBI, "LLBI", MIL_FMT_MEM },
	{ MIL_OP_LM, "LM", MIL_FMT_IM_0_15 },
	{ MIL_OP_LR, "LR", MIL_FMT_R },
	{ MIL_OP_LSTI, "LSTI", MIL_FMT_ADDR },
	{ MIL_OP_LST, "LST", MIL_FMT_ADDR },
	{ MIL_OP_LUB, "LUB", MIL_FMT_MEM },
	{ MIL_OP_LUBI, "LUBI", MIL_FMT_MEM },
	{ MIL_OP_MR, "MR", MIL_FMT_R },
	{ MIL_OP_M, "M", MIL_FMT_MEM },
	{ MIL_OP_MB, "MB", MIL_FMT_B },
	{ MIL_OP_MBX, "MBX", MIL_FMT_BX },
	{ MIL_OP_MISN, "MISN", MIL_FMT_IS },
	{ MIL_OP_MISP, "MISP", MIL_FMT_IS },
	{ MIL_OP_MIM, "MIM", MIL_FMT_IM_OCX },
	{ MIL_OP_MOV, "MOV", MIL_FMT_R },
	{ MIL_OP_MS, "MS", MIL_FMT_MEM },
	{ MIL_OP_MSIM, "MSIM", MIL_FMT_IM_OCX },
	{ MIL_OP_MSR, "MSR", MIL_FMT_R },
	{ MIL_OP_N, "N", MIL_FMT_MEM },
	{ MIL_OP_NEG, "NEG", MIL_FMT_R },
	{ MIL_OP_NIM, "NIM", MIL_FMT_IM_OCX },
	{ MIL_OP_NOP, "NOP", MIL_FMT_NONE },
	{ MIL_OP_NR, "NR", MIL_FMT_R },
	{ MIL_OP_OR, "OR", MIL_FMT_MEM },
	{ MIL_OP_ORB, "ORB", MIL_FMT_B },
	{ MIL_OP_ORBX, "ORBX", MIL_FMT_BX },
	{ MIL_OP_ORIM, "ORIM", MIL_FMT_IM_OCX },
	{ MIL_OP_ORR, "ORR", MIL_FMT_R },
	{ MIL_OP_POPM, "POPM", MIL_FMT_R },
	{ MIL_OP_PSHM, "PSHM", MIL_FMT_R },
	{ MIL_OP_RB, "RB", MIL_FMT_IM_0_15 },
	{ MIL_OP_RBI, "RBI", MIL_FMT_IM_0_15 },
	{ MIL_OP_RBR, "RBR", MIL_FMT_IMM_R },
	{ MIL_OP_RVBR, "RVBR", MIL_FMT_R },
	{ MIL_OP_SLBI, "SLBI", MIL_FMT_MEM },
	{ MIL_OP_SBBX, "SBBX", MIL_FMT_BX },
	{ MIL_OP_STBX, "STBX", MIL_FMT_BX },
	{ MIL_OP_SCR, "SCR", MIL_FMT_R },
	{ MIL_OP_SAR, "SAR", MIL_FMT_R },
	{ MIL_OP_S, "S", MIL_FMT_MEM },
	{ MIL_OP_SB, "SB", MIL_FMT_IM_0_15 },
	{ MIL_OP_SBB, "SBB", MIL_FMT_B },
	{ MIL_OP_SBR, "SBR", MIL_FMT_IMM_R },
	{ MIL_OP_SBI, "SBI", MIL_FMT_IM_0_15 },
	{ MIL_OP_SFBS, "SFBS", MIL_FMT_R },
	{ MIL_OP_SIM, "SIM", MIL_FMT_IM_OCX },
	{ MIL_OP_SISP, "SISP", MIL_FMT_IS },
	{ MIL_OP_SJS, "SJS", MIL_FMT_MEM },
	{ MIL_OP_SLC, "SLC", MIL_FMT_R_IMM },
	{ MIL_OP_SLL, "SLL", MIL_FMT_R_IMM },
	{ MIL_OP_SLR, "SLR", MIL_FMT_R },
	{ MIL_OP_SOJ, "SOJ", MIL_FMT_MEM },
	{ MIL_OP_SR, "SR", MIL_FMT_R },
	{ MIL_OP_SRA, "SRA", MIL_FMT_R_IMM },
	{ MIL_OP_SRM, "SRM", MIL_FMT_MEM },
	{ MIL_OP_SRL, "SRL", MIL_FMT_R_IMM },
	{ MIL_OP_ST, "ST", MIL_FMT_MEM },
	{ MIL_OP_STC, "STC", MIL_FMT_IM_0_15 },
	{ MIL_OP_STCI, "STCI", MIL_FMT_IM_0_15 },
	{ MIL_OP_STI, "STI", MIL_FMT_MEM },
	{ MIL_OP_STB, "STB", MIL_FMT_B },
	{ MIL_OP_STLB, "STLB", MIL_FMT_MEM },
	{ MIL_OP_STM, "STM", MIL_FMT_IM_0_15 },
	{ MIL_OP_STUB, "STUB", MIL_FMT_MEM },
	{ MIL_OP_SUBI, "SUBI", MIL_FMT_MEM },
	{ MIL_OP_SVBR, "SVBR", MIL_FMT_R },
	{ MIL_OP_TB, "TB", MIL_FMT_IM_0_15 },
	{ MIL_OP_STE, "STE", MIL_FMT_MEM },
	{ MIL_OP_TBR, "TBR", MIL_FMT_IMM_R },
	{ MIL_OP_TVBR, "TVBR", MIL_FMT_R },
	{ MIL_OP_TBI, "TBI", MIL_FMT_IM_0_15 },
	{ MIL_OP_TSB, "TSB", MIL_FMT_IM_0_15 },
	{ MIL_OP_UA, "UA", MIL_FMT_MEM },
	{ MIL_OP_UAR, "UAR", MIL_FMT_R },
	{ MIL_OP_UC, "UC", MIL_FMT_MEM },
	{ MIL_OP_UCIM, "UCIM", MIL_FMT_IM_OCX },
	{ MIL_OP_UCR, "UCR", MIL_FMT_R },
	{ MIL_OP_URS, "URS", MIL_FMT_SR },
	{ MIL_OP_US, "US", MIL_FMT_MEM },
	{ MIL_OP_USR, "USR", MIL_FMT_R },
	{ MIL_OP_VIO, "VIO", MIL_FMT_MEM },
	{ MIL_OP_XBR, "XBR", MIL_FMT_R },
	{ MIL_OP_XIO, "XIO", MIL_FMT_XIO },
	{ MIL_OP_XOR, "XOR", MIL_FMT_MEM },
	{ MIL_OP_XORM, "XORM", MIL_FMT_IM_OCX },
	{ MIL_OP_XORR, "XORR", MIL_FMT_R },
	{ MIL_OP_XWR, "XWR", MIL_FMT_R },
};
// clang-format on

// Each format implies a specific opcode mask:
//   BX     → 0xFCF0  (6-bit op + 4-bit opex)
//   B      → 0xFC00  (6-bit op)
//   IM_OCX → 0xFF0F  (8-bit op + 4-bit opex)
//   NONE   → 0xFFFF  (full match — distinguishes BPT 0xFFFF from NOP 0xFF00)
//   others → 0xFF00  (8-bit op)
// No cross-format collisions because opcode ranges are disjoint.
static ut16 format_mask(MilStd1750Format format) {
	switch (format) {
	case MIL_FMT_NONE:
		return 0xFFFF;
	case MIL_FMT_BX:
		return 0xFCF0;
	case MIL_FMT_B:
		return 0xFC00;
	case MIL_FMT_IM_OCX:
		return 0xFF0F;
	default:
		return 0xFF00;
	}
}

static ut8 format_size(MilStd1750Format format) {
	switch (format) {
	case MIL_FMT_XIO:
	case MIL_FMT_MEM:
	case MIL_FMT_IM_OCX:
	case MIL_FMT_IM_0_15:
	case MIL_FMT_IM_1_16:
	case MIL_FMT_ADDR:
	case MIL_FMT_JUMP:
		return 4;
	default:
		return 2;
	}
}

static const MilStd1750LongInstruction *match_instruction(ut16 w1) {
	for (size_t i = 0; i < RZ_ARRAY_SIZE(milstd1750_inst_tab); ++i) {
		ut16 mask = format_mask(milstd1750_inst_tab[i].format);
		if (milstd1750_inst_tab[i].opcode == (w1 & mask)) {
			return &milstd1750_inst_tab[i];
		}
	}
	return NULL;
}

bool rz_milstd1750_decode(const ut8 *buf, int len, MilStd1750Instruction *out) {
	if (len < 2 || !out) {
		return false;
	}
	ut16 w1 = rz_read_be16(buf);
	const MilStd1750LongInstruction *m = match_instruction(w1);
	if (!m) {
		return false;
	}

	ut8 size = format_size(m->format);
	if (len < size) {
		return false;
	}
	ut16 w2 = (size == 4) ? rz_read_be16(buf + 2) : 0;
	ut32 full = ((ut32)w1 << 16) | w2;

	memset(out, 0, sizeof(*out));
	out->mnemonic = m->mnemonic;
	out->format = m->format;
	out->size = size;
	out->opcode = m->opcode;

	switch (m->format) {
	case MIL_FMT_NONE:
		break;
	case MIL_FMT_R:
		out->ra = (w1 >> 4) & 0xF;
		out->rb = w1 & 0xF;
		break;
	case MIL_FMT_SR:
		out->ra = (w1 >> 4) & 0xF;
		break;
	case MIL_FMT_IMM_R:
		out->imm8 = (w1 >> 4) & 0xF;
		out->rb = w1 & 0xF;
		break;
	case MIL_FMT_R_IMM:
		out->rb = w1 & 0xF;
		out->imm8 = ((w1 >> 4) & 0xF) + 1;
		break;
	case MIL_FMT_IS:
		out->ra = (w1 >> 4) & 0xF;
		out->imm8 = (w1 & 0xF) + 1;
		break;
	case MIL_FMT_BX:
		out->br = ((w1 >> 8) & 0x3) + 12;
		out->rx = w1 & 0xF;
		break;
	case MIL_FMT_B:
		out->br = ((w1 >> 8) & 0x3) + 12;
		out->imm8 = w1 & 0xFF;
		break;
	case MIL_FMT_ICR:
		out->imm8 = w1 & 0xFF;
		break;
	case MIL_FMT_S:
		out->special = w1 >> 8;
		out->imm8 = w1 & 0xFF; // BIF uses all 8 bits; BEX uses low 4
		break;
	case MIL_FMT_XIO:
		out->ra = (full >> 20) & 0xF;
		out->rx = (full >> 16) & 0xF;
		out->xio_cmd = full & 0xFFFF;
		break;
	case MIL_FMT_MEM:
		out->ra = (full >> 20) & 0xF;
		out->rx = (full >> 16) & 0xF;
		out->addr = full & 0xFFFF;
		break;
	case MIL_FMT_IM_OCX:
		out->ra = (full >> 20) & 0xF;
		out->opex = (full >> 16) & 0xF;
		out->imm16 = full & 0xFFFF;
		break;
	case MIL_FMT_IM_0_15:
		out->imm8 = (full >> 20) & 0xF;
		out->rx = (full >> 16) & 0xF;
		out->addr = full & 0xFFFF;
		break;
	case MIL_FMT_IM_1_16:
		// Semantic range is 1..16; the printed value is the raw 4-bit N (0..15).
		out->imm8 = (full >> 20) & 0xF;
		out->rx = (full >> 16) & 0xF;
		out->addr = full & 0xFFFF;
		break;
	case MIL_FMT_ADDR:
		out->rx = (full >> 16) & 0xF;
		out->addr = full & 0xFFFF;
		break;
	case MIL_FMT_JUMP:
		out->cond = (full >> 20) & 0xF;
		out->rx = (full >> 16) & 0xF;
		out->addr = full & 0xFFFF;
		break;
	}

	return true;
}

static char *format_operands(const MilStd1750Instruction *insn) {
	switch (insn->format) {
	case MIL_FMT_NONE:
		return rz_str_dup("");
	case MIL_FMT_R:
		return rz_str_newf("r%d, r%d", insn->ra, insn->rb);
	case MIL_FMT_SR:
		return rz_str_newf("r%d", insn->ra);
	case MIL_FMT_IMM_R:
		return rz_str_newf("%d, r%d", insn->imm8, insn->rb);
	case MIL_FMT_R_IMM:
		return rz_str_newf("r%d, %d", insn->rb, insn->imm8);
	case MIL_FMT_IS:
		return rz_str_newf("r%d, %d", insn->ra, insn->imm8);
	case MIL_FMT_BX:
		return rz_str_newf("r%d, r%d", insn->br, insn->rx);
	case MIL_FMT_B:
		return rz_str_newf("r%d, %d", insn->br, insn->imm8);
	case MIL_FMT_ICR:
		return rz_str_newf("0x%04x", insn->imm8);
	case MIL_FMT_S:
		switch (insn->special) {
		case 0x77: // BEX
			return rz_str_newf("%d", insn->imm8 & 0xF);
		case 0x4F: // BIF
			return rz_str_newf("0x%02x", insn->imm8);
		default:
			rz_warn_if_reached();
			return rz_str_dup("invalid");
		}
	case MIL_FMT_XIO: {
		char *cmd = format_xio_command(insn->xio_cmd);
		if (!cmd) {
			return NULL;
		}
		char *result = (insn->rx != 0)
			? rz_str_newf("r%d, r%d, %s", insn->ra, insn->rx, cmd)
			: rz_str_newf("r%d, %s", insn->ra, cmd);
		free(cmd);
		return result;
	}
	case MIL_FMT_MEM:
		if (insn->rx) {
			return rz_str_newf("r%d, 0x%04x, r%d", insn->ra, insn->addr, insn->rx);
		}
		return rz_str_newf("r%d, 0x%04x", insn->ra, insn->addr);
	case MIL_FMT_IM_OCX:
		return rz_str_newf("r%d, 0x%04x", insn->ra, insn->imm16);
	case MIL_FMT_IM_0_15:
	case MIL_FMT_IM_1_16:
		return rz_str_newf("%d, 0x%04x, r%d", insn->imm8, insn->addr, insn->rx);
	case MIL_FMT_ADDR:
		return rz_str_newf("0x%04x, r%d", insn->addr, insn->rx);
	case MIL_FMT_JUMP:
		return rz_str_newf("0x%x, 0x%04x, r%d", insn->cond, insn->addr, insn->rx);
	}
	rz_warn_if_reached();
	return NULL;
}

char *rz_milstd1750_stringify(const MilStd1750Instruction *insn) {
	if (!insn || !insn->mnemonic) {
		return NULL;
	}
	char *operands = format_operands(insn);
	if (!operands) {
		return NULL;
	}
	char *result = rz_str_newf("%s(%s)", insn->mnemonic, operands);
	free(operands);
	return result;
}

int rz_milstd1750_op_size(const ut8 *buf, int len) {
	MilStd1750Instruction insn;
	if (!rz_milstd1750_decode(buf, len, &insn)) {
		return -1;
	}
	return insn.size;
}

int rz_milstd1750_disasm(const RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	MilStd1750Instruction insn;
	if (!rz_milstd1750_decode(buf, len, &insn)) {
		rz_strbuf_set(&op->buf_asm, "invalid");
		return -1;
	}
	op->size = insn.size;
	char *result = rz_milstd1750_stringify(&insn);
	if (result) {
		rz_strbuf_set(&op->buf_asm, result);
		free(result);
	}
	return op->size;
}