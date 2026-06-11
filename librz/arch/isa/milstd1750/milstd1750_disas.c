// SPDX-FileCopyrightText: 2026 godcodehunter
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file Disassembler for the MIL-STD-1750A instruction set architecture.
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
	{ 0x2000, "SMK" },
	{ 0x2001, "CLIR" },
	{ 0x2002, "ENBL" },
	{ 0x2003, "DSBL" },
	{ 0x2004, "RPI" },
	{ 0x2005, "SPI" },
	{ 0x200E, "WSW" },
	{ 0xA000, "RMK" },
	{ 0xA004, "RPIR" },
	{ 0xA00E, "RSW" },
	{ 0xA00F, "RCFR" },
	{ 0x2008, "OD" },
	{ 0x200A, "RNS" },
	{ 0x4000, "CO" },
	{ 0x4001, "CLC" },
	{ 0x4003, "MPEN" },
	{ 0x4004, "ESUR" },
	{ 0x4005, "DSUR" },
	{ 0x4006, "DMAE" },
	{ 0x4007, "DMAD" },
	{ 0x4008, "TAS" },
	{ 0x4009, "TAH" },
	{ 0x400A, "OTA" },
	{ 0x400B, "GO" },
	{ 0x400C, "TBS" },
	{ 0x400D, "TBH" },
	{ 0x400E, "OTB" },
	{ 0xA001, "RIC1" },
	{ 0xA002, "RIC2" },
	{ 0xA008, "RDOR" },
	{ 0xA009, "RDI" },
	{ 0xA00B, "TPIO" },
	{ 0xA00D, "RMFS" },
	{ 0xC000, "CI" },
	{ 0xC001, "RCS" },
	{ 0xC00A, "ITA" },
	{ 0xC00E, "ITB" },
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
	{ 0x4040, "ABX",  MIL_FMT_BX,      },
	{ 0x40E0, "ANDX", MIL_FMT_BX,      },
	{ 0xA000, "A",    MIL_FMT_MEM,     },
	{ 0xA400, "ABS",  MIL_FMT_R,       },
	{ 0x4A01, "AIM",  MIL_FMT_IM_OCX,  },
	{ 0xA200, "AISP", MIL_FMT_IS,      },
	{ 0xE200, "AND",  MIL_FMT_MEM,     },
	{ 0x3400, "ANDB", MIL_FMT_B,       },
	{ 0x4A07, "ANDM", MIL_FMT_IM_OCX,  },
	{ 0xE300, "ANDR", MIL_FMT_R,       },
	{ 0xA100, "AR",   MIL_FMT_R,       },
	{ 0x1000, "AB",   MIL_FMT_B,       },
	{ 0x7700, "BEX",  MIL_FMT_S,       },
	{ 0x7500, "BEZ",  MIL_FMT_ICR,     },
	{ 0x7B00, "BGE",  MIL_FMT_ICR,     },
	{ 0x7900, "BGT",  MIL_FMT_ICR,     },
	{ 0x4F00, "BIF",  MIL_FMT_S,       },
	{ 0x7800, "BLE",  MIL_FMT_ICR,     },
	{ 0x7600, "BLT",  MIL_FMT_ICR,     },
	{ 0x7A00, "BNZ",  MIL_FMT_ICR,     },
	{ 0xFFFF, "BPT",  MIL_FMT_NONE,    },
	{ 0x7400, "BR",   MIL_FMT_ICR,     },
	{ 0xF000, "C",    MIL_FMT_MEM,     },
	{ 0x3800, "CB",   MIL_FMT_B,       },
	{ 0xF400, "CBL",  MIL_FMT_MEM,     },
	{ 0x40C0, "CBX",  MIL_FMT_BX,      },
	{ 0xF100, "CR",   MIL_FMT_R,       },
	{ 0xF200, "CISP", MIL_FMT_IS,      },
	{ 0xF300, "CISN", MIL_FMT_IS,      },
	{ 0x4A0A, "CIM",  MIL_FMT_IM_OCX,  },
	{ 0xD700, "DDR",  MIL_FMT_R,       },
	{ 0xD600, "DD",   MIL_FMT_MEM,     },
	{ 0xD400, "D",    MIL_FMT_MEM,     },
	{ 0xA600, "DA",   MIL_FMT_MEM,     },
	{ 0xA500, "DABS", MIL_FMT_R,       },
	{ 0xA700, "DAR",  MIL_FMT_R,       },
	{ 0x1C00, "DB",   MIL_FMT_B,       },
	{ 0xF600, "DC",   MIL_FMT_MEM,     },
	{ 0xF700, "DCR",  MIL_FMT_R,       },
	{ 0xB300, "DECM", MIL_FMT_IM_1_16, },
	{ 0x4A05, "DIM",  MIL_FMT_IM_OCX,  },
	{ 0xD300, "DISN", MIL_FMT_IS,      },
	{ 0xD200, "DISP", MIL_FMT_IS,      },
	{ 0x8600, "DL",   MIL_FMT_MEM,     },
	{ 0x0400, "DLB",  MIL_FMT_B,       },
	{ 0x4010, "DLBX", MIL_FMT_BX,      },
	{ 0xDF00, "DLE",  MIL_FMT_MEM,     },
	{ 0x8800, "DLI",  MIL_FMT_MEM,     },
	{ 0x8700, "DLR",  MIL_FMT_R,       },
	{ 0xC600, "DM",   MIL_FMT_MEM,     },
	{ 0xC700, "DMR",  MIL_FMT_R,       },
	{ 0xB500, "DNEG", MIL_FMT_R,       },
	{ 0xD500, "DR",   MIL_FMT_R,       },
	{ 0xB600, "DS",   MIL_FMT_MEM,     },
	{ 0x6E00, "DSAR", MIL_FMT_R,       },
	{ 0x6F00, "DSCR", MIL_FMT_R,       },
	{ 0x6500, "DSLL", MIL_FMT_R_IMM,   },
	{ 0x6800, "DSLC", MIL_FMT_R_IMM,   },
	{ 0x6D00, "DSLR", MIL_FMT_R,       },
	{ 0x6700, "DSRA", MIL_FMT_R_IMM,   },
	{ 0x6600, "DSRL", MIL_FMT_R_IMM,   },
	{ 0xB700, "DSR",  MIL_FMT_R,       },
	{ 0x9600, "DST",  MIL_FMT_MEM,     },
	{ 0x0C00, "DSTB", MIL_FMT_B,       },
	{ 0x9800, "DSTI", MIL_FMT_MEM,     },
	{ 0xDD00, "DSTE", MIL_FMT_MEM,     },
	{ 0x4030, "DSTX", MIL_FMT_BX,      },
	{ 0xD000, "DV",   MIL_FMT_MEM,     },
	{ 0x4A06, "DVIM", MIL_FMT_IM_OCX,  },
	{ 0xD100, "DVR",  MIL_FMT_R,       },
	{ 0x4070, "DBX",  MIL_FMT_BX,      },
	{ 0xEB00, "EFLT", MIL_FMT_R,       },
	{ 0xEA00, "EFIX", MIL_FMT_R,       },
	{ 0xFA00, "EFC",  MIL_FMT_MEM,     },
	{ 0xFB00, "EFCR", MIL_FMT_R,       },
	{ 0xAA00, "EFA",  MIL_FMT_MEM,     },
	{ 0xAB00, "EFAR", MIL_FMT_R,       },
	{ 0xDA00, "EFD",  MIL_FMT_MEM,     },
	{ 0xDB00, "EFDR", MIL_FMT_R,       },
	{ 0x8A00, "EFL",  MIL_FMT_MEM,     },
	{ 0xCA00, "EFM",  MIL_FMT_MEM,     },
	{ 0xCB00, "EFMR", MIL_FMT_R,       },
	{ 0xBA00, "EFS",  MIL_FMT_MEM,     },
	{ 0xBB00, "EFSR", MIL_FMT_R,       },
	{ 0x9A00, "EFST", MIL_FMT_MEM,     },
	{ 0xAC00, "FABS", MIL_FMT_R,       },
	{ 0xA800, "FA",   MIL_FMT_MEM,     },
	{ 0x2000, "FAB",  MIL_FMT_B,       },
	{ 0x4080, "FABX", MIL_FMT_BX,      },
	{ 0xA900, "FAR",  MIL_FMT_R,       },
	{ 0xF800, "FC",   MIL_FMT_MEM,     },
	{ 0x3C00, "FCB",  MIL_FMT_B,       },
	{ 0x40D0, "FCBX", MIL_FMT_BX,      },
	{ 0xF900, "FCR",  MIL_FMT_R,       },
	{ 0xD800, "FD",   MIL_FMT_MEM,     },
	{ 0x2C00, "FDB",  MIL_FMT_B,       },
	{ 0x40B0, "FDBX", MIL_FMT_BX,      },
	{ 0xD900, "FDR",  MIL_FMT_R,       },
	{ 0xE800, "FIX",  MIL_FMT_R,       },
	{ 0xE900, "FLT",  MIL_FMT_R,       },
	{ 0xC800, "FM",   MIL_FMT_MEM,     },
	{ 0x2800, "FMB",  MIL_FMT_B,       },
	{ 0x40A0, "FMBX", MIL_FMT_BX,      },
	{ 0xC900, "FMR",  MIL_FMT_R,       },
	{ 0xBC00, "FNEG", MIL_FMT_R,       },
	{ 0xB800, "FS",   MIL_FMT_MEM,     },
	{ 0x2400, "FSB",  MIL_FMT_B,       },
	{ 0x4090, "FSBX", MIL_FMT_BX,      },
	{ 0xB900, "FSR",  MIL_FMT_R,       },
	{ 0xA300, "INCM", MIL_FMT_IM_1_16, },
	{ 0x7000, "JC",   MIL_FMT_JUMP,    },
	{ 0x7100, "JCI",  MIL_FMT_JUMP,    },
	{ 0x7200, "JS",   MIL_FMT_MEM,     },
	{ 0x8300, "LISN", MIL_FMT_IS,      },
	{ 0x8000, "L",    MIL_FMT_MEM,     },
	{ 0x0000, "LB",   MIL_FMT_B,       },
	{ 0x4000, "LBX",  MIL_FMT_BX,      },
	{ 0xDE00, "LE",   MIL_FMT_MEM,     },
	{ 0x8400, "LI",   MIL_FMT_MEM,     },
	{ 0x8500, "LIM",  MIL_FMT_MEM,     },
	{ 0x8200, "LISP", MIL_FMT_IS,      },
	{ 0x8C00, "LLB",  MIL_FMT_MEM,     },
	{ 0x8E00, "LLBI", MIL_FMT_MEM,     },
	{ 0x8900, "LM",   MIL_FMT_IM_0_15, },
	{ 0x8100, "LR",   MIL_FMT_R,       },
	{ 0x7C00, "LSTI", MIL_FMT_ADDR,    },
	{ 0x7D00, "LST",  MIL_FMT_ADDR,    },
	{ 0x8B00, "LUB",  MIL_FMT_MEM,     },
	{ 0x8D00, "LUBI", MIL_FMT_MEM,     },
	{ 0xC500, "MR",   MIL_FMT_R,       },
	{ 0xC400, "M",    MIL_FMT_MEM,     },
	{ 0x1800, "MB",   MIL_FMT_B,       },
	{ 0x4060, "MBX",  MIL_FMT_BX,      },
	{ 0xC300, "MISN", MIL_FMT_IS,      },
	{ 0xC200, "MISP", MIL_FMT_IS,      },
	{ 0x4A03, "MIM",  MIL_FMT_IM_OCX,  },
	{ 0x9300, "MOV",  MIL_FMT_R,       },
	{ 0xC000, "MS",   MIL_FMT_MEM,     },
	{ 0x4A04, "MSIM", MIL_FMT_IM_OCX,  },
	{ 0xC100, "MSR",  MIL_FMT_R,       },
	{ 0xE600, "N",    MIL_FMT_MEM,     },
	{ 0xB400, "NEG",  MIL_FMT_R,       },
	{ 0x4A0B, "NIM",  MIL_FMT_IM_OCX,  },
	{ 0xFF00, "NOP",  MIL_FMT_NONE,    },
	{ 0xE700, "NR",   MIL_FMT_R,       },
	{ 0xE000, "OR",   MIL_FMT_MEM,     },
	{ 0x3000, "ORB",  MIL_FMT_B,       },
	{ 0x40F0, "ORBX", MIL_FMT_BX,      },
	{ 0x4A08, "ORIM", MIL_FMT_IM_OCX,  },
	{ 0xE100, "ORR",  MIL_FMT_R,       },
	{ 0x8F00, "POPM", MIL_FMT_R,       },
	{ 0x9F00, "PSHM", MIL_FMT_R,       },
	{ 0x5300, "RB",   MIL_FMT_IM_0_15, },
	{ 0x5500, "RBI",  MIL_FMT_IM_0_15, },
	{ 0x5400, "RBR",  MIL_FMT_IMM_R,   },
	{ 0x5C00, "RVBR", MIL_FMT_R,       },
	{ 0x9E00, "SLBI", MIL_FMT_MEM,     },
	{ 0x4050, "SBBX", MIL_FMT_BX,      },
	{ 0x4020, "STBX", MIL_FMT_BX,      },
	{ 0x6C00, "SCR",  MIL_FMT_R,       },
	{ 0x6B00, "SAR",  MIL_FMT_R,       },
	{ 0xB000, "S",    MIL_FMT_MEM,     },
	{ 0x5000, "SB",   MIL_FMT_IM_0_15, },
	{ 0x1400, "SBB",  MIL_FMT_B,       },
	{ 0x5100, "SBR",  MIL_FMT_IMM_R,   },
	{ 0x5200, "SBI",  MIL_FMT_IM_0_15, },
	{ 0x9500, "SFBS", MIL_FMT_R,       },
	{ 0x4A02, "SIM",  MIL_FMT_IM_OCX,  },
	{ 0xB200, "SISP", MIL_FMT_IS,      },
	{ 0x7E00, "SJS",  MIL_FMT_MEM,     },
	{ 0x6300, "SLC",  MIL_FMT_R_IMM,   },
	{ 0x6000, "SLL",  MIL_FMT_R_IMM,   },
	{ 0x6A00, "SLR",  MIL_FMT_R,       },
	{ 0x7300, "SOJ",  MIL_FMT_MEM,     },
	{ 0xB100, "SR",   MIL_FMT_R,       },
	{ 0x6200, "SRA",  MIL_FMT_R_IMM,   },
	{ 0x9700, "SRM",  MIL_FMT_MEM,     },
	{ 0x6100, "SRL",  MIL_FMT_R_IMM,   },
	{ 0x9000, "ST",   MIL_FMT_MEM,     },
	{ 0x9100, "STC",  MIL_FMT_IM_0_15, },
	{ 0x9200, "STCI", MIL_FMT_IM_0_15, },
	{ 0x9400, "STI",  MIL_FMT_MEM,     },
	{ 0x0800, "STB",  MIL_FMT_B,       },
	{ 0x9C00, "STLB", MIL_FMT_MEM,     },
	{ 0x9900, "STM",  MIL_FMT_IM_0_15, },
	{ 0x9B00, "STUB", MIL_FMT_MEM,     },
	{ 0x9D00, "SUBI", MIL_FMT_MEM,     },
	{ 0x5A00, "SVBR", MIL_FMT_R,       },
	{ 0x5600, "TB",   MIL_FMT_IM_0_15, },
	{ 0xDC00, "STE",  MIL_FMT_MEM,     },
	{ 0x5700, "TBR",  MIL_FMT_IMM_R,   },
	{ 0x5E00, "TVBR", MIL_FMT_R,       },
	{ 0x5800, "TBI",  MIL_FMT_IM_0_15, },
	{ 0x5900, "TSB",  MIL_FMT_IM_0_15, },
	{ 0xAE00, "UA",   MIL_FMT_MEM,     },
	{ 0xAD00, "UAR",  MIL_FMT_R,       },
	{ 0xFD00, "UC",   MIL_FMT_MEM,     },
	{ 0xF500, "UCIM", MIL_FMT_IM_OCX,  },
	{ 0xFC00, "UCR",  MIL_FMT_R,       },
	{ 0x7F00, "URS",  MIL_FMT_SR,      },
	{ 0xBE00, "US",   MIL_FMT_MEM,     },
	{ 0xBD00, "USR",  MIL_FMT_R,       },
	{ 0x4900, "VIO",  MIL_FMT_MEM,     },
	{ 0xEC00, "XBR",  MIL_FMT_R,       },
	{ 0x4800, "XIO",  MIL_FMT_XIO,     },
	{ 0xE400, "XOR",  MIL_FMT_MEM,     },
	{ 0x4A09, "XORM", MIL_FMT_IM_OCX,  },
	{ 0xE500, "XORR", MIL_FMT_R,       },
	{ 0xED00, "XWR",  MIL_FMT_R,       },
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
	out->raw_w1 = w1;
	out->raw_w2 = w2;

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