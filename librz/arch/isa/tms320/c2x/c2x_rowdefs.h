// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * Shared decode-table row macros for the TMS320C2x/C5x tables. Included
 * immediately before a `static const C55InsnDef <cpu>_table[] = {` body and
 * paired with c2x_rowundefs.h afterwards. Requires the c2x_x_* operand
 * extractors (declared in c2x.h) to be visible.
 */

// head-space mask/match: the 16-bit opcode word occupies head bits 31:16.
#define OP(wmask, wmatch) .mask = ((ut32)(wmask) << 16), .match = ((ut32)(wmatch) << 16)
#define MEM(lo_)          { .lo = (lo_), .width = 8, .fn = c2x_x_mem }
#define NARP(lo_)         { .lo = (lo_), .width = 4, .fn = c2x_x_nextarp }
#define SHF(lo_, w_)      { .lo = (lo_), .width = (w_), .fn = c2x_x_shift }
#define AR(lo_)           { .lo = (lo_), .width = 3, .fn = c2x_x_reg }
#define IMM(lo_, w_, p_)  { .lo = (lo_), .width = (w_), .fn = c2x_x_imm, .param = (p_) }
#define BR(lo_)           { .lo = (lo_), .width = 16, .fn = c2x_x_branch }

// memory-reference opcode keyed on the whole high byte + the direct/indirect bit
#define MEMOP_D(hb, id_) \
	{ \
		OP(0xff80, ((ut16)(hb) << 8) | 0x0000), .id = (id_), .len = 2, .ops = { MEM(0) } \
	}
#define MEMOP_I(hb, id_) \
	{ \
		OP(0xff80, ((ut16)(hb) << 8) | 0x0080), .id = (id_), .len = 2, .ops = { MEM(0), \
			NARP(0) } \
	}
#define FIX(word, id_) OP(0xffff, (word)), .id = (id_), .len = 2
#define BROP(hb, id_) \
	{ \
		OP(0xff80, ((ut16)(hb) << 8) | 0x0080), .id = (id_), .len = 4, .ops = { BR(0) } \
	}
// BANZ also carries the indirect addressing byte (in the leading word, bits
// 31:16) that selects the loop-counter AR post-modify (*- etc.); decode it so
// the lifter can apply the auxiliary-register update.
#define BANZOP(hb, id_) \
	{ \
		OP(0xff80, ((ut16)(hb) << 8) | 0x0080), .id = (id_), .len = 4, .ops = { BR(0), \
			MEM(16), \
			NARP(16) } \
	}

// 2-word instruction carrying a 16-bit memory address in the trailing word plus
// a destination addressing byte in the leading word (mac/macd/blkp/blkd). The
// leading word sits in packed bits 31:16, so MEM/NARP index from bit 16.
#define PMAOP_D(hb, id_) \
	{ \
		OP(0xff80, ((ut16)(hb) << 8) | 0x0000), .id = (id_), .len = 4, .ops = { IMM(0, 16, 0), \
			MEM(16) } \
	}
#define PMAOP_I(hb, id_) \
	{ \
		OP(0xff80, ((ut16)(hb) << 8) | 0x0080), .id = (id_), .len = 4, .ops = { IMM(0, 16, 0), \
			MEM(16), \
			NARP(16) } \
	}
