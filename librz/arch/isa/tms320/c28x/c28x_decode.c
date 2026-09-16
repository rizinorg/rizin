// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "c28x.h"

/**
 * \file c28x_decode.c
 * Table-driven instruction decoder for the TMS320C28x.
 *
 * The C28x opcode is one or two little-endian 16-bit words. Both are packed
 * into a single ut32 (word0 in bits 31:16, word1 in bits 15:0) so that a table
 * row can constrain either of them with one mask/match pair, and so that an
 * operand field is named by a single bit offset regardless of which word holds
 * it. A second word that the instruction does not own reads as zero, which is
 * safe because no row masks bits of a word it does not use.
 */

#define BITS(w, lo, width) (((w) >> (lo)) & ((1u << (width)) - 1))

/// What a table row's operand slot extracts from the packed opcode.
typedef enum {
	C28X_OD_NONE = 0,
	C28X_OD_REG, ///< fixed register named by \ref C28xOpndDef::param
	C28X_OD_AX, ///< AH (0) or AL (1) selected by the field; param selects .LSB/.MSB
	C28X_OD_XAR, ///< XAR0-XAR7 from a 3-bit field
	C28X_OD_AR, ///< AR0-AR7 from a 3-bit field
	C28X_OD_ARP, ///< ARP number from a 3-bit field
	C28X_OD_LOC, ///< loc16 (param 0) or loc32 (param 1) addressing byte
	C28X_OD_IMM, ///< immediate; param 1 sign-extends
	C28X_OD_IMMFIX, ///< fixed immediate held in param
	C28X_OD_SHIFT, ///< shift amount; param 1 means the field encodes n-1
	C28X_OD_SHIFTFIX, ///< fixed shift amount held in param
	C28X_OD_COND, ///< 4-bit condition code
	C28X_OD_PCREL, ///< signed word displacement from the instruction address
	C28X_OD_PMA, ///< absolute program-memory word address
	C28X_OD_PMA_IND, ///< the same, read as data and wrapped
	C28X_OD_PMA_DP, ///< the same, through the page pointer
	C28X_OD_DMA, ///< absolute data-memory word address
	C28X_OD_PORT, ///< I/O space port address
	C28X_OD_MODE, ///< ST0/ST1 mode bit mask
	C28X_OD_PMSHIFT, ///< SPM product shift mode selector
	C28X_OD_BITNUM, ///< bit number for TBIT/TSET/TCLR
	C28X_OD_INTR, ///< interrupt selector for INTR
	C28X_OD_IND, ///< fixed indirect operand, mode in param and register in lo
} C28xOpndKind;

typedef struct {
	ut8 kind; ///< C28xOpndKind
	ut8 lo; ///< low bit of the field inside the packed opcode
	ut8 width; ///< field width in bits
	ut8 param; ///< kind-specific selector (see \ref C28xOpndKind)
} C28xOpndDef;

typedef struct {
	ut32 mask; ///< bits of the packed opcode this row constrains
	ut32 match; ///< required value of those bits
	const char *mnem;
	ut8 len; ///< instruction size in bytes; 0 means the 2-byte default
	_RzAnalysisOpType type;
	ut8 cond; ///< condition baked into the opcode, else 0 (C28X_COND_NEQ)
	bool repeatable; ///< may be prefixed by RPT
	C28xOpndDef ops[C28X_MAX_OPS];
} C28xInsnDef;

#include "c28x_rowdefs.h"
static const C28xInsnDef c28x_table[] = {
#include "c28x_rows.inc"
};
#include "c28x_rowundefs.h"

/// SPM's 3-bit field, in encoding order (SPRU430F "SPM shift").
static const st8 c28x_pm_shift[8] = { 1, 0, -1, -2, -3, -4, -5, -6 };

static C28xReg c28x_xar(ut8 n) {
	return (C28xReg)(C28X_REG_XAR0 + (n & 7));
}

static C28xReg c28x_ar(ut8 n) {
	return (C28xReg)(C28X_REG_AR0 + (n & 7));
}

/**
 * \brief Decode the 8-bit loc16/loc32 addressing field (SPRU430F Table 5-1).
 * \param field the raw 8-bit value
 * \param wide true for loc32, which selects the 32-bit register names
 * \param out receives a C28X_OP_MEM operand
 *
 * Only the AMODE = 0 reading is implemented; see the file comment in c28x.h.
 * The 0x80-0xBF sub-range decoded here is identical under AMODE = 1.
 */
static void c28x_decode_loc(ut8 field, bool wide, RZ_OUT C28xOperand *out) {
	out->kind = C28X_OP_MEM;
	out->wide = wide;
	const ut8 hi2 = field >> 6;
	const ut8 mid = (field >> 3) & 7;
	const ut8 low = field & 7;
	if (hi2 == 0) {
		out->mode = C28X_AM_DP;
		out->off = field & 0x3f;
		return;
	}
	if (hi2 == 1) {
		out->mode = C28X_AM_SP;
		out->off = field & 0x3f;
		return;
	}
	if (hi2 == 3) {
		out->mode = C28X_AM_XAR_IMM;
		out->arn = low;
		out->off = mid;
		return;
	}
	// hi2 == 2: the indirect, register-direct and C2xLP forms
	switch (mid) {
	case 0:
		out->mode = C28X_AM_XAR_POSTINC;
		out->arn = low;
		return;
	case 1:
		out->mode = C28X_AM_XAR_PREDEC;
		out->arn = low;
		return;
	case 2:
		out->mode = C28X_AM_XAR_AR0;
		out->arn = low;
		return;
	case 3:
		out->mode = C28X_AM_XAR_AR1;
		out->arn = low;
		return;
	case 4:
		// @XARn for a 32-bit access, @ARn for a 16-bit one
		out->mode = C28X_AM_REG;
		out->reg = wide ? c28x_xar(low) : c28x_ar(low);
		return;
	case 5:
		out->mode = C28X_AM_REG;
		// A 32-bit access names a register pair, so the low bit that picks the
		// half in the 16-bit map is don't-care here: 0xa8/0xa9 are both ACC.
		switch (wide && low < 4 ? (low & ~1) : low) {
		case 0: out->reg = wide ? C28X_REG_ACC : C28X_REG_AH; return;
		case 1: out->reg = C28X_REG_AL; return;
		case 2: out->reg = wide ? C28X_REG_P : C28X_REG_PH; return;
		case 3: out->reg = C28X_REG_PL; return;
		case 4: out->reg = wide ? C28X_REG_XT : C28X_REG_T; return;
		case 5:
			if (wide) {
				// 0xad has no 32-bit register meaning. Breaking here fell
				// through to the ARP_SET case below and reported a mode this
				// encoding does not have.
				out->mode = C28X_AM_NONE;
				return;
			}
			out->reg = C28X_REG_SP;
			return;
		default:
			// 0xae/0xaf are the bit-reversed C2xLP forms, not registers
			out->mode = (low == 6) ? C28X_AM_ARP_BR_INC : C28X_AM_ARP_BR_DEC;
			return;
		}
	case 6:
		out->mode = C28X_AM_ARP_SET;
		out->arn = low;
		return;
	default: // mid == 7
		switch (low) {
		case 0: out->mode = C28X_AM_ARP; return;
		case 1: out->mode = C28X_AM_ARP_POSTINC; return;
		case 2: out->mode = C28X_AM_ARP_POSTDEC; return;
		case 3: out->mode = C28X_AM_ARP_IDX_INC; return;
		case 4: out->mode = C28X_AM_ARP_IDX_DEC; return;
		case 5: out->mode = C28X_AM_SP_POSTINC; return;
		case 6: out->mode = C28X_AM_SP_PREDEC; return;
		default: out->mode = C28X_AM_CIRC; return;
		}
	}
}

/// Sign-extend the low \p width bits of \p v.
static st64 c28x_sext(ut32 v, ut8 width) {
	const ut32 sign = 1u << (width - 1);
	return (st64)(v ^ sign) - (st64)sign;
}

static void c28x_decode_operand(const C28xOpndDef *def, ut32 packed, ut64 pc, RZ_OUT C28xOperand *out) {
	const ut32 f = def->width ? BITS(packed, def->lo, def->width) : 0;
	switch (def->kind) {
	case C28X_OD_REG:
		out->kind = C28X_OP_REG;
		out->reg = (C28xReg)def->param;
		break;
	case C28X_OD_AX:
		// SPRU430F writes this field as "A" without stating the polarity;
		// compiled code settles it: in decrypt() the int return value and the
		// PARITY_REF compare both use A = 0, and the C28x ABI returns 16-bit
		// values in AL.
		out->kind = C28X_OP_REG;
		out->reg = f ? C28X_REG_AH : C28X_REG_AL;
		out->byte_sel = def->param;
		break;
	case C28X_OD_XAR:
		out->kind = C28X_OP_REG;
		out->reg = c28x_xar(f);
		break;
	case C28X_OD_AR:
		out->kind = C28X_OP_REG;
		out->reg = c28x_ar(f);
		break;
	case C28X_OD_ARP:
		out->kind = C28X_OP_REG;
		out->reg = C28X_REG_ARP;
		out->imm = f;
		break;
	case C28X_OD_LOC:
		c28x_decode_loc(f, def->param != 0, out);
		break;
	case C28X_OD_IMM:
		out->kind = C28X_OP_IMM;
		out->is_signed = def->param != 0;
		out->imm = out->is_signed ? c28x_sext(f, def->width) : (st64)f;
		break;
	case C28X_OD_IMMFIX:
		out->kind = C28X_OP_IMM;
		out->imm = def->param;
		break;
	case C28X_OD_SHIFT:
		out->kind = C28X_OP_SHIFT;
		out->imm = def->param ? (st64)f + 1 : (st64)f;
		break;
	case C28X_OD_SHIFTFIX:
		out->kind = C28X_OP_SHIFT;
		out->imm = def->param;
		break;
	case C28X_OD_COND:
		out->kind = C28X_OP_COND;
		out->imm = f;
		break;
	case C28X_OD_PCREL:
		// The branch base is the address of the branch itself, and the
		// displacement counts 16-bit words (SPRU430F "B 16bitOffset,COND").
		out->kind = C28X_OP_PCREL;
		out->imm = (st64)pc + c28x_sext(f, def->width) * C28X_WORD_BYTES;
		break;
	case C28X_OD_PMA:
		out->kind = C28X_OP_PMA;
		out->imm = (st64)f * C28X_WORD_BYTES;
		break;
	case C28X_OD_PMA_IND:
		out->kind = C28X_OP_PMA_IND;
		out->imm = (st64)f * C28X_WORD_BYTES;
		break;
	case C28X_OD_PMA_DP:
		out->kind = C28X_OP_PMA_DP;
		out->imm = (st64)f * C28X_WORD_BYTES;
		break;
	case C28X_OD_DMA:
		out->kind = C28X_OP_DMA;
		out->imm = (st64)f * C28X_WORD_BYTES;
		break;
	case C28X_OD_PORT:
		out->kind = C28X_OP_PORT;
		out->imm = f;
		break;
	case C28X_OD_MODE:
		out->kind = C28X_OP_MODE;
		out->imm = f;
		break;
	case C28X_OD_PMSHIFT:
		out->kind = C28X_OP_IMM;
		out->is_signed = true;
		out->imm = c28x_pm_shift[f & 7];
		break;
	case C28X_OD_BITNUM:
		out->kind = C28X_OP_IMM;
		out->imm = f;
		break;
	case C28X_OD_INTR:
		out->kind = C28X_OP_INTR;
		out->imm = f;
		break;
	case C28X_OD_IND:
		out->kind = C28X_OP_MEM;
		out->mode = (C28xAddrMode)def->param;
		// width 1 marks \p lo as a literal register number rather than a field
		out->arn = def->width ? (ut8)def->lo
				      : (def->lo ? (ut8)BITS(packed, def->lo, 3) : 0);
		break;
	default:
		out->kind = C28X_OP_NONE;
		break;
	}
}

/**
 * \brief Find the table row that best matches \p packed.
 *
 * Several rows can match one opcode: the manual encodes a handful of
 * instructions as a fully-specified case of a wider one (POP ACC is
 * MOVL ACC,*--SP, PUSH XAR4 is MOVL *SP++,XAR4, and so on). The row with the
 * most constrained mask is the intended one, so the search keeps the best
 * candidate rather than stopping at the first hit; that also makes the table
 * order irrelevant to correctness.
 */
static const C28xInsnDef *c28x_match(ut32 packed) {
	const C28xInsnDef *best = NULL;
	int best_bits = -1;
	for (size_t i = 0; i < RZ_ARRAY_SIZE(c28x_table); i++) {
		const C28xInsnDef *def = &c28x_table[i];
		if ((packed & def->mask) != def->match) {
			continue;
		}
		const int bits = (int)rz_bits_count_ones_ut32(def->mask);
		if (bits > best_bits) {
			best_bits = bits;
			best = def;
		}
	}
	return best;
}

/**
 * \brief Decode one C28x instruction.
 * \param buf instruction bytes
 * \param len bytes available at \p buf
 * \param pc byte address of the instruction, used for PC-relative operands
 * \param insn receives the decoded instruction
 * \return true when \p buf holds a complete, known instruction
 */
RZ_IPI bool c28x_decode(const ut8 *buf, int len, ut64 pc, RZ_OUT C28xInsn *insn) {
	rz_return_val_if_fail(buf && insn, false);
	if (len < 2) {
		return false;
	}
	memset(insn, 0, sizeof(*insn));
	insn->cond = C28X_COND_UNC;
	const ut16 w0 = rz_read_at_le16(buf, 0);
	const ut16 w1 = len >= 4 ? rz_read_at_le16(buf, 2) : 0;
	const ut32 packed = ((ut32)w0 << 16) | w1;

	const C28xInsnDef *def = c28x_match(packed);
	if (!def) {
		return false;
	}
	const ut32 size = def->len ? def->len : 2;
	if ((int)size > len) {
		return false;
	}
	insn->word = size > 2 ? packed : ((ut32)w0 << 16);
	insn->size = size;
	insn->mnemonic = def->mnem;
	insn->op_type = def->type;
	insn->repeatable = def->repeatable;
	if (def->cond) {
		insn->cond = def->cond;
	}
	for (ut8 i = 0; i < C28X_MAX_OPS; i++) {
		if (def->ops[i].kind == C28X_OD_NONE) {
			break;
		}
		c28x_decode_operand(&def->ops[i], packed, pc, &insn->ops[i]);
		if (insn->ops[i].kind == C28X_OP_COND) {
			insn->cond = (ut8)insn->ops[i].imm;
		}
		insn->nops = i + 1;
	}
	return true;
}

RZ_IPI RZ_OWN RzPVector /*<const char *>*/ *c28x_mnemonics(void) {
	RzPVector *vec = rz_pvector_new(NULL);
	if (!vec) {
		return NULL;
	}
	for (size_t i = 0; i < RZ_ARRAY_SIZE(c28x_table); i++) {
		const char *m = c28x_table[i].mnem;
		bool seen = false;
		void **it;
		rz_pvector_foreach (vec, it) {
			if (!strcmp((const char *)*it, m)) {
				seen = true;
				break;
			}
		}
		if (!seen) {
			rz_pvector_push(vec, (void *)m);
		}
	}
	return vec;
}
