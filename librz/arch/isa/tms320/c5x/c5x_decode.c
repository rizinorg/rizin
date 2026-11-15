// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * TMS320C5x decode front-end (the real C5x object encoding).
 *
 * The C5x is source-compatible with the C2x but encodes instructions
 * differently, so it cannot reuse the C2x decode table. c5x_decode() ports the
 * authoritative TMS320C5x opcode table directly and fills the shared C55Insn:
 * shared-semantics instructions carry the C2X_INS_* ids (so the C2x lifter,
 * op-type and mnemonic tables apply unchanged) and C5x-only instructions carry
 * the C5X_INS_* ids handled by c5x.c.
 *
 * Memory operands use one addressing byte (the low 8 bits of the opcode word):
 * bit 7 selects direct (0) or indirect (1). For indirect, bits 6:3 are a 4-bit
 * sub-mode (the LSB of which requests a next-ARP load from bits 2:0): 0=*, 2=*-,
 * 4=*+, 8=*BR0-, A=*0-, C=*0+, E=*BR0+. Operand order matches the C2x
 * convention so the shared consumers render and lift them identically.
 */

#include "c5x.h"
#include <rz_util.h>

static const char *const c5x_indir_raw[16] = {
	"*", "*", "*-", "*-", "*+", "*+", "*?", "*?",
	"*br0-", "*br0-", "*0-", "*0-", "*0+", "*0+", "*br0+", "*br0+"
};
static const C55AddrMode c5x_indir_amode[16] = {
	C55_AM_INDIRECT, C55_AM_INDIRECT, C55_AM_POSTDEC, C55_AM_POSTDEC,
	C55_AM_POSTINC, C55_AM_POSTINC, C55_AM_INDIRECT, C55_AM_INDIRECT,
	C55_AM_BITREV_SUB, C55_AM_BITREV_SUB, C55_AM_POSTSUB, C55_AM_POSTSUB,
	C55_AM_POSTADD, C55_AM_POSTADD, C55_AM_BITREV, C55_AM_BITREV
};
static const char *const c5x_arx_raw[8] = {
	"ar0", "ar1", "ar2", "ar3", "ar4", "ar5", "ar6", "ar7"
};

// A data-memory operand from one addressing byte: direct (DP-relative, in disp)
// or indirect (ARP-relative, rendered via raw).
static void mem_op(C55Operand *out, ut8 low) {
	out->kind = C55_OP_MEM;
	out->access = 16;
	if (low & 0x80) {
		ut8 sub = (low >> 3) & 0xf;
		out->amode = c5x_indir_amode[sub];
		out->reg.cls = C55_RC_AR;
		out->raw = c5x_indir_raw[sub];
	} else {
		out->amode = C55_AM_DIRECT;
		out->disp = (st32)(low & 0x7f);
	}
}

// The next-ARP operand (rendered ",arN") when an indirect sub-mode is odd.
static bool narp_op(C55Operand *out, ut8 low) {
	if ((low & 0x80) && ((low >> 3) & 1)) {
		out->kind = C55_OP_REG;
		out->reg.cls = C55_RC_AR;
		out->reg.num = low & 7;
		out->width = 16;
		out->raw = c5x_arx_raw[low & 7];
		return true;
	}
	return false;
}

static void imm_op(C55Operand *out, ut64 v, ut8 width, bool is_signed) {
	out->kind = C55_OP_IMM;
	out->imm = v;
	out->width = width;
	out->imm_signed = is_signed;
}

static void shift_op(C55Operand *out, ut8 sh) {
	out->kind = C55_OP_IMM;
	out->imm = sh;
	out->width = 16;
}

static void ar_op(C55Operand *out, ut8 n) {
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_AR;
	out->reg.num = n & 7;
	out->width = 16;
	out->raw = c5x_arx_raw[n & 7];
}

// 16-bit absolute branch/call target carried in the trailing word.
static void target_op(C55Operand *out, ut16 t) {
	out->kind = C55_OP_IMM;
	out->imm = t;
	out->width = 16;
	out->addr = true;
	out->abs_target = true;
}

// Condition fragments for the 0xE0-0xFF group, rendered verbatim. zl/cv/tp are
// packed across the opcode's high and low nibbles (see the C5x opcode table).
static const char *const c5x_zl[16] = {
	"", "gt", "neq", "gt", "", "lt", "neq", "lt", "", "gt", "eq", "geq", "", "lt", "eq", "leq"
};
static const char *const c5x_cv[16] = {
	"", "nc", "nov", "nc nov", "", "c", "nov", "c nov", "", "nc", "ov", "nc ov", "", "c", "ov", "c ov"
};
static const char *const c5x_tp[4] = { "bio", "tc", "ntc", "" };

// Control bits addressed by SETC/CLRC (sub 0x40-0x4f), selected by (sub >> 1).
static const char *const c5x_ctrl_bits[8] = {
	"intm", "ovm", "cnf", "sxm", "hold", "tc", "xf", "carry"
};

// 16-bit long-immediate ALU forms in the 0xB<sub> group, indexed by the low
// nibble; the zero entries are not long-immediate ops.
static const ut16 c5x_long_imm_alu[16] = {
	[0x8] = C2X_INS_LALK, [0x9] = C2X_INS_ADLK, [0xa] = C2X_INS_SBLK, [0xb] = C2X_INS_ANDK, [0xc] = C2X_INS_ORK, [0xd] = C2X_INS_XORK
};

// Append the active zl/cv/tp condition fragments as verbatim operands.
static void cond_ops(C55Insn *out, ut16 op) {
	ut8 zlcvmask = op & 0xf;
	ut8 zlcv = (op >> 4) & 0xf;
	ut8 zl = (zlcv & 0xc) | ((zlcvmask >> 2) & 3);
	ut8 cv = ((zlcv << 2) & 0xc) | (zlcvmask & 3);
	ut8 tp = (op >> 8) & 3;
	const char *frag[3] = { c5x_zl[zl], c5x_cv[cv], c5x_tp[tp] };
	for (int i = 0; i < 3; i++) {
		if (frag[i][0]) {
			out->ops[out->n_ops].kind = C55_OP_NONE;
			out->ops[out->n_ops].raw = frag[i];
			out->n_ops++;
		}
	}
}

#define ID(_id) (out->id = (ut16)(_id))

/**
 * \brief Fill a "mem [narp]" instruction form.
 * \param out Instruction to fill in
 * \param id Instruction id to set
 * \param low Addressing byte (low 8 bits of the opcode word)
 * \return Instruction length in bytes
 */
static int mem_plain_insn(C55Insn *out, ut16 id, ut8 low) {
	out->id = id;
	mem_op(&out->ops[0], low);
	out->n_ops = 1;
	if (narp_op(&out->ops[1], low)) {
		out->n_ops++;
	}
	out->size = 2;
	return 2;
}

/**
 * \brief Fill a "mem shift [narp]" instruction form.
 * \param out Instruction to fill in
 * \param id Instruction id to set
 * \param low Addressing byte (low 8 bits of the opcode word)
 * \param shift Shift amount encoded in the opcode
 * \return Instruction length in bytes
 */
static int mem_shift_insn(C55Insn *out, ut16 id, ut8 low, ut8 shift) {
	out->id = id;
	mem_op(&out->ops[0], low);
	shift_op(&out->ops[1], shift);
	out->n_ops = 2;
	if (narp_op(&out->ops[2], low)) {
		out->n_ops++;
	}
	out->size = 2;
	return 2;
}

/**
 * \brief Fill a "mem [narp] #imm16" instruction form.
 * \param out Instruction to fill in
 * \param id Instruction id to set
 * \param low Addressing byte (low 8 bits of the opcode word)
 * \param w2 Trailing word carrying the long immediate
 * \return Instruction length in bytes
 *
 * The next-ARP operand keeps its source order ahead of the immediate, so the
 * immediate lands at whichever slot the optional \p narp_op left free.
 */
static int mem_imm2_insn(C55Insn *out, ut16 id, ut8 low, ut16 w2) {
	out->id = id;
	mem_op(&out->ops[0], low);
	out->n_ops = 1;
	if (narp_op(&out->ops[1], low)) {
		out->n_ops++;
	}
	imm_op(&out->ops[out->n_ops], w2, 16, false);
	out->n_ops++;
	out->size = 4;
	return 4;
}

/**
 * \brief Fill a single-immediate-operand instruction form.
 * \param out Instruction to fill in
 * \param id Instruction id to set
 * \param v Immediate value, already masked to its encoded width
 * \param width Immediate width in bits
 * \return Instruction length in bytes
 */
static int imm_insn(C55Insn *out, ut16 id, ut64 v, ut8 width) {
	out->id = id;
	imm_op(&out->ops[0], v, width, false);
	out->n_ops = 1;
	out->size = 2;
	return 2;
}

// The BE group (0xBExx): ACCB ops, control bits, 2-word immediates.
static int decode_be(C55Insn *out, ut16 op, ut16 w2) {
	ut8 sub = op & 0xff;
	switch (sub) {
	case 0x00: ID(C2X_INS_ABS); return 2;
	case 0x01: ID(C2X_INS_CMPL); return 2;
	case 0x02: ID(C2X_INS_NEG); return 2;
	case 0x03: ID(C2X_INS_PAC); return 2;
	case 0x04: ID(C2X_INS_APAC); return 2;
	case 0x05: ID(C2X_INS_SPAC); return 2;
	case 0x09: ID(C2X_INS_SFL); return 2;
	case 0x0a: ID(C2X_INS_SFR); return 2;
	case 0x0c: ID(C2X_INS_ROL); return 2;
	case 0x0d: ID(C2X_INS_ROR); return 2;
	case 0x10: ID(C5X_INS_ADDB); return 2;
	case 0x11: ID(C5X_INS_ADCB); return 2;
	case 0x12: ID(C5X_INS_ANDB); return 2;
	case 0x13: ID(C5X_INS_ORB); return 2;
	case 0x14: ID(C5X_INS_ROLB); return 2;
	case 0x15: ID(C5X_INS_RORB); return 2;
	case 0x16: ID(C5X_INS_SFLB); return 2;
	case 0x17: ID(C5X_INS_SFRB); return 2;
	case 0x18: ID(C5X_INS_SBB); return 2;
	case 0x19: ID(C5X_INS_SBBB); return 2;
	case 0x1a: ID(C5X_INS_XORB); return 2;
	case 0x1b: ID(C5X_INS_CRGT); return 2;
	case 0x1c: ID(C5X_INS_CRLT); return 2;
	case 0x1d: ID(C5X_INS_EXAR); return 2;
	case 0x1e: ID(C5X_INS_SACB); return 2;
	case 0x1f: ID(C5X_INS_LACB); return 2;
	case 0x20: ID(C2X_INS_BACC); return 2;
	case 0x21: ID(C5X_INS_BACCD); return 2;
	case 0x22: ID(C2X_INS_IDLE); return 2;
	case 0x23: ID(C5X_INS_IDLE2); return 2;
	case 0x30: ID(C2X_INS_CALA); return 2;
	case 0x32: ID(C2X_INS_POP); return 2;
	case 0x38: ID(C5X_INS_RETI); return 2;
	case 0x3a: ID(C5X_INS_RETE); return 2;
	case 0x3c: ID(C2X_INS_PUSH); return 2;
	case 0x3d: ID(C5X_INS_CALAD); return 2;
	case 0x51: ID(C2X_INS_TRAP); return 2;
	case 0x52: ID(C5X_INS_NMI); return 2;
	case 0x58: ID(C5X_INS_ZPR); return 2;
	case 0x59: ID(C5X_INS_ZAP); return 2;
	case 0x5a: ID(C5X_INS_SATH); return 2;
	case 0x5b: ID(C5X_INS_SATL); return 2;
	default: break;
	}
	if (sub >= 0x40 && sub <= 0x4f) {
		ID((sub & 1) ? C5X_INS_SETC : C5X_INS_CLRC);
		out->ops[0].kind = C55_OP_NONE;
		out->ops[0].raw = c5x_ctrl_bits[(sub >> 1) & 7];
		out->n_ops = 1;
		return 2;
	}
	if (sub >= 0x60 && sub <= 0x7f) {
		ID(C5X_INS_INTR);
		imm_op(&out->ops[0], op & 0x1f, 8, false);
		out->n_ops = 1;
		return 2;
	}
	switch (sub) {
	case 0x80:
		ID(C2X_INS_MPY);
		imm_op(&out->ops[0], w2, 16, true);
		out->n_ops = 1;
		return 4;
	case 0x81:
		ID(C2X_INS_AND);
		imm_op(&out->ops[0], w2, 16, false);
		out->n_ops = 1;
		return 4;
	case 0x82:
		ID(C2X_INS_OR);
		imm_op(&out->ops[0], w2, 16, false);
		out->n_ops = 1;
		return 4;
	case 0x83:
		ID(C2X_INS_XOR);
		imm_op(&out->ops[0], w2, 16, false);
		out->n_ops = 1;
		return 4;
	case 0xc4:
		ID(C2X_INS_RPT);
		imm_op(&out->ops[0], w2, 16, false);
		out->n_ops = 1;
		return 4;
	case 0xc5:
		ID(C5X_INS_RPTZ);
		imm_op(&out->ops[0], w2, 16, false);
		out->n_ops = 1;
		return 4;
	case 0xc6:
		ID(C5X_INS_RPTB);
		target_op(&out->ops[0], w2);
		out->n_ops = 1;
		return 4;
	default: return 0;
	}
}

// The BF group (0xBFxx): LAR/SPM, CMPR, shifted long-immediate ALU, BSAR.
static int decode_bf(C55Insn *out, ut16 op, ut16 w2) {
	ut8 sub = (op >> 4) & 0xf;
	ut8 shift = op & 0xf;
	if (sub == 0x0) {
		if (op & 0x8) {
			ID(C2X_INS_LAR);
			ar_op(&out->ops[0], op & 7);
			imm_op(&out->ops[1], w2, 16, false);
			out->n_ops = 2;
			return 4;
		}
		ID(C2X_INS_SPM);
		imm_op(&out->ops[0], op & 3, 8, false);
		out->n_ops = 1;
		return 2;
	}
	if (sub == 0x4) {
		ID(C2X_INS_CMPR);
		imm_op(&out->ops[0], op & 3, 8, false);
		out->n_ops = 1;
		return 2;
	}
	if (sub == 0xe) {
		ID(C5X_INS_BSAR);
		imm_op(&out->ops[0], shift + 1, 8, false);
		out->n_ops = 1;
		return 2;
	}
	if (c5x_long_imm_alu[sub]) {
		ID(c5x_long_imm_alu[sub]);
		imm_op(&out->ops[0], w2, 16, false);
		out->n_ops = 1;
		if (shift) {
			shift_op(&out->ops[1], shift);
			out->n_ops = 2;
		}
		return 4;
	}
	return 0;
}

/**
 * \brief Decode one C5x instruction into the shared C55 representation.
 * \param buf Instruction bytes, big-endian 16-bit words
 * \param len Number of readable bytes in \p buf
 * \param out Instruction to fill in
 * \return Instruction length in bytes (2 or 4), or 0 on an undefined opcode
 *
 * Two-word forms consume the following word as their trailing operand, so
 * \p len must cover both words for those to decode.
 */
RZ_IPI int c5x_decode(const ut8 *buf, int len, C55Insn *out) {
	if (!buf || !out || len < 2) {
		return 0;
	}
	memset(out, 0, sizeof(*out));
	out->arch = C55_ARCH_C5X;
	ut16 op = ((ut16)buf[0] << 8) | buf[1];
	ut16 w2 = (len >= 4) ? (((ut16)buf[2] << 8) | buf[3]) : 0;
	ut8 base = (op >> 8) & 0xff;
	ut8 low = op & 0xff;
	ut8 sh4 = (op >> 8) & 0xf;
	ut8 sh3 = (op >> 8) & 7;
	ut8 ar = (op >> 8) & 7;

	if (base <= 0x07) { // lar arN, mem
		ID(C2X_INS_LAR);
		ar_op(&out->ops[0], ar);
		mem_op(&out->ops[1], low);
		out->n_ops = 2;
		if (narp_op(&out->ops[2], low)) {
			out->n_ops++;
		}
		out->size = 2;
		return 2;
	}
	switch (base) {
	case 0x08: return mem_plain_insn(out, C5X_INS_LAMM, low);
	case 0x09: return mem_imm2_insn(out, C5X_INS_SMMR, low, w2);
	case 0x0a: return mem_plain_insn(out, C2X_INS_SUBC, low);
	case 0x0b: return mem_plain_insn(out, C2X_INS_RPT, low);
	case 0x0c: return mem_imm2_insn(out, C2X_INS_OUT, low, w2);
	case 0x0d: return mem_plain_insn(out, C2X_INS_LDP, low);
	case 0x0e:
	case 0x0f: {
		ID(C5X_INS_LST);
		imm_op(&out->ops[0], base & 1, 8, false);
		mem_op(&out->ops[1], low);
		out->n_ops = 2;
		if (narp_op(&out->ops[2], low)) {
			out->n_ops++;
		}
		out->size = 2;
		return 2;
	}
	default: break;
	}
	if (base >= 0x10 && base <= 0x1f) {
		return mem_shift_insn(out, C5X_INS_LACC, low, sh4);
	}
	if (base >= 0x20 && base <= 0x2f) {
		return mem_shift_insn(out, C2X_INS_ADD, low, sh4);
	}
	if (base >= 0x30 && base <= 0x3f) {
		return mem_shift_insn(out, C2X_INS_SUB, low, sh4);
	}
	if (base >= 0x40 && base <= 0x4f) { // bit code, mem
		ID(C2X_INS_BIT);
		imm_op(&out->ops[0], sh4, 8, false);
		mem_op(&out->ops[1], low);
		out->n_ops = 2;
		if (narp_op(&out->ops[2], low)) {
			out->n_ops++;
		}
		out->size = 2;
		return 2;
	}
	switch (base) {
	case 0x50: return mem_plain_insn(out, C2X_INS_MPYA, low);
	case 0x51: return mem_plain_insn(out, C2X_INS_MPYS, low);
	case 0x52: return mem_plain_insn(out, C2X_INS_SQRA, low);
	case 0x53: return mem_plain_insn(out, C2X_INS_SQRS, low);
	case 0x54: return mem_plain_insn(out, C2X_INS_MPY, low);
	case 0x55: return mem_plain_insn(out, C2X_INS_MPYU, low);
	case 0x57: return mem_plain_insn(out, C5X_INS_BLDP, low);
	case 0x58: return mem_plain_insn(out, C5X_INS_XPL, low);
	case 0x59: return mem_plain_insn(out, C5X_INS_OPL, low);
	case 0x5a: return mem_plain_insn(out, C5X_INS_APL, low);
	case 0x5b: return mem_plain_insn(out, C5X_INS_CPL, low);
	case 0x5c: return mem_imm2_insn(out, C5X_INS_XPL, low, w2);
	case 0x5d: return mem_imm2_insn(out, C5X_INS_OPL, low, w2);
	case 0x5e: return mem_imm2_insn(out, C5X_INS_APL, low, w2);
	case 0x5f: return mem_imm2_insn(out, C5X_INS_CPL, low, w2);
	case 0x60: return mem_plain_insn(out, C2X_INS_ADDC, low);
	case 0x61: return mem_shift_insn(out, C2X_INS_ADD, low, 16);
	case 0x62: return mem_plain_insn(out, C2X_INS_ADDS, low);
	case 0x63: return mem_plain_insn(out, C2X_INS_ADDT, low);
	case 0x64: return mem_plain_insn(out, C2X_INS_SUBB, low);
	case 0x65: return mem_shift_insn(out, C2X_INS_SUB, low, 16);
	case 0x66: return mem_plain_insn(out, C2X_INS_SUBS, low);
	case 0x67: return mem_plain_insn(out, C2X_INS_SUBT, low);
	case 0x68: return mem_plain_insn(out, C2X_INS_ZALR, low);
	case 0x69: return mem_plain_insn(out, C5X_INS_LACL, low);
	case 0x6a: return mem_shift_insn(out, C5X_INS_LACC, low, 16);
	case 0x6b: return mem_plain_insn(out, C2X_INS_LACT, low);
	case 0x6c: return mem_plain_insn(out, C2X_INS_XOR, low);
	case 0x6d: return mem_plain_insn(out, C2X_INS_OR, low);
	case 0x6e: return mem_plain_insn(out, C2X_INS_AND, low);
	case 0x6f: return mem_plain_insn(out, C2X_INS_BITT, low);
	case 0x70: return mem_plain_insn(out, C2X_INS_LTA, low);
	case 0x71: return mem_plain_insn(out, C2X_INS_LTP, low);
	case 0x72: return mem_plain_insn(out, C2X_INS_LTD, low);
	case 0x73: return mem_plain_insn(out, C2X_INS_LT, low);
	case 0x74: return mem_plain_insn(out, C2X_INS_LTS, low);
	case 0x75: return mem_plain_insn(out, C2X_INS_LPH, low);
	case 0x76: return mem_plain_insn(out, C2X_INS_PSHD, low);
	case 0x77: return mem_plain_insn(out, C2X_INS_DMOV, low);
	default: break;
	}
	if (base == 0x78 || base == 0x7c) {
		return imm_insn(out, base == 0x78 ? C2X_INS_ADRK : C2X_INS_SBRK, low, 8);
	}
	{
		ut16 brid = 0;
		switch (base) {
		case 0x79: brid = C2X_INS_B; break;
		case 0x7a: brid = C2X_INS_CALL; break;
		case 0x7b: brid = C2X_INS_BANZ; break;
		case 0x7d: brid = C5X_INS_BD; break;
		case 0x7e: brid = C5X_INS_CALLD; break;
		case 0x7f: brid = C5X_INS_BANZD; break;
		default: break;
		}
		if (brid) {
			ID(brid);
			target_op(&out->ops[0], w2);
			mem_op(&out->ops[1], low | 0x80); // branch addressing is always indirect
			out->n_ops = 2;
			if (narp_op(&out->ops[2], low | 0x80)) {
				out->n_ops++;
			}
			out->has_branch = true;
			out->branch_target = w2;
			out->size = 4;
			return 4;
		}
	}
	if (base >= 0x80 && base <= 0x87) { // sar arN, mem
		ID(C2X_INS_SAR);
		ar_op(&out->ops[0], ar);
		mem_op(&out->ops[1], low);
		out->n_ops = 2;
		if (narp_op(&out->ops[2], low)) {
			out->n_ops++;
		}
		out->size = 2;
		return 2;
	}
	switch (base) {
	case 0x88: return mem_plain_insn(out, C5X_INS_SAMM, low);
	case 0x89: return mem_imm2_insn(out, C5X_INS_LMMR, low, w2);
	case 0x8a: return mem_plain_insn(out, C2X_INS_POPD, low);
	case 0x8b:
		if (low == 0) {
			ID(C2X_INS_NOP);
			out->n_ops = 0;
			out->size = 2;
			return 2;
		}
		return mem_plain_insn(out, C2X_INS_MAR, low);
	case 0x8c: return mem_plain_insn(out, C2X_INS_SPL, low);
	case 0x8d: return mem_plain_insn(out, C2X_INS_SPH, low);
	case 0x8e:
	case 0x8f: {
		ID(C5X_INS_SST);
		imm_op(&out->ops[0], base & 1, 8, false);
		mem_op(&out->ops[1], low);
		out->n_ops = 2;
		if (narp_op(&out->ops[2], low)) {
			out->n_ops++;
		}
		out->size = 2;
		return 2;
	}
	default: break;
	}
	if (base >= 0x90 && base <= 0x97) {
		return mem_shift_insn(out, C2X_INS_SACL, low, sh3);
	}
	if (base >= 0x98 && base <= 0x9f) {
		return mem_shift_insn(out, C2X_INS_SACH, low, sh3);
	}
	switch (base) {
	case 0xa0: return mem_imm2_insn(out, C2X_INS_NORM, low, w2); // norm mem, #w2 (the trailing word is a count/operand)
	case 0xa2: return mem_imm2_insn(out, C2X_INS_MAC, low, w2);
	// MACD is MAC's data-move twin and carries the same trailing pma word; the
	// BMAR-addressed single-word variants are MADS/MADD below.
	case 0xa3: return mem_imm2_insn(out, C2X_INS_MACD, low, w2);
	case 0xa4: return mem_plain_insn(out, C5X_INS_BLPD, low);
	case 0xa5: return mem_imm2_insn(out, C5X_INS_BLPD, low, w2);
	case 0xa6: return mem_plain_insn(out, C2X_INS_TBLR, low);
	case 0xa7: return mem_plain_insn(out, C2X_INS_TBLW, low);
	case 0xa8:
	case 0xa9: return mem_imm2_insn(out, C5X_INS_BLDD, low, w2);
	case 0xaa: return mem_plain_insn(out, C5X_INS_MADS, low);
	case 0xab: return mem_plain_insn(out, C5X_INS_MADD, low);
	case 0xac:
	case 0xad: return mem_plain_insn(out, C5X_INS_BLDD, low);
	case 0xae: return mem_imm2_insn(out, C5X_INS_SPLK, low, w2);
	case 0xaf: return mem_imm2_insn(out, C2X_INS_IN, low, w2);
	default: break;
	}
	if (base >= 0xb0 && base <= 0xb7) { // lar arN, #imm8 (C2x LARK; rendered "lar")
		ID(C2X_INS_LARK);
		ar_op(&out->ops[0], ar);
		imm_op(&out->ops[1], low, 8, false);
		out->n_ops = 2;
		out->size = 2;
		return 2;
	}
	switch (base) {
	case 0xb8:
		return imm_insn(out, C2X_INS_ADDK, low, 8);
	case 0xb9:
		return imm_insn(out, C5X_INS_LACL, low, 8);
	case 0xba:
		return imm_insn(out, C2X_INS_SUBK, low, 8);
	case 0xbb:
		return imm_insn(out, C2X_INS_RPTK, low, 8);
	case 0xbc:
	case 0xbd:
		return imm_insn(out, C2X_INS_LDPK, op & 0x1ff, 16);
	case 0xbe: {
		int r = decode_be(out, op, w2);
		if (r) {
			out->size = (ut8)r;
		}
		return r;
	}
	case 0xbf: {
		int r = decode_bf(out, op, w2);
		if (r) {
			out->size = (ut8)r;
		}
		return r;
	}
	default: break;
	}
	if (base >= 0xc0 && base <= 0xdf) {
		return 0; // undefined opcode range
	}
	// 0xE0-0xFF: conditional branch / call / return / execute group.
	if (base >= 0xe0 && base <= 0xe3) {
		ID(C5X_INS_BCND);
		target_op(&out->ops[0], w2);
		out->n_ops = 1;
		cond_ops(out, op);
		out->has_branch = true;
		out->branch_target = w2;
		out->size = 4;
		return 4;
	}
	if ((base >= 0xe4 && base <= 0xe7) || (base >= 0xf4 && base <= 0xf7)) {
		ID(C5X_INS_XC);
		imm_op(&out->ops[0], ((op >> 12) & 1) + 1, 8, false);
		out->n_ops = 1;
		cond_ops(out, op);
		out->size = 2;
		return 2;
	}
	if (base >= 0xe8 && base <= 0xeb) {
		ID(C5X_INS_CC);
		target_op(&out->ops[0], w2);
		out->n_ops = 1;
		cond_ops(out, op);
		out->has_branch = true;
		out->branch_target = w2;
		out->size = 4;
		return 4;
	}
	if (base >= 0xec && base <= 0xef) {
		if (op == 0xef00) {
			ID(C2X_INS_RET);
			out->size = 2;
			return 2;
		}
		ID(C5X_INS_RETC);
		cond_ops(out, op);
		out->size = 2;
		return 2;
	}
	if (base >= 0xf0 && base <= 0xf3) {
		ID(C5X_INS_BCNDD);
		target_op(&out->ops[0], w2);
		out->n_ops = 1;
		cond_ops(out, op);
		out->has_branch = true;
		out->branch_target = w2;
		out->size = 4;
		return 4;
	}
	if (base >= 0xf8 && base <= 0xfb) {
		ID(C5X_INS_CCD);
		target_op(&out->ops[0], w2);
		out->n_ops = 1;
		cond_ops(out, op);
		out->has_branch = true;
		out->branch_target = w2;
		out->size = 4;
		return 4;
	}
	if (base >= 0xfc && base <= 0xff) {
		if (op == 0xff00) {
			ID(C5X_INS_RETD); // unconditional delayed return
			out->size = 2;
			return 2;
		}
		ID(C5X_INS_RETCD);
		cond_ops(out, op);
		out->size = 2;
		return 2;
	}
	return 0;
}
