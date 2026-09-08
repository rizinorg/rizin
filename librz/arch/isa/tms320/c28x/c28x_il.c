// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file c28x_il.c
 * TMS320C28x RzIL lifting.
 *
 * Lifts a decoded \ref C28xInsn (from c28x_decode.c) to RzIL. Kept separate from
 * the disassembler so decode and IL stay independent; forms not yet handled
 * return NULL and simply leave op->il_op unset.
 *
 * Two things shape what is modelled. First, the C28x is word addressed: memory
 * is an array of 16-bit words and every address the ISA computes counts words,
 * while the IL VM (like the rest of rizin) addresses bytes. Word addresses are
 * therefore scaled by \ref C28X_WORD_BYTES on the way into a load or store, the
 * same convention the C2x and C5x lifters use.
 *
 * Second, several addressing modes modify their own pointer register, before
 * the access for the pre-decrementing forms and after it for the
 * post-incrementing ones. A memory operand is consequently not a pure
 * expression: c28x_ea_begin() emits any pre-modification and latches the
 * effective address into a local, the access reads that local, and
 * c28x_ea_end() emits the post-modification. Callers must sequence all three.
 *
 * Status flags are not modelled yet. The C28x sets N/Z/C/V from most ALU
 * results, with the exact rule differing per instruction (and per shift count
 * for the shifted forms), so lifting them from a shared helper would be wrong
 * more often than right. Instructions whose whole purpose is a flag (the
 * compare and test group) are left unlifted rather than lifted incorrectly.
 */

#include <rz_util.h>
#include "c28x.h"

#include <rz_il/rz_il_opbuilder_begin.h>

// A C28x word spans this many byte-address units in the IL VM's space.
#define C28X_WORD_BYTES 2
// Data addresses are 32-bit (the ISA computes a 32bitDataAddr; silicon
// implements 22 of those bits).
#define C28X_MEM_ADDR_BITS 32
// Name of the local holding a memory operand's latched effective address.
#define C28X_EA_LOCAL "_ea"
// Name of the local holding a memory operand's loaded value.
#define C28X_VAL_LOCAL "_val"

/* helpers */

// Scale a word address into the byte-addressed IL VM space.
static RzILOpPure *c28x_byte(RzILOpPure *word_addr) {
	return MUL(UNSIGNED(C28X_MEM_ADDR_BITS, word_addr), UN(C28X_MEM_ADDR_BITS, C28X_WORD_BYTES));
}

static const char *c28x_xar_name(ut8 n) {
	static const char *const names[8] = {
		"xar0", "xar1", "xar2", "xar3", "xar4", "xar5", "xar6", "xar7"
	};
	return names[n & 7];
}

// How far a pointer register moves for one access of this width.
static ut32 c28x_step(const C28xOperand *m) {
	return m->wide ? 2 : 1;
}

/**
 * \brief Emit any pre-access pointer update and latch the effective address.
 * \return an effect, or NULL if \p m is not a memory operand this lifts
 *
 * The address is left in the local named \ref C28X_EA_LOCAL as a word address.
 */
static RzILOpEffect *c28x_ea_begin(const C28xOperand *m) {
	const ut32 step = c28x_step(m);
	switch (m->mode) {
	case C28X_AM_DP:
		// 32bitDataAddr(21:6) = DP, (5:0) = 6bit (SPRU430F section 5.4)
		return SETL(C28X_EA_LOCAL,
			LOGOR(SHIFTL0(UNSIGNED(32, VARG("dp")), UN(32, 6)),
				UN(32, m->off & 0x3f)));
	case C28X_AM_SP:
		// 32bitDataAddr(15:0) = SP - 6bit
		return SETL(C28X_EA_LOCAL,
			UNSIGNED(32, SUB(VARG("sp"), UN(16, m->off & 0x3f))));
	case C28X_AM_SP_POSTINC:
		return SETL(C28X_EA_LOCAL, UNSIGNED(32, VARG("sp")));
	case C28X_AM_SP_PREDEC:
		// the decrement happens first, then the access uses the new SP
		return SEQ2(SETG("sp", SUB(VARG("sp"), UN(16, step))),
			SETL(C28X_EA_LOCAL, UNSIGNED(32, VARG("sp"))));
	case C28X_AM_XAR_POSTINC:
	case C28X_AM_XAR_NONE:
		return SETL(C28X_EA_LOCAL, VARG(c28x_xar_name(m->arn)));
	case C28X_AM_XAR_PREDEC:
		return SEQ2(SETG(c28x_xar_name(m->arn),
				    SUB(VARG(c28x_xar_name(m->arn)), UN(32, step))),
			SETL(C28X_EA_LOCAL, VARG(c28x_xar_name(m->arn))));
	case C28X_AM_XAR_AR0:
	case C28X_AM_XAR_AR1:
		// AR0/AR1 are added as unsigned 16-bit values; XARn's upper half
		// participates and may be overflowed into. AR0/AR1 are the low halves
		// of XAR0/XAR1, which is what the VM binds.
		return SETL(C28X_EA_LOCAL,
			ADD(VARG(c28x_xar_name(m->arn)),
				UNSIGNED(32,
					UNSIGNED(16, VARG(m->mode == C28X_AM_XAR_AR0 ? "xar0" : "xar1")))));
	case C28X_AM_XAR_IMM:
		return SETL(C28X_EA_LOCAL,
			ADD(VARG(c28x_xar_name(m->arn)), UN(32, m->off & 7)));
	default:
		// the ARP-relative, circular and register-direct modes are not lifted
		return NULL;
	}
}

/** \brief Emit any post-access pointer update, or NULL when there is none. */
static RzILOpEffect *c28x_ea_end(const C28xOperand *m) {
	const ut32 step = c28x_step(m);
	switch (m->mode) {
	case C28X_AM_SP_POSTINC:
		return SETG("sp", ADD(VARG("sp"), UN(16, step)));
	case C28X_AM_XAR_POSTINC:
		return SETG(c28x_xar_name(m->arn),
			ADD(VARG(c28x_xar_name(m->arn)), UN(32, step)));
	default:
		return NULL;
	}
}

/** \brief Read the latched effective address as a \p bits -wide value. */
static RzILOpPure *c28x_ea_load(ut32 bits) {
	return LOADW(bits, c28x_byte(VARL(C28X_EA_LOCAL)));
}

static RzILOpEffect *c28x_ea_store(RzILOpPure *val) {
	return STOREW(c28x_byte(VARL(C28X_EA_LOCAL)), val);
}

// Sequence pre-modification, body and post-modification for one memory operand.
static RzILOpEffect *c28x_with_ea(const C28xOperand *m, RzILOpEffect *body) {
	RzILOpEffect *pre = c28x_ea_begin(m);
	if (!pre || !body) {
		rz_il_op_effect_free(pre);
		rz_il_op_effect_free(body);
		return NULL;
	}
	RzILOpEffect *post = c28x_ea_end(m);
	return post ? SEQ3(pre, body, post) : SEQ2(pre, body);
}

/**
 * \brief Latch a memory operand's value into \ref C28X_VAL_LOCAL, then run \p body.
 *
 * ALU lifting needs the loaded value more than once (for the result and again
 * for a flag) and an RzIL pure expression cannot be shared, so it is latched
 * first.
 */
static RzILOpEffect *c28x_with_val(const C28xOperand *m, ut32 bits, RzILOpEffect *body) {
	if (!body) {
		return NULL;
	}
	return c28x_with_ea(m, SEQ2(SETL(C28X_VAL_LOCAL, c28x_ea_load(bits)), body));
}

// A loc16 source widened to 32 bits: SXM selects sign or zero extension.
static RzILOpPure *c28x_ext16(bool sxm_ext) {
	return sxm_ext
		? ITE(VARG("sxm"), SIGNED(32, VARL(C28X_VAL_LOCAL)), UNSIGNED(32, VARL(C28X_VAL_LOCAL)))
		: UNSIGNED(32, VARL(C28X_VAL_LOCAL));
}

/* register operands */

// Name of a 16-bit register operand the IL VM binds directly, else NULL.
// AR0-AR7 are deliberately absent: they alias the low half of XAR0-XAR7 and the
// VM binds only the 32-bit parent, so they go through c28x_read16/c28x_write16.
static const char *c28x_reg16(const C28xOperand *o) {
	switch (o->reg) {
	case C28X_REG_SP: return "sp";
	case C28X_REG_DP: return "dp";
	default: return NULL;
	}
}

// True when \p o names one of AR0-AR7.
static bool c28x_is_ar(const C28xOperand *o) {
	return o->reg >= C28X_REG_AR0 && o->reg < C28X_REG_AR0 + 8;
}

/** A 16-bit register that is really a half of a 32-bit one. */
typedef struct {
	const char *parent; ///< name of the 32-bit register holding it
	ut8 shift; ///< bit position of the half within the parent
} C28xSlice;

/**
 * \brief Resolve a 16-bit register operand to its 32-bit parent and position.
 *
 * AH/AL, PH/PL and T/TL are halves of ACC, P and XT, and AR0-AR7 are the low
 * halves of XAR0-XAR7. The IL VM binds the halves and the parents as separate
 * variables, so writing one would leave the other stale; the parent is
 * therefore the single source of truth and the halves are only read and written
 * through it. The C2x lifter keeps ACC authoritative the same way and leaves
 * ACCL/ACCH to the register profile.
 */
static bool c28x_slice(const C28xOperand *o, C28xSlice *out) {
	switch (o->reg) {
	case C28X_REG_AL: *out = (C28xSlice){ "acc", 0 }; return true;
	case C28X_REG_AH: *out = (C28xSlice){ "acc", 16 }; return true;
	case C28X_REG_PL: *out = (C28xSlice){ "p", 0 }; return true;
	case C28X_REG_PH: *out = (C28xSlice){ "p", 16 }; return true;
	case C28X_REG_TL: *out = (C28xSlice){ "xt", 0 }; return true;
	case C28X_REG_T: *out = (C28xSlice){ "xt", 16 }; return true;
	default: break;
	}
	if (c28x_is_ar(o)) {
		*out = (C28xSlice){ c28x_xar_name(o->reg - C28X_REG_AR0), 0 };
		return true;
	}
	return false;
}

// Read a half out of its parent.
static RzILOpPure *c28x_slice_read(const C28xSlice *sl) {
	RzILOpPure *v = VARG(sl->parent);
	return UNSIGNED(16, sl->shift ? SHIFTR0(v, UN(6, sl->shift)) : v);
}

// Write a half back into its parent, keeping the other half unless \p clear_high
// (MOVZ, which is only defined for the low halves).
static RzILOpEffect *c28x_slice_write(const C28xSlice *sl, RzILOpPure *val, bool clear_high) {
	RzILOpPure *wide = UNSIGNED(32, val);
	if (sl->shift) {
		wide = SHIFTL0(wide, UN(6, sl->shift));
	}
	if (clear_high && !sl->shift) {
		return SETG(sl->parent, wide);
	}
	const ut32 keep = sl->shift ? 0x0000ffff : 0xffff0000;
	return SETG(sl->parent, LOGOR(LOGAND(VARG(sl->parent), UN(32, keep)), wide));
}

/** \brief Read a 16-bit register operand, or NULL if it is not one this lifts. */
static RzILOpPure *c28x_read16(const C28xOperand *o) {
	const char *n = c28x_reg16(o);
	if (n) {
		return VARG(n);
	}
	C28xSlice sl;
	return c28x_slice(o, &sl) ? c28x_slice_read(&sl) : NULL;
}

/**
 * \brief Write a 16-bit register operand.
 * \param clear_high zero the parent's upper half (MOVZ) instead of keeping it
 *
 * MOV ARn,loc16 leaves ARnH untouched while MOVZ ARn,loc16 clears it, so the
 * upper half has to be spelled out rather than left to a plain 16-bit store.
 */
static RzILOpEffect *c28x_write16(const C28xOperand *o, RzILOpPure *val, bool clear_high) {
	const char *n = c28x_reg16(o);
	if (n) {
		return SETG(n, val);
	}
	C28xSlice sl;
	if (!c28x_slice(o, &sl)) {
		rz_il_op_pure_free(val);
		return NULL;
	}
	return c28x_slice_write(&sl, val, clear_high);
}

// Name of a 32-bit register operand, or NULL if it is not one this lifts.
static const char *c28x_reg32(const C28xOperand *o) {
	switch (o->reg) {
	case C28X_REG_ACC: return "acc";
	case C28X_REG_P: return "p";
	case C28X_REG_XT: return "xt";
	default: break;
	}
	if (o->reg >= C28X_REG_XAR0 && o->reg < C28X_REG_XAR0 + 8) {
		return c28x_xar_name(o->reg - C28X_REG_XAR0);
	}
	return NULL;
}

/* flags */

// N and Z from a result already latched in a local.
static RzILOpEffect *c28x_nz(const char *local) {
	return SEQ2(SETG("n", MSB(VARL(local))), SETG("z", IS_ZERO(VARL(local))));
}

/**
 * \brief acc = acc +/- val, with C28x flag and saturation behaviour.
 *
 * Latches the old accumulator, the operand and the result so the overflow test
 * can compare their signs. Per SPRU430F's "Flags and Modes" for this group, V is
 * sticky (set on overflow, otherwise untouched), OVC only moves while OVM is
 * clear, and with OVM set the accumulator saturates to the extreme of the sign
 * it started from.
 */
static RzILOpEffect *c28x_acc_addsub(RzILOpPure *val, bool sub) {
	// overflow: operands agreeing in sign but disagreeing with the result
	RzILOpPure *ovf = sub
		? MSB(LOGAND(LOGXOR(VARL("oa"), VARL("av")), LOGXOR(VARL("oa"), VARL("na"))))
		: MSB(LOGAND(LOGXOR(VARL("na"), VARL("av")), LOGXOR(VARL("oa"), VARL("na"))));
	// carry is set by a carry out and cleared by a borrow
	RzILOpPure *carry = sub
		? INV(ULT(VARL("oa"), VARL("av")))
		: ULT(VARL("na"), VARL("oa"));
	return SEQ8(
		SETL("oa", VARG("acc")),
		SETL("av", val),
		SETL("na", sub ? SUB(VARL("oa"), VARL("av")) : ADD(VARL("oa"), VARL("av"))),
		SETL("ovf", ovf),
		SETG("acc",
			ITE(AND(VARG("ovm"), VARL("ovf")),
				ITE(MSB(VARL("oa")), UN(32, 0x80000000), UN(32, 0x7fffffff)),
				VARL("na"))),
		SEQ2(SETG("v", OR(VARG("v"), VARL("ovf"))), SETG("c", carry)),
		// a positive overflow wraps the result negative, so it counts up
		SETG("ovc",
			ITE(AND(VARL("ovf"), INV(VARG("ovm"))),
				ITE(MSB(VARL("na")), ADD(VARG("ovc"), UN(6, 1)), SUB(VARG("ovc"), UN(6, 1))),
				VARG("ovc"))),
		SEQ2(SETG("n", MSB(VARG("acc"))), SETG("z", IS_ZERO(VARG("acc")))));
}

/* conditions */

/**
 * \brief The COND field as a boolean (SPRU430F, "B 16bitOffset,COND").
 * \return NULL for NBIO, whose external input is not modelled
 */
static RzILOpPure *c28x_cond(ut8 cond) {
	switch (cond) {
	case C28X_COND_NEQ: return INV(VARG("z"));
	case C28X_COND_EQ: return VARG("z");
	case C28X_COND_GT: return AND(INV(VARG("z")), INV(VARG("n")));
	case C28X_COND_GEQ: return INV(VARG("n"));
	case C28X_COND_LT: return VARG("n");
	case C28X_COND_LEQ: return OR(VARG("z"), VARG("n"));
	case C28X_COND_HI: return AND(VARG("c"), INV(VARG("z")));
	case C28X_COND_HIS: return VARG("c");
	case C28X_COND_LO: return INV(VARG("c"));
	case C28X_COND_LOS: return OR(INV(VARG("c")), VARG("z"));
	case C28X_COND_NOV: return INV(VARG("v"));
	case C28X_COND_OV: return VARG("v");
	case C28X_COND_NTC: return INV(VARG("tc"));
	case C28X_COND_TC: return VARG("tc");
	case C28X_COND_UNC: return IL_TRUE;
	default: return NULL; // NBIO
	}
}

// Apply a source operand's shift suffix, if it has one. "<< T" takes the count
// from T(3:0); a shift of zero is left alone so the common case stays readable.
static RzILOpPure *c28x_apply_shift(const C28xInsn *insn, RzILOpPure *v) {
	for (ut8 i = 0; i < insn->nops; i++) {
		const C28xOperand *o = &insn->ops[i];
		if (o->kind == C28X_OP_SHIFT && o->imm) {
			return SHIFTL0(v, UN(6, (ut8)o->imm));
		}
		if (o->kind == C28X_OP_REG && o->reg == C28X_REG_T && i == 2) {
			return SHIFTL0(v, UNSIGNED(6, LOGAND(UNSIGNED(16, SHIFTR0(VARG("xt"), UN(6, 16))), UN(16, 0xf))));
		}
	}
	return v;
}

// ACC <op>= <32-bit source>, for the bitwise group: only N and Z are affected.
static RzILOpEffect *c28x_acc_logic(const char *op, RzILOpPure *val) {
	RzILOpPure *r = !strcmp(op, "and") ? LOGAND(VARG("acc"), val)
		: !strcmp(op, "or")        ? LOGOR(VARG("acc"), val)
					   : LOGXOR(VARG("acc"), val);
	return SEQ3(SETL("na", r), SETG("acc", VARL("na")), c28x_nz("na"));
}

/**
 * \brief Shift ACC or AX by a constant, setting N, Z and C.
 * \param n shift count, 1..16
 * \param right shift right rather than left
 * \param arith arithmetic (sign-filling) right shift
 *
 * SPRU430F: C receives the last bit shifted out. Shifting left by n, that is
 * bit (width - n) of the original; shifting right, it is bit (n - 1).
 */
static RzILOpEffect *c28x_shift_const(const char *reg, ut32 width, ut8 n, bool right, bool arith) {
	const ut8 cbit = right ? (ut8)(n - 1) : (ut8)(width - n);
	RzILOpPure *res = right
		? (arith ? SHIFTRA(VARG(reg), UN(6, n)) : SHIFTR0(VARG(reg), UN(6, n)))
		: SHIFTL0(VARG(reg), UN(6, n));
	return SEQ4(
		SETL("sv", VARG(reg)),
		SETG("c", LSB(SHIFTR0(VARL("sv"), UN(6, cbit)))),
		SETG(reg, res),
		SEQ2(SETG("n", MSB(VARG(reg))), SETG("z", IS_ZERO(VARG(reg)))));
}

/* per-instruction lifting */

/**
 * \brief Read a loc16/loc32 source that is register-direct rather than memory.
 * \return an owned pure, or NULL if \p o is not a register-direct operand
 */
static RzILOpPure *c28x_reg_direct(const C28xOperand *o, bool wide) {
	if (o->kind != C28X_OP_MEM || o->mode != C28X_AM_REG) {
		return NULL;
	}
	if (wide) {
		const char *n = c28x_reg32(o);
		return n ? VARG(n) : NULL;
	}
	return c28x_read16(o);
}

static bool c28x_is_mem(const C28xOperand *o) {
	return o->kind == C28X_OP_MEM && o->mode != C28X_AM_REG;
}

// MOV AX,loc16 and MOVL <32-bit reg>,loc32: load a register from memory.
static RzILOpEffect *c28x_lift_load_reg(const C28xInsn *insn, bool wide, bool clear_high) {
	if (!c28x_is_mem(&insn->ops[1])) {
		return NULL;
	}
	RzILOpEffect *body;
	if (wide) {
		const char *dst = c28x_reg32(&insn->ops[0]);
		body = dst ? SETG(dst, c28x_ea_load(32)) : NULL;
	} else {
		body = c28x_write16(&insn->ops[0], c28x_ea_load(16), clear_high);
	}
	return body ? c28x_with_ea(&insn->ops[1], body) : NULL;
}

// MOV loc16,AX and MOVL loc32,<32-bit reg>: store a register to memory.
static RzILOpEffect *c28x_lift_store_reg(const C28xInsn *insn, bool wide) {
	if (!c28x_is_mem(&insn->ops[0])) {
		return NULL;
	}
	RzILOpPure *src;
	if (wide) {
		const char *n = c28x_reg32(&insn->ops[1]);
		src = n ? VARG(n) : NULL;
	} else {
		src = c28x_read16(&insn->ops[1]);
	}
	return src ? c28x_with_ea(&insn->ops[0], c28x_ea_store(src)) : NULL;
}

// Register-to-register move, either width.
static RzILOpEffect *c28x_lift_move_reg(const C28xInsn *insn, bool wide, bool clear_high) {
	const bool src_ok = insn->ops[1].kind == C28X_OP_IMM ||
		insn->ops[1].kind == C28X_OP_REG ||
		(insn->ops[1].kind == C28X_OP_MEM && insn->ops[1].mode == C28X_AM_REG);
	if (!src_ok) {
		return NULL;
	}
	if (wide) {
		const char *dst = c28x_reg32(&insn->ops[0]);
		if (!dst) {
			return NULL;
		}
		if (insn->ops[1].kind == C28X_OP_IMM) {
			return SETG(dst, UN(32, (ut64)insn->ops[1].imm));
		}
		const char *src = c28x_reg32(&insn->ops[1]);
		return src ? SETG(dst, VARG(src)) : NULL;
	}
	RzILOpPure *src = insn->ops[1].kind == C28X_OP_IMM
		? UN(16, (ut64)insn->ops[1].imm)
		: c28x_read16(&insn->ops[1]);
	return src ? c28x_write16(&insn->ops[0], src, clear_high) : NULL;
}

/**
 * \brief Lift an instruction to RzIL.
 * \param insn decoded instruction to lift
 * \param pc byte address of the instruction
 * \return an owned effect, or NULL when the form is not lifted yet
 */
RZ_IPI RZ_OWN RzILOpEffect *c28x_lift(RZ_NONNULL const C28xInsn *insn, ut64 pc) {
	rz_return_val_if_fail(insn && insn->mnemonic, NULL);
	const char *m = insn->mnemonic;

	if (!strcmp(m, "nop")) {
		return NOP();
	}
	const bool movz = !strcmp(m, "movz");
	if ((!strcmp(m, "mov") || movz) && insn->nops == 2) {
		if (c28x_is_mem(&insn->ops[1])) {
			return c28x_lift_load_reg(insn, false, movz);
		}
		if (c28x_is_mem(&insn->ops[0])) {
			return c28x_lift_store_reg(insn, false);
		}
		return c28x_lift_move_reg(insn, false, movz);
	}
	if (!strcmp(m, "movl") && insn->nops == 2) {
		if (c28x_is_mem(&insn->ops[1])) {
			return c28x_lift_load_reg(insn, true, false);
		}
		if (c28x_is_mem(&insn->ops[0])) {
			return c28x_lift_store_reg(insn, true);
		}
		return c28x_lift_move_reg(insn, true, false);
	}
	if (!strcmp(m, "movb") && insn->nops == 2 && insn->ops[1].kind == C28X_OP_IMM) {
		// MOVB ACC,#8bit zero-extends into the whole accumulator; MOVB AX,#8bit
		// writes only the named half
		const char *w = c28x_reg32(&insn->ops[0]);
		if (w) {
			return SETG(w, UN(32, (ut64)insn->ops[1].imm & 0xff));
		}
		return c28x_write16(&insn->ops[0], UN(16, (ut64)insn->ops[1].imm & 0xff), false);
	}
	if (!strcmp(m, "push") && insn->nops == 1) {
		const char *r32 = c28x_reg32(&insn->ops[0]);
		if (r32) {
			return SEQ2(STOREW(c28x_byte(VARG("sp")), VARG(r32)),
				SETG("sp", ADD(VARG("sp"), UN(16, 2))));
		}
		RzILOpPure *v16 = c28x_read16(&insn->ops[0]);
		return v16 ? SEQ2(STOREW(c28x_byte(VARG("sp")), v16),
				     SETG("sp", ADD(VARG("sp"), UN(16, 1))))
			   : NULL;
	}
	if (!strcmp(m, "pop") && insn->nops == 1) {
		const char *r32 = c28x_reg32(&insn->ops[0]);
		if (r32) {
			return SEQ2(SETG("sp", SUB(VARG("sp"), UN(16, 2))),
				SETG(r32, LOADW(32, c28x_byte(VARG("sp")))));
		}
		RzILOpEffect *w = c28x_write16(&insn->ops[0], LOADW(16, c28x_byte(VARG("sp"))), false);
		return w ? SEQ2(SETG("sp", SUB(VARG("sp"), UN(16, 1))), w) : NULL;
	}
	if ((!strcmp(m, "addb") || !strcmp(m, "subb")) && insn->nops == 2 &&
		insn->ops[1].kind == C28X_OP_IMM) {
		const bool sub = m[0] == 's';
		const ut64 k = (ut64)insn->ops[1].imm;
		// ADDB/SUBB ACC set the full flag set; the SP and XARn forms are
		// pointer arithmetic and touch nothing (SPRU430F "Flags and Modes")
		if (insn->ops[0].kind == C28X_OP_REG && insn->ops[0].reg == C28X_REG_ACC) {
			return c28x_acc_addsub(UN(32, k), sub);
		}
		const char *r32 = c28x_reg32(&insn->ops[0]);
		if (r32) {
			return SETG(r32, sub ? SUB(VARG(r32), UN(32, k)) : ADD(VARG(r32), UN(32, k)));
		}
		RzILOpPure *cur = c28x_read16(&insn->ops[0]);
		if (!cur) {
			return NULL;
		}
		return c28x_write16(&insn->ops[0],
			sub ? SUB(cur, UN(16, k)) : ADD(cur, UN(16, k)), false);
	}
	// ADD/SUB ACC,loc16 (with any shift suffix) and the loc32 forms
	const bool is_add = !strcmp(m, "add") || !strcmp(m, "addl");
	const bool is_sub = !strcmp(m, "sub") || !strcmp(m, "subl");
	if ((is_add || is_sub) && insn->nops >= 2 &&
		insn->ops[0].kind == C28X_OP_REG && insn->ops[0].reg == C28X_REG_ACC &&
		c28x_is_mem(&insn->ops[1])) {
		const bool wide = insn->ops[1].wide;
		RzILOpPure *v = wide ? VARL(C28X_VAL_LOCAL) : c28x_apply_shift(insn, c28x_ext16(true));
		return c28x_with_val(&insn->ops[1], wide ? 32 : 16, c28x_acc_addsub(v, is_sub));
	}
	if ((is_add || is_sub) && insn->nops >= 2 &&
		insn->ops[0].kind == C28X_OP_REG && insn->ops[0].reg == C28X_REG_ACC &&
		insn->ops[1].mode == C28X_AM_REG) {
		const bool wide = insn->ops[1].wide;
		RzILOpPure *v = c28x_reg_direct(&insn->ops[1], wide);
		if (!v) {
			return NULL;
		}
		return c28x_acc_addsub(wide ? v : ITE(VARG("sxm"), SIGNED(32, v), UNSIGNED(32, DUP(v))), is_sub);
	}
	if ((is_add || is_sub) && insn->nops == 2 &&
		insn->ops[0].kind == C28X_OP_REG && insn->ops[0].reg == C28X_REG_ACC &&
		insn->ops[1].kind == C28X_OP_IMM) {
		return c28x_acc_addsub(UN(32, (ut64)insn->ops[1].imm), is_sub);
	}

	// AND/OR/XOR ACC,loc16 and the loc32 forms
	if ((!strcmp(m, "and") || !strcmp(m, "or") || !strcmp(m, "xor") ||
		    !strcmp(m, "andl") || !strcmp(m, "orl") || !strcmp(m, "xorl")) &&
		insn->nops >= 2 && insn->ops[0].kind == C28X_OP_REG &&
		insn->ops[0].reg == C28X_REG_ACC && c28x_is_mem(&insn->ops[1])) {
		const bool wide = insn->ops[1].wide;
		char base[4] = { m[0], m[1], m[2], 0 };
		RzILOpPure *v = wide ? VARL(C28X_VAL_LOCAL)
				     : c28x_apply_shift(insn, c28x_ext16(false));
		return c28x_with_val(&insn->ops[1], wide ? 32 : 16, c28x_acc_logic(base, v));
	}

	// CMP/CMPL: the difference is discarded, only N/Z/C are set
	if ((!strcmp(m, "cmp") || !strcmp(m, "cmpl")) && insn->nops == 2 &&
		insn->ops[0].kind == C28X_OP_REG) {
		const bool wide = !strcmp(m, "cmpl");
		RzILOpPure *lhs = wide ? (c28x_reg32(&insn->ops[0]) ? VARG(c28x_reg32(&insn->ops[0])) : NULL)
				       : c28x_read16(&insn->ops[0]);
		if (!lhs) {
			return NULL;
		}
		RzILOpEffect *body = SEQ4(
			SETL("cl", lhs),
			SETL("cd", SUB(VARL("cl"), VARL(C28X_VAL_LOCAL))),
			c28x_nz("cd"),
			SETG("c", INV(ULT(VARL("cl"), VARL(C28X_VAL_LOCAL)))));
		if (c28x_is_mem(&insn->ops[1])) {
			return c28x_with_val(&insn->ops[1], wide ? 32 : 16, body);
		}
		rz_il_op_effect_free(body);
		RzILOpPure *rhs = c28x_reg_direct(&insn->ops[1], wide);
		if (!rhs && insn->ops[1].kind == C28X_OP_IMM) {
			rhs = UN(wide ? 32 : 16, (ut64)insn->ops[1].imm);
		}
		if (!rhs) {
			return NULL;
		}
		RzILOpPure *l2 = wide ? (c28x_reg32(&insn->ops[0]) ? VARG(c28x_reg32(&insn->ops[0])) : NULL)
				      : c28x_read16(&insn->ops[0]);
		if (!l2) {
			rz_il_op_pure_free(rhs);
			return NULL;
		}
		return SEQ4(
			SETL("cl", l2),
			SETL("cr", rhs),
			SEQ2(SETL("cd", SUB(VARL("cl"), VARL("cr"))), c28x_nz("cd")),
			SETG("c", INV(ULT(VARL("cl"), VARL("cr")))));
	}

	// CMPB AX,#8bit compares against a zero-extended constant
	if (!strcmp(m, "cmpb") && insn->nops == 2 && insn->ops[1].kind == C28X_OP_IMM) {
		RzILOpPure *lhs = c28x_read16(&insn->ops[0]);
		if (!lhs) {
			return NULL;
		}
		return SEQ4(
			SETL("cl", lhs),
			SETL("cr", UN(16, (ut64)insn->ops[1].imm & 0xff)),
			SEQ2(SETL("cd", SUB(VARL("cl"), VARL("cr"))), c28x_nz("cd")),
			SETG("c", INV(ULT(VARL("cl"), VARL("cr")))));
	}

	// MOVW DP,#16bit loads the data page register outright
	if (!strcmp(m, "movw") && insn->nops == 2 && insn->ops[1].kind == C28X_OP_IMM &&
		insn->ops[0].kind == C28X_OP_REG && insn->ops[0].reg == C28X_REG_DP) {
		return SETG("dp", UN(16, (ut64)insn->ops[1].imm & 0xffff));
	}

	// LCR: RPC is pushed as two words, RPC takes the return address, then the
	// call is taken (SPRU430F "LCR #22bit"). PC + 2 is the next instruction,
	// which in rizin's byte-scaled space is pc + size.
	if (!strcmp(m, "lcr") && insn->nops == 1 &&
		(insn->ops[0].kind == C28X_OP_PMA || insn->ops[0].kind == C28X_OP_PCREL)) {
		return SEQ4(
			STOREW(c28x_byte(VARG("sp")), UNSIGNED(16, VARG("rpc"))),
			SEQ2(SETG("sp", ADD(VARG("sp"), UN(16, 1))),
				STOREW(c28x_byte(VARG("sp")),
					UNSIGNED(16, SHIFTR0(VARG("rpc"), UN(6, 16))))),
			SEQ2(SETG("sp", ADD(VARG("sp"), UN(16, 1))),
				SETG("rpc", UN(32, pc + insn->size))),
			JMP(UN(32, (ut64)insn->ops[0].imm)));
	}

	// LRETR: PC comes from RPC, then RPC is popped back off the stack
	if (!strcmp(m, "lretr") && !insn->nops) {
		return SEQ4(
			SETL("rt", VARG("rpc")),
			SEQ2(SETG("sp", SUB(VARG("sp"), UN(16, 1))),
				SETL("hi", UNSIGNED(32, LOADW(16, c28x_byte(VARG("sp")))))),
			SEQ2(SETG("sp", SUB(VARG("sp"), UN(16, 1))),
				SETG("rpc",
					LOGAND(LOGOR(SHIFTL0(VARL("hi"), UN(6, 16)),
						       UNSIGNED(32, LOADW(16, c28x_byte(VARG("sp"))))),
						UN(32, 0x3fffff)))),
			JMP(VARL("rt")));
	}

	// LSL/LSR/ASR/SFR with a constant count. SFR picks arithmetic or logical
	// from SXM, so it is lifted only where the choice is already decided.
	if ((!strcmp(m, "lsl") || !strcmp(m, "lsr") || !strcmp(m, "asr")) &&
		insn->nops == 2 && insn->ops[0].kind == C28X_OP_REG &&
		insn->ops[1].kind == C28X_OP_SHIFT && insn->ops[1].imm) {
		const ut8 n = (ut8)insn->ops[1].imm;
		const bool right = m[1] == 's' && (m[2] == 'r');
		const bool arith = m[0] == 'a';
		const char *r32 = c28x_reg32(&insn->ops[0]);
		if (r32) {
			return c28x_shift_const(r32, 32, n, right, arith);
		}
		C28xSlice sl;
		if (!c28x_slice(&insn->ops[0], &sl)) {
			return NULL;
		}
		RzILOpPure *res = right
			? (arith ? SHIFTRA(VARL("sv"), UN(6, n)) : SHIFTR0(VARL("sv"), UN(6, n)))
			: SHIFTL0(VARL("sv"), UN(6, n));
		return SEQ4(
			SETL("sv", c28x_slice_read(&sl)),
			SETG("c", LSB(SHIFTR0(VARL("sv"), UN(6, right ? n - 1 : 16 - n)))),
			c28x_slice_write(&sl, res, false),
			SEQ2(SETG("n", MSB(c28x_slice_read(&sl))), SETG("z", IS_ZERO(c28x_slice_read(&sl)))));
	}

	// TBIT loc16,#bit: TC receives the tested bit
	if (!strcmp(m, "tbit") && insn->nops == 2 && c28x_is_mem(&insn->ops[0]) &&
		insn->ops[1].kind == C28X_OP_IMM) {
		const ut8 bit = (ut8)(insn->ops[1].imm & 0xf);
		return c28x_with_val(&insn->ops[0], 16,
			SETG("tc", LSB(SHIFTR0(VARL(C28X_VAL_LOCAL), UN(5, bit)))));
	}

	// MPYB P,T,#8bit: signed T times a zero-extended constant
	if (!strcmp(m, "mpyb") && insn->nops == 3 && insn->ops[2].kind == C28X_OP_IMM) {
		return SETG("p", MUL(SIGNED(32, UNSIGNED(16, SHIFTR0(VARG("xt"), UN(6, 16)))), UN(32, (ut64)insn->ops[2].imm & 0xff)));
	}

	// SETC/CLRC: each set bit of the mask names one status bit to write
	if ((!strcmp(m, "setc") || !strcmp(m, "clrc")) && insn->nops == 1 &&
		insn->ops[0].kind == C28X_OP_MODE) {
		// same order as the formatter's mask spelling (SPRU430F "SETC mode")
		static const char *const bits[8] = {
			"sxm", "ovm", "tc", "c", "intm", "dbgm", "page0", "vmap"
		};
		const bool set = m[0] == 's';
		RzILOpEffect *eff = NULL;
		for (ut8 i = 0; i < 8; i++) {
			if (!(insn->ops[0].imm & (1 << i))) {
				continue;
			}
			RzILOpEffect *one = SETG(bits[i], set ? IL_TRUE : IL_FALSE);
			eff = eff ? SEQ2(eff, one) : one;
		}
		return eff;
	}

	// branches: the decoder already resolved the target to an absolute address
	if ((!strcmp(m, "b") || !strcmp(m, "sb") || !strcmp(m, "lb") || !strcmp(m, "sbf")) &&
		insn->nops >= 1 &&
		(insn->ops[0].kind == C28X_OP_PCREL || insn->ops[0].kind == C28X_OP_PMA)) {
		RzILOpPure *target = UN(32, (ut64)insn->ops[0].imm);
		if (insn->cond == C28X_COND_UNC) {
			return JMP(target);
		}
		RzILOpPure *c = c28x_cond(insn->cond);
		if (!c) {
			rz_il_op_pure_free(target);
			return NULL;
		}
		return BRANCH(c, JMP(target), NOP());
	}

	(void)pc;
	return NULL;
}

/**
 * \brief IL-VM configuration for the C28x.
 *
 * The VM addresses bytes, so a 16-bit word address becomes a
 * C28X_MEM_ADDR_BITS-wide byte address once scaled.
 */
RZ_IPI RZ_OWN RzAnalysisILConfig *c28x_il_config(void) {
	return rz_analysis_il_config_new(C28X_MEM_ADDR_BITS, false, C28X_MEM_ADDR_BITS);
}

#include <rz_il/rz_il_opbuilder_end.h>
