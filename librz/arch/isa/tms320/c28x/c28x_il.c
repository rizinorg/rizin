// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file c28x_il.c
 * TMS320C28x RzIL lifting.
 *
 * Lifts a decoded \ref C28xInsn. Forms not handled here return NULL and leave
 * op->il_op unset.
 *
 * The ISA computes 16-bit word addresses but the IL VM addresses bytes, so a
 * word address is scaled by \ref C28X_WORD_BYTES on its way into a load or
 * store, as in the C2x and C5x lifters.
 *
 * Several addressing modes update their pointer register before or after the
 * access, so a memory operand is not a pure expression: c28x_ea_begin() applies
 * any pre-update and latches the address, the access reads it, and
 * c28x_ea_end() applies any post-update.
 *
 * Flags are set by each instruction's own lifting, since the rules differ per
 * instruction; c28x_acc_addsub() documents the accumulator's.
 */

#include <rz_util.h>
#include "c28x.h"
#include "c28x_il.h"

#include <rz_il/rz_il_opbuilder_begin.h>

// A C28x word spans this many byte-address units in the IL VM's space.
#define C28X_WORD_BYTES 2
// Data addresses are 32-bit (the ISA computes a 32bitDataAddr; silicon
// implements 22 of those bits).
#define C28X_MEM_ADDR_BITS 32
// Name of the local holding a memory operand's loaded value.
#define C28X_VAL_LOCAL "_val"

/* helpers */

// Scale a word address into the byte-addressed IL VM space.
RZ_IPI RzILOpPure *c28x_byte(RzILOpPure *word_addr) {
	return MUL(UNSIGNED(C28X_MEM_ADDR_BITS, word_addr),
		UN(C28X_MEM_ADDR_BITS, C28X_WORD_BYTES));
}

/**
 * \brief The word at SP, zero-extended to 32 bits: one half of a popped RPC.
 */
static RzILOpPure *c28x_stack_word(void) {
	return UNSIGNED(32, LOADW(16, c28x_byte(VARG("sp"))));
}

static const char *const c28x_xar_names[8] = {
	"xar0", "xar1", "xar2", "xar3", "xar4", "xar5", "xar6", "xar7"
};

// the status bits SETC and CLRC name, in the order of their mask (SPRU430F "SETC mode")
static const char *const c28x_mode_bits[8] = {
	"sxm", "ovm", "tc", "c", "intm", "dbgm", "page0", "vmap"
};

static const char *c28x_xar_name(ut8 n) {
	return c28x_xar_names[n & 7];
}

// How far a pointer register moves for one access of this width.
static ut32 c28x_step(const C28xOperand *m) {
	return m->wide ? 2 : 1;
}

// XAR(ARP): the auxiliary register the 3-bit ARP selects.
static RzILOpPure *c28x_arp_xar(void) {
	RzILOpPure *v = VARG(c28x_xar_name(7));
	for (int n = 6; n >= 0; n--) {
		v = ITE(EQ(VARG("arp"), UN(3, n)), VARG(c28x_xar_name((ut8)n)), v);
	}
	return v;
}

// Write the local \p local to XAR(ARP).
static RzILOpEffect *c28x_arp_write(const char *local) {
	RzILOpEffect *eff = SETG(c28x_xar_name(7), VARL(local));
	for (int n = 6; n >= 0; n--) {
		RzILOpPure *sel = EQ(VARG("arp"), UN(3, n));
		eff = BRANCH(sel, SETG(c28x_xar_name((ut8)n), VARL(local)), eff);
	}
	return eff;
}

// The 16-bit local \p local with its bits in reverse order.
static RzILOpPure *c28x_rev16(const char *local) {
	RzILOpPure *r = SHIFTL0(LOGAND(VARL(local), UN(16, 1)), UN(4, 15));
	for (ut32 i = 1; i < 16; i++) {
		RzILOpPure *bit = LOGAND(VARL(local), UN(16, 1u << i));
		RzILOpPure *moved;
		if (i < 8) {
			moved = SHIFTL0(bit, UN(4, 15 - 2 * i));
		} else {
			moved = SHIFTR0(bit, UN(4, 2 * i - 15));
		}
		r = LOGOR(r, moved);
	}
	return r;
}

/**
 * \brief The post-access update of XAR(ARP) for the C2xLP modes.
 *
 * *BR0++ and *BR0-- reverse-carry add or subtract AR0 in the low half only,
 * which walks an FFT buffer in bit-reversed order (SPRU430F section 5.6).
 */
static RzILOpEffect *c28x_arp_update(const C28xOperand *m) {
	const ut32 step = c28x_step(m);
	RzILOpPure *ar0 = UNSIGNED(32, UNSIGNED(16, VARG("xar0")));
	RzILOpEffect *calc;
	switch (m->mode) {
	case C28X_AM_ARP_POSTINC:
		rz_il_op_pure_free(ar0);
		calc = SETL("an", ADD(VARL("ao"), UN(32, step)));
		break;
	case C28X_AM_ARP_POSTDEC:
		rz_il_op_pure_free(ar0);
		calc = SETL("an", SUB(VARL("ao"), UN(32, step)));
		break;
	case C28X_AM_ARP_IDX_INC:
		calc = SETL("an", ADD(VARL("ao"), ar0));
		break;
	case C28X_AM_ARP_IDX_DEC:
		calc = SETL("an", SUB(VARL("ao"), ar0));
		break;
	case C28X_AM_ARP_BR_INC:
	case C28X_AM_ARP_BR_DEC: {
		rz_il_op_pure_free(ar0);
		const bool inc = m->mode == C28X_AM_ARP_BR_INC;
		RzILOpPure *ra = c28x_rev16("ba");
		RzILOpPure *r0 = c28x_rev16("b0");
		RzILOpPure *high = LOGAND(VARL("ao"), UN(32, 0xffff0000));
		calc = SEQ5(SETL("ba", UNSIGNED(16, VARL("ao"))),
			SETL("b0", UNSIGNED(16, VARG("xar0"))),
			SETL("bs", inc ? ADD(ra, r0) : SUB(ra, r0)),
			SETL("bn", c28x_rev16("bs")),
			SETL("an", LOGOR(high, UNSIGNED(32, VARL("bn")))));
		break;
	}
	default:
		rz_il_op_pure_free(ar0);
		return NULL;
	}
	return SEQ3(SETL("ao", c28x_arp_xar()), calc, c28x_arp_write("an"));
}

/**
 * \brief The post-access update of *AR6%++, a circular buffer over XAR6.
 *
 * The buffer ends where XAR6(7:0) reaches AR1(7:0); XAR6 then wraps to its
 * 256-word-aligned start (SPRU430F section 5.6).
 */
static RzILOpEffect *c28x_circ_update(const C28xOperand *m) {
	RzILOpPure *low = UNSIGNED(32, ADD(UNSIGNED(16, VARG("xar6")), UN(16, c28x_step(m))));
	return SEQ2(BRANCH(EQ(UNSIGNED(8, VARG("xar6")), UNSIGNED(8, VARG("xar1"))),
			    SETG("xar6", LOGAND(VARG("xar6"), UN(32, 0xffffff00))),
			    SETG("xar6", LOGOR(LOGAND(VARG("xar6"), UN(32, 0xffff0000)), low))),
		SETG("arp", UN(3, 6)));
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
					UNSIGNED(16,
						VARG(c28x_xar_name(m->mode == C28X_AM_XAR_AR1))))));
	case C28X_AM_XAR_IMM:
		return SETL(C28X_EA_LOCAL,
			ADD(VARG(c28x_xar_name(m->arn)), UN(32, m->off & 7)));
	case C28X_AM_ARP:
	case C28X_AM_ARP_POSTINC:
	case C28X_AM_ARP_POSTDEC:
	case C28X_AM_ARP_IDX_INC:
	case C28X_AM_ARP_IDX_DEC:
	case C28X_AM_ARP_BR_INC:
	case C28X_AM_ARP_BR_DEC:
	case C28X_AM_ARP_SET:
		return SETL(C28X_EA_LOCAL, c28x_arp_xar());
	case C28X_AM_CIRC:
		return SETL(C28X_EA_LOCAL, VARG("xar6"));
	default:
		// register-direct operands are not memory
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
	case C28X_AM_ARP_SET:
		// the access used the old ARP; the new one applies from here
		return SETG("arp", UN(3, m->arn & 7));
	case C28X_AM_CIRC:
		return c28x_circ_update(m);
	default:
		return c28x_arp_update(m);
	}
}

/** \brief Read the latched effective address as a \p bits -wide value. */
RZ_IPI RzILOpPure *c28x_ea_load(ut32 bits) {
	return LOADW(bits, c28x_byte(VARL(C28X_EA_LOCAL)));
}

RZ_IPI RzILOpEffect *c28x_ea_store(RzILOpPure *val) {
	return STOREW(c28x_byte(VARL(C28X_EA_LOCAL)), val);
}

// Sequence pre-modification, body and post-modification for one memory operand.
RZ_IPI RzILOpEffect *c28x_with_ea(const C28xOperand *m, RzILOpEffect *body) {
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
		? ITE(VARG("sxm"), SIGNED(32, VARL(C28X_VAL_LOCAL)),
			  UNSIGNED(32, VARL(C28X_VAL_LOCAL)))
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
 * halves of XAR0-XAR7. The IL VM holds halves and parents as separate
 * variables, so only the parent is stored and the halves are read and written
 * through it, as the C2x lifter does for ACC.
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
RZ_IPI const char *c28x_reg32(const C28xOperand *o) {
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

/**
 * \brief Read the left operand of CMP (16-bit) or CMPL (a 32-bit register).
 * \return NULL if CMPL's operand is not a 32-bit register this lifts
 */
static RzILOpPure *c28x_cmp_lhs(const C28xOperand *o, bool wide) {
	if (!wide) {
		return c28x_read16(o);
	}
	const char *r = c28x_reg32(o);
	return r ? VARG(r) : NULL;
}

/* flags */

// N and Z from a result already latched in a local.
static RzILOpEffect *c28x_nz(const char *local) {
	return SEQ2(SETG("n", MSB(VARL(local))), SETG("z", IS_ZERO(VARL(local))));
}

/**
 * \brief acc = acc +/- val, with the C28x flags and saturation.
 *
 * The old accumulator, the operand and the result are latched so the overflow
 * test can compare their signs. Per SPRU430F "Flags and Modes": V is sticky,
 * OVC counts only while OVM is clear, and with OVM set the accumulator
 * saturates at the limit of its original sign.
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
				ITE(MSB(VARL("na")), ADD(VARG("ovc"), UN(6, 1)),
					SUB(VARG("ovc"), UN(6, 1))),
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
			// the count is the low four bits of T, the high half of XT
			RzILOpPure *t = UNSIGNED(16, SHIFTR0(VARG("xt"), UN(6, 16)));
			return SHIFTL0(v, UNSIGNED(6, LOGAND(t, UN(16, 0xf))));
		}
	}
	return v;
}

// ACC <op>= <32-bit source>, for the bitwise group: only N and Z are affected.
static RzILOpEffect *c28x_acc_logic(C28xInsnId id, RzILOpPure *val) {
	RzILOpPure *r = id == C28X_INS_AND ? LOGAND(VARG("acc"), val)
		: id == C28X_INS_OR        ? LOGOR(VARG("acc"), val)
					   : LOGXOR(VARG("acc"), val);
	return SEQ3(SETL("na", r), SETG("acc", VARL("na")), c28x_nz("na"));
}

/**
 * \brief Shift \p val by the constant \p n.
 * \param right shift right rather than left
 * \param arith arithmetic (sign-filling) right shift
 */
static RzILOpPure *c28x_shift_by(RzILOpPure *val, ut8 n, bool right, bool arith) {
	if (!right) {
		return SHIFTL0(val, UN(6, n));
	}
	return arith ? SHIFTRA(val, UN(6, n)) : SHIFTR0(val, UN(6, n));
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
	RzILOpPure *res = c28x_shift_by(VARG(reg), n, right, arith);
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

RZ_IPI bool c28x_is_mem(const C28xOperand *o) {
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
/**
 * \brief Latch a source operand, memory or register, into \ref C28X_VAL_LOCAL,
 * then run \p body.
 */
static RzILOpEffect *c28x_with_src(const C28xOperand *o, ut32 bits, RzILOpEffect *body) {
	if (!body) {
		return NULL;
	}
	if (c28x_is_mem(o)) {
		return c28x_with_val(o, bits, body);
	}
	RzILOpPure *v = NULL;
	if (bits == 32) {
		const char *n = c28x_reg32(o);
		v = n ? VARG(n) : NULL;
	} else {
		v = c28x_read16(o);
	}
	if (!v) {
		rz_il_op_effect_free(body);
		return NULL;
	}
	return SEQ2(SETL(C28X_VAL_LOCAL, v), body);
}

/**
 * \brief Read-modify-write a 16-bit operand, memory or register.
 *
 * \p body computes the local "res" from the old value in \ref C28X_VAL_LOCAL;
 * "res" is then written back.
 */
static RzILOpEffect *c28x_rmw16(const C28xOperand *o, RzILOpEffect *body) {
	if (!body) {
		return NULL;
	}
	if (c28x_is_mem(o)) {
		RzILOpEffect *load = SETL(C28X_VAL_LOCAL, c28x_ea_load(16));
		return c28x_with_ea(o, SEQ3(load, body, c28x_ea_store(VARL("res"))));
	}
	RzILOpPure *cur = c28x_read16(o);
	RzILOpEffect *wr = c28x_write16(o, VARL("res"), false);
	if (!cur || !wr) {
		rz_il_op_pure_free(cur);
		rz_il_op_effect_free(wr);
		rz_il_op_effect_free(body);
		return NULL;
	}
	return SEQ3(SETL(C28X_VAL_LOCAL, cur), body, wr);
}

// Store to a 16-bit operand, memory or register.
static RzILOpEffect *c28x_store16(const C28xOperand *o, RzILOpPure *val) {
	if (c28x_is_mem(o)) {
		return c28x_with_ea(o, c28x_ea_store(val));
	}
	return c28x_write16(o, val, false);
}

static RzILOpEffect *c28x_nz_acc(void) {
	return SEQ2(SETG("n", MSB(VARG("acc"))), SETG("z", IS_ZERO(VARG("acc"))));
}

/**
 * \brief acc = acc + val + C, or acc = acc - val - !C, flagged and saturated
 * as c28x_acc_addsub() does.
 *
 * The sum is formed in 33 bits so bit 32 is the carry out, or the borrow.
 */
static RzILOpEffect *c28x_acc_addsub_carry(RzILOpPure *val, bool sub) {
	RzILOpPure *cin = ITE(sub ? INV(VARG("c")) : VARG("c"), UN(33, 1), UN(33, 0));
	RzILOpPure *wide = sub
		? SUB(SUB(UNSIGNED(33, VARL("oa")), UNSIGNED(33, VARL("av"))), cin)
		: ADD(ADD(UNSIGNED(33, VARL("oa")), UNSIGNED(33, VARL("av"))), cin);
	RzILOpPure *ovf = sub
		? MSB(LOGAND(LOGXOR(VARL("oa"), VARL("av")), LOGXOR(VARL("oa"), VARL("na"))))
		: MSB(LOGAND(LOGXOR(VARL("na"), VARL("av")), LOGXOR(VARL("oa"), VARL("na"))));
	return SEQ8(
		SETL("oa", VARG("acc")),
		SETL("av", val),
		SEQ2(SETL("w", wide), SETL("na", UNSIGNED(32, VARL("w")))),
		SETL("ovf", ovf),
		SETG("acc",
			ITE(AND(VARG("ovm"), VARL("ovf")),
				ITE(MSB(VARL("oa")), UN(32, 0x80000000), UN(32, 0x7fffffff)),
				VARL("na"))),
		SEQ2(SETG("v", OR(VARG("v"), VARL("ovf"))),
			SETG("c", sub ? INV(MSB(VARL("w"))) : MSB(VARL("w")))),
		SETG("ovc",
			ITE(AND(VARL("ovf"), INV(VARG("ovm"))),
				ITE(MSB(VARL("na")), ADD(VARG("ovc"), UN(6, 1)),
					SUB(VARG("ovc"), UN(6, 1))),
				VARG("ovc"))),
		c28x_nz_acc());
}

// T, the high half of XT, as a shift count masked to \p mask.
static RzILOpPure *c28x_t_count(ut32 bits, ut32 mask) {
	return UNSIGNED(bits, LOGAND(UNSIGNED(16, SHIFTR0(VARG("xt"), UN(6, 16))), UN(16, mask)));
}

/**
 * \brief Shift the \p bits wide local "sv" by the local count "sc" into "sr",
 * setting C to the last bit out, or clearing it for a zero count.
 * \param arith for a right shift: NULL fills with zeros, else an arithmetic
 * shift happens where this pure is true
 */
static RzILOpEffect *c28x_shift_var(ut32 bits, bool right, RzILOpPure *arith) {
	RzILOpPure *res;
	if (!right) {
		res = SHIFTL0(VARL("sv"), VARL("sc"));
	} else if (arith) {
		res = ITE(arith, SHIFTRA(VARL("sv"), VARL("sc")), SHIFTR0(VARL("sv"), VARL("sc")));
	} else {
		res = SHIFTR0(VARL("sv"), VARL("sc"));
	}
	RzILOpPure *out = right ? SUB(VARL("sc"), UN(bits, 1)) : SUB(UN(bits, bits), VARL("sc"));
	return SEQ2(SETL("sr", res),
		SETG("c", ITE(IS_ZERO(VARL("sc")), IL_FALSE, LSB(SHIFTR0(VARL("sv"), out)))));
}

/* lifters */

static bool c28x_is_acc(const C28xOperand *o) {
	return o->kind == C28X_OP_REG && o->reg == C28X_REG_ACC;
}

// N and Z of a 16-bit register operand after it was written.
static RzILOpEffect *c28x_nz16(const C28xOperand *o) {
	RzILOpPure *a = c28x_read16(o);
	RzILOpPure *b = c28x_read16(o);
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	return SEQ2(SETG("n", MSB(a)), SETG("z", IS_ZERO(b)));
}

/* products */

// T, the high half of XT, widened signed or unsigned to 32 bits.
static RzILOpPure *c28x_t32(bool sign) {
	RzILOpPure *t = UNSIGNED(16, SHIFTR0(VARG("xt"), UN(6, 16)));
	return sign ? SIGNED(32, t) : UNSIGNED(32, t);
}

// Load T, the high half of XT, keeping TL.
static RzILOpEffect *c28x_set_t(RzILOpPure *v16) {
	RzILOpPure *tl = LOGAND(VARG("xt"), UN(32, 0xffff));
	return SETG("xt", LOGOR(tl, SHIFTL0(UNSIGNED(32, v16), UN(6, 16))));
}

/**
 * \brief The local "pv" as the product shifter passes it (SPRU430F table 2-3).
 *
 * PM = 0 shifts left by one and PM = 1 not at all; PM = 2..7 shift right by
 * PM - 1, sign-extending, except that PM = 5 shifts left by four with AMODE set.
 */
static RzILOpPure *c28x_pm_shifted(void) {
	RzILOpPure *right = SHIFTRA(VARL("pv"), SUB(UNSIGNED(8, VARG("pm")), UN(8, 1)));
	RzILOpPure *amode4 = AND(EQ(VARG("pm"), UN(3, 5)), VARG("amode"));
	RzILOpPure *rest = ITE(amode4, SHIFTL0(VARL("pv"), UN(8, 4)), right);
	RzILOpPure *none = ITE(EQ(VARG("pm"), UN(3, 1)), VARL("pv"), rest);
	return ITE(IS_ZERO(VARG("pm")), SHIFTL0(VARL("pv"), UN(8, 1)), none);
}

// ACC +/-= P << PM, flagged and saturated as ADD and SUB are.
static RzILOpEffect *c28x_acc_p_pm(bool sub) {
	return SEQ2(SETL("pv", VARG("p")), c28x_acc_addsub(c28x_pm_shifted(), sub));
}

/**
 * \brief \p reg +/-= \p val as the unsigned ADDUL and SUBUL do.
 *
 * C, N and Z follow the result and V is sticky, but OVC counts the unsigned
 * carry or borrow whatever OVM says, and nothing saturates (SPRU430F "ADDUL").
 */
static RzILOpEffect *c28x_addsub_unsigned(const char *reg, RzILOpPure *val, bool sub) {
	RzILOpPure *res = sub ? SUB(VARL("uo"), VARL("uv")) : ADD(VARL("uo"), VARL("uv"));
	// the carry out of an add, or the borrow of a subtract
	RzILOpPure *cy = sub ? ULT(VARL("uo"), VARL("uv")) : ULT(VARL("un"), VARL("uo"));
	RzILOpPure *ovf;
	if (sub) {
		ovf = MSB(LOGAND(LOGXOR(VARL("uo"), VARL("uv")), LOGXOR(VARL("uo"), VARL("un"))));
	} else {
		ovf = MSB(LOGAND(LOGXOR(VARL("un"), VARL("uv")), LOGXOR(VARL("uo"), VARL("un"))));
	}
	RzILOpPure *ovc = sub ? SUB(VARG("ovc"), UN(6, 1)) : ADD(VARG("ovc"), UN(6, 1));
	return SEQ8(SETL("uo", VARG(reg)), SETL("uv", val), SETL("un", res), SETL("cy", cy),
		SETG(reg, VARL("un")),
		SETG("c", sub ? INV(VARL("cy")) : VARL("cy")),
		SEQ2(SETG("v", OR(VARG("v"), ovf)), SETG("ovc", ITE(VARL("cy"), ovc, VARG("ovc")))),
		SEQ2(SETG("n", MSB(VARL("un"))), SETG("z", IS_ZERO(VARL("un")))));
}

// Write a 16 x 16 or 32 x 32 result to P, or to ACC with N and Z.
static RzILOpEffect *c28x_product_to(const C28xOperand *d, RzILOpPure *v) {
	if (c28x_is_acc(d)) {
		return SEQ2(SETG("acc", v), c28x_nz_acc());
	}
	return SETG("p", v);
}

typedef enum {
	C28X_ALU_NONE = 0,
	C28X_ALU_ADD,
	C28X_ALU_SUB,
	C28X_ALU_AND,
	C28X_ALU_OR,
	C28X_ALU_XOR,
} C28xAlu;

// The 16-bit ALU operation of an ADD/SUB/AND/OR/XOR form.
static const C28xAlu c28x_alus[] = {
	[C28X_INS_ADD] = C28X_ALU_ADD,
	[C28X_INS_SUB] = C28X_ALU_SUB,
	[C28X_INS_AND] = C28X_ALU_AND,
	[C28X_INS_OR] = C28X_ALU_OR,
	[C28X_INS_XOR] = C28X_ALU_XOR,
};

static C28xAlu c28x_alu_of(C28xInsnId id) {
	return (size_t)id < RZ_ARRAY_SIZE(c28x_alus) ? c28x_alus[id] : C28X_ALU_NONE;
}

static bool c28x_is_ax(const C28xOperand *o) {
	return o->kind == C28X_OP_REG && (o->reg == C28X_REG_AL || o->reg == C28X_REG_AH);
}

// True for a loc16 that names @AL or @AH, whose stores set N and Z.
static bool c28x_at_ax(const C28xOperand *o) {
	return o->mode == C28X_AM_REG && (o->reg == C28X_REG_AL || o->reg == C28X_REG_AH);
}

// True for an operand the decoder resolved to an absolute code address.
static bool c28x_is_target(const C28xOperand *o) {
	return o->kind == C28X_OP_PMA || o->kind == C28X_OP_PCREL;
}

static bool c28x_is_reg(const C28xOperand *o, C28xReg r) {
	return o->kind == C28X_OP_REG && o->reg == r;
}

/**
 * \brief "res" = "a16" op "b16", flagged as the AX and loc16 forms are.
 *
 * N and Z follow the result. ADD and SUB also set C, which a borrow clears,
 * and V, sticky except for ADD loc16,#16bitSigned (SPRU430F).
 */
static RzILOpEffect *c28x_alu16(C28xAlu op, bool v_sticky) {
	RzILOpPure *res;
	switch (op) {
	case C28X_ALU_ADD: res = ADD(VARL("a16"), VARL("b16")); break;
	case C28X_ALU_SUB: res = SUB(VARL("a16"), VARL("b16")); break;
	case C28X_ALU_AND: res = LOGAND(VARL("a16"), VARL("b16")); break;
	case C28X_ALU_OR: res = LOGOR(VARL("a16"), VARL("b16")); break;
	case C28X_ALU_XOR: res = LOGXOR(VARL("a16"), VARL("b16")); break;
	default: return NULL;
	}
	RzILOpEffect *eff = SEQ3(SETL("res", res), SETG("n", MSB(VARL("res"))),
		SETG("z", IS_ZERO(VARL("res"))));
	if (op != C28X_ALU_ADD && op != C28X_ALU_SUB) {
		return eff;
	}
	const bool add = op == C28X_ALU_ADD;
	RzILOpPure *carry;
	RzILOpPure *ovf;
	if (add) {
		carry = ULT(VARL("res"), VARL("a16"));
		RzILOpPure *x = LOGXOR(VARL("res"), VARL("a16"));
		ovf = MSB(LOGAND(x, LOGXOR(VARL("res"), VARL("b16"))));
	} else {
		carry = INV(ULT(VARL("a16"), VARL("b16")));
		RzILOpPure *x = LOGXOR(VARL("a16"), VARL("b16"));
		ovf = MSB(LOGAND(x, LOGXOR(VARL("a16"), VARL("res"))));
	}
	return SEQ3(eff, SETG("c", carry), SETG("v", v_sticky ? OR(VARG("v"), ovf) : ovf));
}

/**
 * \brief The ADD/SUB/AND/OR/XOR forms beyond ACC with a memory operand: AX
 * and loc16 operands, shifted immediates, register-mode sources, IER and IFR.
 */
static RzILOpEffect *c28x_lift_alu_more(const C28xInsn *insn) {
	const C28xAlu op = c28x_alu_of(insn->id);
	if (op == C28X_ALU_NONE || insn->nops < 2) {
		return NULL;
	}
	const C28xOperand *d = &insn->ops[0];
	const C28xOperand *s = &insn->ops[1];
	const bool arith = op == C28X_ALU_ADD || op == C28X_ALU_SUB;
	if (c28x_is_acc(d) && s->kind == C28X_OP_IMM && insn->nops == 3) {
		// ACC,#16bit<<#n: ADD and SUB extend the constant by SXM, logic by zero
		RzILOpPure *k = UN(16, (ut64)s->imm & 0xffff);
		if (arith) {
			RzILOpPure *ext = ITE(VARG("sxm"), SIGNED(32, k), UNSIGNED(32, DUP(k)));
			return c28x_acc_addsub(c28x_apply_shift(insn, ext), op == C28X_ALU_SUB);
		}
		return c28x_acc_logic(insn->id, c28x_apply_shift(insn, UNSIGNED(32, k)));
	}
	if (c28x_is_acc(d) && s->kind == C28X_OP_MEM && s->mode == C28X_AM_REG && !arith) {
		const bool wide = s->wide;
		RzILOpPure *v;
		if (wide) {
			v = VARL(C28X_VAL_LOCAL);
		} else {
			v = c28x_apply_shift(insn, c28x_ext16(false));
		}
		return c28x_with_src(s, wide ? 32 : 16, c28x_acc_logic(insn->id, v));
	}
	const bool ie = c28x_is_reg(d, C28X_REG_IER) || c28x_is_reg(d, C28X_REG_IFR);
	if (ie && s->kind == C28X_OP_IMM &&
		(op == C28X_ALU_AND || op == C28X_ALU_OR)) {
		const char *r = d->reg == C28X_REG_IER ? "ier" : "ifr";
		RzILOpPure *k = UN(16, (ut64)s->imm & 0xffff);
		return SETG(r, op == C28X_ALU_AND ? LOGAND(VARG(r), k) : LOGOR(VARG(r), k));
	}
	if (c28x_is_ax(d)) {
		// AX op= loc16, or AND AX,loc16,#16bit: AX = [loc16] & constant
		const bool three = insn->nops == 3 && insn->ops[2].kind == C28X_OP_IMM;
		RzILOpPure *a = three ? VARL(C28X_VAL_LOCAL) : c28x_read16(d);
		const ut64 k = three ? (ut64)insn->ops[2].imm & 0xffff : 0;
		RzILOpPure *b = three ? UN(16, k) : VARL(C28X_VAL_LOCAL);
		RzILOpEffect *wr = c28x_write16(d, VARL("res"), false);
		if (!a || !wr) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			rz_il_op_effect_free(wr);
			return NULL;
		}
		RzILOpEffect *tail = SEQ2(c28x_alu16(op, true), wr);
		return c28x_with_src(s, 16, SEQ3(SETL("a16", a), SETL("b16", b), tail));
	}
	if (c28x_is_ax(s) || s->kind == C28X_OP_IMM) {
		// loc16 op= AX or loc16 op= #16bit, read-modify-write
		const bool imm = s->kind == C28X_OP_IMM;
		RzILOpPure *b = imm ? UN(16, (ut64)s->imm & 0xffff) : c28x_read16(s);
		if (!b) {
			return NULL;
		}
		RzILOpEffect *alu = c28x_alu16(op, !imm);
		return c28x_rmw16(d, SEQ3(SETL("a16", VARL(C28X_VAL_LOCAL)), SETL("b16", b), alu));
	}
	return NULL;
}

// LSL ACC,T and LSL AX,T shift by T(3:0); a zero count clears C.
static RzILOpEffect *c28x_lift_shift_t(const C28xInsn *insn) {
	if (insn->id != C28X_INS_LSL || insn->nops != 2 ||
		!c28x_is_reg(&insn->ops[1], C28X_REG_T)) {
		return NULL;
	}
	if (c28x_is_acc(&insn->ops[0])) {
		return SEQ5(SETL("sv", VARG("acc")), SETL("sc", c28x_t_count(32, 0xf)),
			c28x_shift_var(32, false, NULL), SETG("acc", VARL("sr")), c28x_nz_acc());
	}
	RzILOpPure *cur = c28x_read16(&insn->ops[0]);
	RzILOpEffect *wr = c28x_write16(&insn->ops[0], VARL("sr"), false);
	RzILOpEffect *nz = c28x_nz16(&insn->ops[0]);
	if (!cur || !wr || !nz) {
		rz_il_op_pure_free(cur);
		rz_il_op_effect_free(wr);
		rz_il_op_effect_free(nz);
		return NULL;
	}
	return SEQ5(SETL("sv", cur), SETL("sc", c28x_t_count(16, 0xf)),
		c28x_shift_var(16, false, NULL), wr, nz);
}

// N and Z of a value stored to @AL or @AH; other locations leave them alone.
static RzILOpEffect *c28x_nz_if_ax(const C28xOperand *o, const char *local) {
	if (!c28x_at_ax(o)) {
		return NOP();
	}
	return SEQ2(SETG("n", MSB(VARL(local))), SETG("z", IS_ZERO(VARL(local))));
}

// Store \p val to the 16-bit location \p o, setting N and Z for @AX.
static RzILOpEffect *c28x_store16_nz(const C28xOperand *o, RzILOpPure *val) {
	RzILOpEffect *st = c28x_store16(o, VARL("mv"));
	if (!st) {
		rz_il_op_pure_free(val);
		return NULL;
	}
	return SEQ3(SETL("mv", val), st, c28x_nz_if_ax(o, "mv"));
}

/**
 * \brief Store \p val to the first operand when the condition holds.
 *
 * The addressing mode's pointer update happens either way. N and Z are set
 * only for a stored @AX or @ACC, and a condition that tests V clears it
 * (SPRU430F "MOV loc16,AX,COND").
 */
static RzILOpEffect *c28x_lift_store_cond(const C28xInsn *insn, ut32 bits, RzILOpPure *val) {
	const C28xOperand *o = &insn->ops[0];
	RzILOpPure *c = c28x_cond(insn->cond);
	if (!c || !val) {
		rz_il_op_pure_free(c);
		rz_il_op_pure_free(val);
		return NULL;
	}
	RzILOpEffect *st;
	RzILOpEffect *nz = NOP();
	if (c28x_is_mem(o)) {
		st = c28x_ea_store(VARL("mv"));
	} else {
		const char *r = bits == 32 ? c28x_reg32(o) : NULL;
		st = r ? SETG(r, VARL("mv")) : c28x_write16(o, VARL("mv"), false);
		const bool flagged = bits == 32 ? o->reg == C28X_REG_ACC
						: (o->reg == C28X_REG_AL || o->reg == C28X_REG_AH);
		if (flagged) {
			rz_il_op_effect_free(nz);
			nz = SEQ2(SETG("n", MSB(VARL("mv"))), SETG("z", IS_ZERO(VARL("mv"))));
		}
	}
	if (!st) {
		rz_il_op_pure_free(c);
		rz_il_op_pure_free(val);
		rz_il_op_effect_free(nz);
		return NULL;
	}
	const bool tests_v = insn->cond == C28X_COND_OV || insn->cond == C28X_COND_NOV;
	RzILOpEffect *vclr = tests_v ? SETG("v", IL_FALSE) : NOP();
	RzILOpEffect *act = BRANCH(VARL("cc"), SEQ2(st, nz), NOP());
	RzILOpEffect *body = SEQ4(SETL("mv", val), SETL("cc", c), vclr, act);
	return c28x_is_mem(o) ? c28x_with_ea(o, body) : body;
}

/**
 * \brief The MOV forms the generic register/memory lifting leaves out:
 * constants, *(0:16bit), OVC, IER, PM, shifted ACC and conditional stores.
 */
static RzILOpEffect *c28x_lift_mov_more(const C28xInsn *insn) {
	if (insn->id != C28X_INS_MOV || insn->nops < 2) {
		return NULL;
	}
	const C28xOperand *d = &insn->ops[0];
	const C28xOperand *s = &insn->ops[1];
	if (insn->nops == 3 && insn->ops[2].kind == C28X_OP_COND) {
		return c28x_lift_store_cond(insn, 16, c28x_read16(s));
	}
	if (c28x_is_acc(d) && s->kind == C28X_OP_IMM) {
		// MOV ACC,#16bit<<#n extends the constant by SXM
		RzILOpPure *k = UN(16, (ut64)s->imm & 0xffff);
		RzILOpPure *ext = ITE(VARG("sxm"), SIGNED(32, k), UNSIGNED(32, DUP(k)));
		return SEQ2(SETG("acc", c28x_apply_shift(insn, ext)), c28x_nz_acc());
	}
	if (c28x_is_acc(d) && s->kind == C28X_OP_MEM) {
		// MOV ACC,loc16 with any shift, sign-extended by SXM
		RzILOpEffect *ld = SETG("acc", c28x_apply_shift(insn, c28x_ext16(true)));
		return c28x_with_src(s, 16, SEQ2(ld, c28x_nz_acc()));
	}
	if (insn->nops == 3 && c28x_is_acc(s) && insn->ops[2].kind == C28X_OP_SHIFT) {
		// MOV loc16,ACC<<#n keeps the low word of the shifted ACC
		RzILOpPure *v = SHIFTL0(VARG("acc"), UN(6, (ut8)insn->ops[2].imm));
		return c28x_store16_nz(d, UNSIGNED(16, v));
	}
	if (insn->nops != 2) {
		return NULL;
	}
	const bool at_ax = c28x_at_ax(d);
	if (s->kind == C28X_OP_IMM && d->kind == C28X_OP_MEM && (c28x_is_mem(d) || at_ax)) {
		// MOV loc16,#16bit; a register other than AX already lifts as a move
		return c28x_store16_nz(d, UN(16, (ut64)s->imm & 0xffff));
	}
	if (d->kind == C28X_OP_DMA) {
		RzILOpPure *addr = UN(C28X_MEM_ADDR_BITS, (ut64)d->imm);
		RzILOpEffect *st = STOREW(addr, VARL(C28X_VAL_LOCAL));
		return c28x_with_src(s, 16, st);
	}
	if (s->kind == C28X_OP_DMA) {
		return c28x_store16_nz(d, LOADW(16, UN(C28X_MEM_ADDR_BITS, (ut64)s->imm)));
	}
	if (c28x_is_reg(d, C28X_REG_OVC)) {
		// OVC takes bits 15:10 of the location
		RzILOpPure *hi = SHIFTR0(VARL(C28X_VAL_LOCAL), UN(4, 10));
		return c28x_with_src(s, 16, SETG("ovc", UNSIGNED(6, hi)));
	}
	if (c28x_is_reg(s, C28X_REG_OVC)) {
		// ...and is stored back to bits 15:10, with bits 9:0 cleared
		return c28x_store16_nz(d, SHIFTL0(UNSIGNED(16, VARG("ovc")), UN(4, 10)));
	}
	if (c28x_is_reg(d, C28X_REG_IER)) {
		return c28x_with_src(s, 16, SETG("ier", VARL(C28X_VAL_LOCAL)));
	}
	if (c28x_is_reg(s, C28X_REG_IER)) {
		return c28x_store16_nz(d, VARG("ier"));
	}
	if (c28x_is_reg(s, C28X_REG_P)) {
		// the low word of P << PM
		RzILOpEffect *st = c28x_store16_nz(d, UNSIGNED(16, c28x_pm_shifted()));
		return st ? SEQ2(SETL("pv", VARG("p")), st) : NULL;
	}
	if (c28x_is_reg(d, C28X_REG_PM) && s->kind == C28X_OP_REG) {
		RzILOpPure *ax = c28x_read16(s);
		return ax ? SETG("pm", UNSIGNED(3, ax)) : NULL;
	}
	return NULL;
}

/**
 * \brief MPY, MPYU and MPYXU into P or ACC, and MPYA and MPYS.
 *
 * MPYA and MPYS first add or subtract the previous product, shifted by PM, to
 * ACC. Only a product into ACC sets N and Z.
 */
static RzILOpEffect *c28x_lift_mpy(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 3) {
		return NULL;
	}
	const C28xInsnId id = insn->id;
	const bool by_t = c28x_is_reg(&insn->ops[1], C28X_REG_T);
	const C28xOperand *src = by_t ? &insn->ops[2] : &insn->ops[1];
	RzILOpPure *prod;
	if (by_t) {
		// MPYU is unsigned throughout, MPYXU takes T signed and loc16 unsigned
		RzILOpPure *s = id == C28X_INS_MPYU || id == C28X_INS_MPYXU
			? UNSIGNED(32, VARL(C28X_VAL_LOCAL))
			: SIGNED(32, VARL(C28X_VAL_LOCAL));
		prod = MUL(c28x_t32(id != C28X_INS_MPYU), s);
	} else if (insn->ops[2].kind == C28X_OP_IMM) {
		RzILOpPure *k = SIGNED(32, UN(16, (ut64)insn->ops[2].imm & 0xffff));
		prod = MUL(SIGNED(32, VARL(C28X_VAL_LOCAL)), k);
	} else {
		return NULL;
	}
	RzILOpEffect *body;
	if (id == C28X_INS_MPYA || id == C28X_INS_MPYS) {
		body = SEQ2(c28x_acc_p_pm(id == C28X_INS_MPYS), SETG("p", prod));
	} else {
		body = c28x_product_to(&insn->ops[0], prod);
	}
	return c28x_with_src(src, 16, body);
}

// SQRA and SQRS: ACC +/-= P << PM, then T = [loc16] and P = T * T.
static RzILOpEffect *c28x_lift_sqr(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 1) {
		return NULL;
	}
	RzILOpPure *sq = MUL(SIGNED(32, VARL(C28X_VAL_LOCAL)), SIGNED(32, VARL(C28X_VAL_LOCAL)));
	RzILOpEffect *body = SEQ3(c28x_acc_p_pm(insn->id == C28X_INS_SQRS),
		c28x_set_t(VARL(C28X_VAL_LOCAL)), SETG("p", sq));
	return c28x_with_src(&insn->ops[0], 16, body);
}

/**
 * \brief MOVA, MOVS, MOVP and MOVAD T,loc16: accumulate P << PM, load T.
 *
 * MOVP loads ACC with the shifted P instead, and MOVAD also copies the word to
 * the next address, as DMOV does.
 */
static RzILOpEffect *c28x_lift_movt(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 2) {
		return NULL;
	}
	const C28xInsnId id = insn->id;
	const C28xOperand *src = &insn->ops[1];
	RzILOpEffect *acc;
	if (id == C28X_INS_MOVP) {
		acc = SEQ3(SETL("pv", VARG("p")), SETG("acc", c28x_pm_shifted()), c28x_nz_acc());
	} else {
		acc = c28x_acc_p_pm(id == C28X_INS_MOVS);
	}
	RzILOpEffect *body = SEQ2(acc, c28x_set_t(VARL(C28X_VAL_LOCAL)));
	if (id != C28X_INS_MOVAD) {
		return c28x_with_src(src, 16, body);
	}
	if (!c28x_is_mem(src)) {
		rz_il_op_effect_free(body);
		return NULL;
	}
	RzILOpPure *next = ADD(VARL(C28X_EA_LOCAL), UN(C28X_MEM_ADDR_BITS, 1));
	RzILOpEffect *copy = STOREW(c28x_byte(next), VARL(C28X_VAL_LOCAL));
	return c28x_with_ea(src, SEQ3(SETL(C28X_VAL_LOCAL, c28x_ea_load(16)), body, copy));
}

// ADDUL and SUBUL add or subtract a loc32 to ACC or P, unsigned.
static RzILOpEffect *c28x_lift_addul(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 2) {
		return NULL;
	}
	const char *dst = c28x_reg32(&insn->ops[0]);
	if (!dst) {
		return NULL;
	}
	const bool sub = insn->id == C28X_INS_SUBUL;
	RzILOpEffect *op = c28x_addsub_unsigned(dst, VARL(C28X_VAL_LOCAL), sub);
	return c28x_with_src(&insn->ops[1], 32, op);
}

typedef enum {
	C28X_MACC_NONE = 0, ///< P or ACC just takes the product
	C28X_MACC_ADD_U, ///< ACC += P, unsigned, first
	C28X_MACC_SUB_U, ///< ACC -= P, unsigned, first
	C28X_MACC_ADD_PM, ///< ACC += P << PM first
	C28X_MACC_SUB_PM, ///< ACC -= P << PM first
} C28xMacc;

typedef struct {
	bool valid;
	bool high; ///< keep bits 63:32 of the product rather than the low word
	bool sign_xt; ///< XT is signed
	bool sign_src; ///< the loc32 is signed
	C28xMacc acc; ///< what happens to ACC before P takes the product
} C28xMul32;

// The 32 x 32 multiplies of XT by a loc32 (SPRU430F "IMPYL" to "QMPYSL").
static const C28xMul32 c28x_mul32s[] = {
	[C28X_INS_IMPYL] = { true, false, true, true, C28X_MACC_NONE },
	[C28X_INS_IMPYXUL] = { true, false, true, false, C28X_MACC_NONE },
	[C28X_INS_QMPYL] = { true, true, true, true, C28X_MACC_NONE },
	[C28X_INS_QMPYUL] = { true, true, false, false, C28X_MACC_NONE },
	[C28X_INS_QMPYXUL] = { true, true, true, false, C28X_MACC_NONE },
	[C28X_INS_IMPYAL] = { true, false, true, true, C28X_MACC_ADD_U },
	[C28X_INS_IMPYSL] = { true, false, true, true, C28X_MACC_SUB_U },
	[C28X_INS_QMPYAL] = { true, true, true, true, C28X_MACC_ADD_PM },
	[C28X_INS_QMPYSL] = { true, true, true, true, C28X_MACC_SUB_PM },
};

/**
 * \brief The 32 x 32 multiplies, by the properties in c28x_mul32s.
 *
 * Into P, the low word is taken from the 64-bit product shifted by PM, which
 * picks a 32-bit window of its lower 38 bits (SPRU430F "IMPYL P,XT,loc32");
 * into ACC it is not shifted, and N and Z are set.
 */
static RzILOpEffect *c28x_lift_mpy32(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	const C28xInsnId id = insn->id;
	if ((size_t)id >= RZ_ARRAY_SIZE(c28x_mul32s) || !c28x_mul32s[id].valid || insn->nops != 3) {
		return NULL;
	}
	const C28xMul32 *m = &c28x_mul32s[id];
	const C28xOperand *d = &insn->ops[0];
	RzILOpPure *a = m->sign_xt ? SIGNED(64, VARG("xt")) : UNSIGNED(64, VARG("xt"));
	RzILOpPure *b = m->sign_src ? SIGNED(64, VARL(C28X_VAL_LOCAL))
				    : UNSIGNED(64, VARL(C28X_VAL_LOCAL));
	RzILOpPure *word;
	if (m->high) {
		word = UNSIGNED(32, SHIFTR0(VARL("pr"), UN(8, 32)));
	} else if (c28x_is_acc(d)) {
		word = UNSIGNED(32, VARL("pr"));
	} else {
		word = UNSIGNED(32, c28x_pm_shifted());
	}
	RzILOpEffect *acc;
	switch (m->acc) {
	case C28X_MACC_ADD_U: acc = c28x_addsub_unsigned("acc", VARG("p"), false); break;
	case C28X_MACC_SUB_U: acc = c28x_addsub_unsigned("acc", VARG("p"), true); break;
	case C28X_MACC_ADD_PM: acc = c28x_acc_p_pm(false); break;
	case C28X_MACC_SUB_PM: acc = c28x_acc_p_pm(true); break;
	default: acc = NOP(); break;
	}
	// the product is latched in "pv" too, for the PM window of the low word
	RzILOpEffect *body = SEQ4(acc, SETL("pr", MUL(a, b)), SETL("pv", VARL("pr")),
		c28x_product_to(d, word));
	return c28x_with_src(&insn->ops[2], 32, body);
}

// MPYB P or ACC,T,#8bit: signed T times a zero-extended constant.
static RzILOpEffect *c28x_lift_mpyb(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 3 || insn->ops[2].kind != C28X_OP_IMM) {
		return NULL;
	}
	RzILOpPure *prod = MUL(c28x_t32(true), UN(32, (ut64)insn->ops[2].imm & 0xff));
	return c28x_product_to(&insn->ops[0], prod);
}

// MOVH loc16,P and MOVH loc16,ACC<<n store the high word of the shifted value.
static RzILOpEffect *c28x_lift_movh(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops < 2) {
		return NULL;
	}
	const C28xOperand *d = &insn->ops[0];
	RzILOpPure *v;
	if (c28x_is_reg(&insn->ops[1], C28X_REG_P)) {
		v = c28x_pm_shifted();
	} else if (c28x_is_acc(&insn->ops[1]) && insn->nops == 3 &&
		insn->ops[2].kind == C28X_OP_SHIFT) {
		v = SHIFTL0(VARL("pv"), UN(6, (ut8)insn->ops[2].imm));
	} else {
		return NULL;
	}
	RzILOpEffect *st = c28x_store16_nz(d, UNSIGNED(16, SHIFTR0(v, UN(6, 16))));
	if (!st) {
		return NULL;
	}
	const bool from_p = c28x_is_reg(&insn->ops[1], C28X_REG_P);
	return SEQ2(SETL("pv", from_p ? VARG("p") : VARG("acc")), st);
}

/* comparisons, division steps and bit operations */

/**
 * \brief MAX and MIN AX,loc16, MAXL and MINL ACC,loc32, all signed.
 *
 * N and Z describe the comparison rather than the result, V is set when the
 * value is replaced and is never cleared, and the 32-bit forms also set C from
 * the borrow of ACC - [loc32] (SPRU430F "MAX AX,loc16", "MAXL ACC,loc32").
 */
static RzILOpEffect *c28x_lift_minmax(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 2) {
		return NULL;
	}
	const C28xInsnId id = insn->id;
	const bool wide = id == C28X_INS_MAXL || id == C28X_INS_MINL;
	const bool max = id == C28X_INS_MAX || id == C28X_INS_MAXL;
	const C28xOperand *d = &insn->ops[0];
	RzILOpPure *cur = NULL;
	RzILOpEffect *wr = NULL;
	if (!wide) {
		cur = c28x_read16(d);
		wr = c28x_write16(d, VARL(C28X_VAL_LOCAL), false);
	} else if (c28x_is_acc(d)) {
		cur = VARG("acc");
		wr = SETG("acc", VARL(C28X_VAL_LOCAL));
	}
	if (!cur || !wr) {
		rz_il_op_pure_free(cur);
		rz_il_op_effect_free(wr);
		return NULL;
	}
	RzILOpPure *lower = SLT(VARL("mo"), VARL(C28X_VAL_LOCAL));
	RzILOpPure *higher = SLT(VARL(C28X_VAL_LOCAL), VARL("mo"));
	RzILOpPure *below = SLT(VARL("mo"), VARL(C28X_VAL_LOCAL));
	RzILOpPure *equal = EQ(VARL("mo"), VARL(C28X_VAL_LOCAL));
	RzILOpEffect *flags = SEQ3(SETG("n", below), SETG("z", equal),
		SETG("v", OR(VARG("v"), VARL("rp"))));
	if (wide) {
		flags = SEQ2(flags, SETG("c", INV(ULT(VARL("mo"), VARL(C28X_VAL_LOCAL)))));
	}
	RzILOpPure *repl = max ? lower : higher;
	rz_il_op_pure_free(max ? higher : lower);
	RzILOpEffect *body = SEQ4(SETL("mo", cur), SETL("rp", repl), flags,
		BRANCH(VARL("rp"), wr, NOP()));
	return c28x_with_src(&insn->ops[1], wide ? 32 : 16, body);
}

/**
 * \brief "rs" = ACC - [loc32], flagged, counted and saturated as SUBL is.
 *
 * SUBRL stores the difference back to its loc32 and leaves ACC alone, so the
 * flags follow the stored value, as SUBR's do; SPRU430F's SUBRL flag text
 * names ACC, copied from SUBL.
 */
static RzILOpEffect *c28x_rsub32(void) {
	RzILOpPure *diff = LOGXOR(VARL("oa"), VARL("av"));
	RzILOpPure *ovf = MSB(LOGAND(diff, LOGXOR(VARL("oa"), VARL("na"))));
	RzILOpPure *sat = ITE(MSB(VARL("oa")), UN(32, 0x80000000), UN(32, 0x7fffffff));
	RzILOpPure *up = ADD(VARG("ovc"), UN(6, 1));
	RzILOpPure *ovc = ITE(MSB(VARL("na")), up, SUB(VARG("ovc"), UN(6, 1)));
	RzILOpPure *counted = AND(VARL("ovf"), INV(VARG("ovm")));
	RzILOpPure *nb = INV(ULT(VARL("oa"), VARL("av")));
	return SEQ8(SETL("oa", VARG("acc")), SETL("av", VARL(C28X_VAL_LOCAL)),
		SETL("na", SUB(VARL("oa"), VARL("av"))), SETL("ovf", ovf),
		SETL("rs", ITE(AND(VARG("ovm"), VARL("ovf")), sat, VARL("na"))),
		SEQ2(SETG("v", OR(VARG("v"), VARL("ovf"))), SETG("c", nb)),
		SETG("ovc", ITE(counted, ovc, VARG("ovc"))),
		SEQ2(SETG("n", MSB(VARL("rs"))), SETG("z", IS_ZERO(VARL("rs")))));
}

// SUBR loc16,AX and SUBRL loc32,ACC: the location takes AX or ACC minus itself.
static RzILOpEffect *c28x_lift_subr(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 2) {
		return NULL;
	}
	const C28xOperand *o = &insn->ops[0];
	if (insn->id == C28X_INS_SUBR) {
		RzILOpPure *ax = c28x_read16(&insn->ops[1]);
		if (!ax) {
			return NULL;
		}
		RzILOpEffect *alu = c28x_alu16(C28X_ALU_SUB, true);
		RzILOpEffect *tail = SEQ2(SETL("b16", VARL(C28X_VAL_LOCAL)), alu);
		return c28x_rmw16(o, SEQ2(SETL("a16", ax), tail));
	}
	if (c28x_is_mem(o)) {
		RzILOpEffect *load = SETL(C28X_VAL_LOCAL, c28x_ea_load(32));
		return c28x_with_ea(o, SEQ3(load, c28x_rsub32(), c28x_ea_store(VARL("rs"))));
	}
	const char *r = c28x_reg32(o);
	if (!r) {
		return NULL;
	}
	return SEQ3(SETL(C28X_VAL_LOCAL, VARG(r)), c28x_rsub32(), SETG(r, VARL("rs")));
}

/**
 * \brief SUBCU and SUBCUL, one step of unsigned division.
 *
 * SPRU430F prints SUBCU's test as temp > 0, but the division it documents only
 * works with temp >= 0, as SUBCUL has it: an exact multiple must still subtract.
 * C is cleared by the borrow of the trial subtraction; V and OVC are untouched.
 */
static RzILOpEffect *c28x_lift_subcu(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 2) {
		return NULL;
	}
	const bool wide = insn->id == C28X_INS_SUBCUL;
	RzILOpPure *acc2 = SHIFTL0(UNSIGNED(33, VARG("acc")), UN(6, 1));
	RzILOpPure *src = UNSIGNED(33, VARL(C28X_VAL_LOCAL));
	RzILOpPure *tmp;
	RzILOpEffect *take;
	RzILOpEffect *skip;
	if (wide) {
		// ACC:P shifts as one 64-bit value; P(31) enters the trial subtraction
		RzILOpPure *p31 = UNSIGNED(33, SHIFTR0(VARG("p"), UN(6, 31)));
		tmp = SUB(ADD(acc2, p31), src);
		RzILOpPure *pq = ADD(SHIFTL0(VARG("p"), UN(6, 1)), UN(32, 1));
		take = SEQ2(SETG("acc", UNSIGNED(32, VARL("tq"))), SETG("p", pq));
		RzILOpPure *carry = SHIFTR0(VARG("p"), UN(6, 31));
		skip = SEQ2(SETG("acc", LOGOR(SHIFTL0(VARG("acc"), UN(6, 1)), carry)),
			SETG("p", SHIFTL0(VARG("p"), UN(6, 1))));
	} else {
		tmp = SUB(acc2, SHIFTL0(src, UN(6, 16)));
		take = SETG("acc", ADD(UNSIGNED(32, VARL("tq")), UN(32, 1)));
		skip = SETG("acc", SHIFTL0(VARG("acc"), UN(6, 1)));
	}
	RzILOpEffect *body = SEQ4(SETL("tq", tmp), SETG("c", INV(MSB(VARL("tq")))),
		BRANCH(MSB(VARL("tq")), skip, take), c28x_nz_acc());
	return c28x_with_src(&insn->ops[1], wide ? 32 : 16, body);
}

// ZALR ACC,loc16 loads AH and puts 0x8000 in AL, for rounding.
static RzILOpEffect *c28x_lift_zalr(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 2) {
		return NULL;
	}
	RzILOpPure *hi = SHIFTL0(UNSIGNED(32, VARL(C28X_VAL_LOCAL)), UN(6, 16));
	RzILOpEffect *ld = SETG("acc", LOGOR(hi, UN(32, 0x8000)));
	return c28x_with_src(&insn->ops[1], 16, SEQ2(ld, c28x_nz_acc()));
}

/**
 * \brief CSB ACC: T takes the number of leading sign bits less one, TC the sign.
 *
 * XORing ACC with its sign turns the sign bits to zeros, so the count is the
 * position of the highest set bit below bit 31.
 */
static RzILOpEffect *c28x_lift_csb(RZ_UNUSED const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	RzILOpPure *t = UN(16, 31);
	for (ut32 b = 0; b < 31; b++) {
		RzILOpPure *set = INV(IS_ZERO(LOGAND(VARL("cx"), UN(32, 1u << b))));
		t = ITE(set, UN(16, 30 - b), t);
	}
	RzILOpPure *x = LOGXOR(VARG("acc"), SHIFTRA(VARG("acc"), UN(6, 31)));
	return SEQ4(SETL("cx", x), c28x_set_t(t), SETG("tc", MSB(VARG("acc"))), c28x_nz_acc());
}

// NEG64 ACC:P, which saturates like NEG ACC (SPRU430F "NEG64 ACC:P").
static RzILOpEffect *c28x_lift_neg64(RZ_UNUSED const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	RzILOpPure *min = EQ(VARL("s64"), UN(64, 0x8000000000000000ULL));
	RzILOpPure *top = UN(64, 0x7fffffffffffffffULL);
	RzILOpPure *sat = ITE(VARG("ovm"), top, UN(64, 0x8000000000000000ULL));
	RzILOpPure *was_min = EQ(VARL("s64"), UN(64, 0x8000000000000000ULL));
	return SEQ6(SETL("s64", APPEND(VARG("acc"), VARG("p"))),
		SETL("r64", ITE(min, sat, NEG(VARL("s64")))),
		SETG("acc", UNSIGNED(32, SHIFTR0(VARL("r64"), UN(7, 32)))),
		SETG("p", UNSIGNED(32, VARL("r64"))),
		SEQ2(SETG("v", OR(VARG("v"), was_min)), SETG("c", IS_ZERO(VARL("r64")))),
		SEQ2(SETG("n", MSB(VARL("r64"))), SETG("z", IS_ZERO(VARL("r64")))));
}

/**
 * \brief CMP64 ACC:P compares the 64-bit value with zero, then clears V.
 *
 * With V set, the preceding operation overflowed into bit 63 and N takes the
 * opposite of ACC(31). SPRU430F's Z test names 0x8000 0000 0000 0000, but the
 * comparison is with zero, as its description says.
 */
static RzILOpEffect *c28x_lift_cmp64(RZ_UNUSED const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	return SEQ3(SETG("n", XOR(VARG("v"), MSB(VARG("acc")))),
		SETG("z", AND(IS_ZERO(VARG("acc")), IS_ZERO(VARG("p")))), SETG("v", IL_FALSE));
}

// SPM: the opcode's low three bits are the PM value itself.
static RzILOpEffect *c28x_lift_spm(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	return SETG("pm", UN(3, (insn->word >> 16) & 7));
}

// FLIP AX reverses the bit order of AX.
static RzILOpEffect *c28x_lift_flip(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	RzILOpPure *cur = insn->nops == 1 ? c28x_read16(&insn->ops[0]) : NULL;
	RzILOpEffect *wr = cur ? c28x_write16(&insn->ops[0], c28x_rev16("fx"), false) : NULL;
	RzILOpEffect *nz = wr ? c28x_nz16(&insn->ops[0]) : NULL;
	if (!nz) {
		rz_il_op_pure_free(cur);
		rz_il_op_effect_free(wr);
		return NULL;
	}
	return SEQ3(SETL("fx", cur), wr, nz);
}

// MOVDL XT,loc32 loads XT and copies it two words up, for 32-bit delay lines.
static RzILOpEffect *c28x_lift_movdl(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 2 || !c28x_is_mem(&insn->ops[1])) {
		return NULL;
	}
	RzILOpPure *next = ADD(VARL(C28X_EA_LOCAL), UN(C28X_MEM_ADDR_BITS, 2));
	RzILOpEffect *body = SEQ3(SETL(C28X_VAL_LOCAL, c28x_ea_load(32)),
		SETG("xt", VARL(C28X_VAL_LOCAL)), STOREW(c28x_byte(next), VARL(C28X_VAL_LOCAL)));
	return c28x_with_ea(&insn->ops[1], body);
}

// Prog[*XAR7]: C28x memory is unified, so program space is the data space.
static RzILOpPure *c28x_prog_xar7(void) {
	return c28x_byte(LOGAND(VARG("xar7"), UN(32, 0x3fffff)));
}

// PREAD loc16,*XAR7 and PWRITE *XAR7,loc16.
static RzILOpEffect *c28x_lift_pread(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 2) {
		return NULL;
	}
	if (insn->id == C28X_INS_PREAD) {
		return c28x_store16_nz(&insn->ops[0], LOADW(16, c28x_prog_xar7()));
	}
	return c28x_with_src(&insn->ops[1], 16, STOREW(c28x_prog_xar7(), VARL(C28X_VAL_LOCAL)));
}

/* C2xLP compatibility */

// A 16-bit C2xLP program address in page 0x3F, as a byte address.
static RzILOpPure *c28x_page3f(RzILOpPure *low16) {
	return c28x_byte(LOGOR(UN(32, 0x3f0000), UNSIGNED(32, low16)));
}

// Set ARP from a C2xLP branch's ARPn operand, or do nothing without one.
static RzILOpEffect *c28x_set_arpn(const C28xInsn *insn) {
	for (ut8 i = 0; i < insn->nops; i++) {
		if (c28x_is_reg(&insn->ops[i], C28X_REG_ARP)) {
			return SETG("arp", UN(3, (ut64)insn->ops[i].imm & 7));
		}
	}
	return NOP();
}

// A condition that tests V clears it, for the conditional branches and returns.
static RzILOpEffect *c28x_v_tested(ut8 cond) {
	return cond == C28X_COND_OV || cond == C28X_COND_NOV ? SETG("v", IL_FALSE) : NOP();
}

/**
 * \brief XB and XCALL in their three forms.
 *
 * C2xLP code runs in the top 64K of program space, page 0x3F: targets and
 * return addresses are 16 bits there, a return address is pushed as one word,
 * and even an XB not taken continues in page 0x3F (SPRU430F "XB pma,COND").
 */
static RzILOpEffect *c28x_lift_xbranch(const C28xInsn *insn, ut64 pc) {
	const bool call = insn->id == C28X_INS_XCALL;
	const ut64 next = (pc + insn->size) / C28X_WORD_BYTES;
	RzILOpPure *target;
	if (insn->nops >= 1 && c28x_is_target(&insn->ops[0])) {
		target = UN(32, (ut64)insn->ops[0].imm);
	} else if (insn->nops == 1 && c28x_is_reg(&insn->ops[0], C28X_REG_AL)) {
		target = c28x_page3f(UNSIGNED(16, VARG("acc")));
	} else {
		return NULL;
	}
	RzILOpEffect *push = NOP();
	if (call) {
		push = SEQ2(STOREW(c28x_byte(VARG("sp")), UN(16, next & 0xffff)),
			SETG("sp", ADD(VARG("sp"), UN(16, 1))));
	}
	RzILOpEffect *go = SEQ3(push, c28x_set_arpn(insn), JMP(target));
	if (insn->cond == C28X_COND_UNC) {
		return go;
	}
	RzILOpPure *c = c28x_cond(insn->cond);
	if (!c) {
		rz_il_op_effect_free(go);
		return NULL;
	}
	RzILOpEffect *stay = NOP();
	if (!call) {
		stay = JMP(UN(32, (0x3f0000 | (next & 0xffff)) * C28X_WORD_BYTES));
	}
	return SEQ3(SETL("cc", c), c28x_v_tested(insn->cond), BRANCH(VARL("cc"), go, stay));
}

// XRETC COND and XRET pop a one-word return address in page 0x3F.
static RzILOpEffect *c28x_lift_xret(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	RzILOpPure *ra = LOADW(16, c28x_byte(VARG("sp")));
	RzILOpEffect *ret = SEQ2(SETG("sp", SUB(VARG("sp"), UN(16, 1))), JMP(c28x_page3f(ra)));
	if (insn->cond == C28X_COND_UNC) {
		return ret;
	}
	RzILOpPure *c = c28x_cond(insn->cond);
	if (!c) {
		rz_il_op_effect_free(ret);
		return NULL;
	}
	return SEQ3(SETL("cc", c), c28x_v_tested(insn->cond), BRANCH(VARL("cc"), ret, NOP()));
}

/**
 * \brief XBANZ pma,*ind{,ARPn}: branch while AR[ARP] is non-zero.
 *
 * The test reads AR[ARP] first; the indirect mode then updates XAR[ARP] and
 * the optional ARPn takes effect last (SPRU430F "XBANZ").
 */
static RzILOpEffect *c28x_lift_xbanz(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops < 2 || !c28x_is_target(&insn->ops[0]) || insn->ops[1].kind != C28X_OP_MEM) {
		return NULL;
	}
	RzILOpEffect *upd = c28x_arp_update(&insn->ops[1]);
	RzILOpPure *nz = INV(IS_ZERO(UNSIGNED(16, c28x_arp_xar())));
	RzILOpEffect *jump = BRANCH(VARL("bz"), JMP(UN(32, (ut64)insn->ops[0].imm)), NOP());
	return SEQ4(SETL("bz", nz), upd ? upd : NOP(), c28x_set_arpn(insn), jump);
}

// XPREAD loc16,*(pma), XPREAD loc16,*AL and XPWRITE *AL,loc16, in page 0x3F.
static RzILOpEffect *c28x_lift_xpread(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 2) {
		return NULL;
	}
	if (insn->id == C28X_INS_XPWRITE) {
		RzILOpPure *addr = c28x_page3f(UNSIGNED(16, VARG("acc")));
		return c28x_with_src(&insn->ops[1], 16, STOREW(addr, VARL(C28X_VAL_LOCAL)));
	}
	const C28xOperand *s = &insn->ops[1];
	RzILOpPure *addr;
	if (s->kind == C28X_OP_PMA_IND) {
		addr = UN(32, (ut64)s->imm);
	} else if (c28x_is_reg(s, C28X_REG_AL)) {
		addr = c28x_page3f(UNSIGNED(16, VARG("acc")));
	} else {
		return NULL;
	}
	return c28x_store16_nz(&insn->ops[0], LOADW(16, addr));
}

/* more status and control */

/**
 * \brief MAXCUL and MINCUL P,loc32, the low half of a 64-bit MAXL or MINL.
 *
 * N and Z still hold the comparison of the high halves; only when those were
 * equal are the low halves compared, unsigned, and then a replacement sets V
 * (SPRU430F "MAXCUL P,loc32").
 */
static RzILOpEffect *c28x_lift_mincul(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 2) {
		return NULL;
	}
	const bool max = insn->id == C28X_INS_MAXCUL;
	RzILOpPure *high = AND(max ? VARG("n") : INV(VARG("n")), INV(VARG("z")));
	RzILOpPure *beats;
	if (max) {
		beats = ULT(VARG("p"), VARL(C28X_VAL_LOCAL));
	} else {
		beats = ULT(VARL(C28X_VAL_LOCAL), VARG("p"));
	}
	RzILOpPure *low = AND(AND(INV(VARG("n")), VARG("z")), beats);
	RzILOpPure *either = OR(VARL("mh"), VARL("ml"));
	RzILOpEffect *take = BRANCH(either, SETG("p", VARL(C28X_VAL_LOCAL)), NOP());
	RzILOpEffect *body = SEQ4(SETL("mh", high), SETL("ml", low),
		SETG("v", OR(VARG("v"), VARL("ml"))), take);
	return c28x_with_src(&insn->ops[1], 32, body);
}

/**
 * \brief NORM ACC, one step of normalisation.
 *
 * While ACC is non-zero and bits 31 and 30 agree, ACC shifts left, TC clears
 * and the pointer steps; the pointer is never dereferenced. Otherwise TC is set.
 */
static RzILOpEffect *c28x_lift_norm(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 2 || insn->ops[1].kind != C28X_OP_MEM) {
		return NULL;
	}
	const C28xOperand *m = &insn->ops[1];
	RzILOpEffect *step;
	if (m->mode == C28X_AM_XAR_MOD_INC || m->mode == C28X_AM_XAR_MOD_DEC) {
		const char *r = c28x_xar_name(m->arn);
		const bool inc = m->mode == C28X_AM_XAR_MOD_INC;
		step = SETG(r, inc ? ADD(VARG(r), UN(32, 1)) : SUB(VARG(r), UN(32, 1)));
	} else {
		step = c28x_arp_update(m);
		if (!step) {
			step = NOP();
		}
	}
	RzILOpPure *b30 = MSB(SHIFTL0(VARG("acc"), UN(6, 1)));
	RzILOpPure *go = AND(INV(IS_ZERO(VARG("acc"))), INV(XOR(MSB(VARG("acc")), b30)));
	RzILOpPure *dbl = SHIFTL0(VARG("acc"), UN(6, 1));
	RzILOpEffect *shift = SEQ3(SETG("acc", dbl), SETG("tc", IL_FALSE), step);
	return SEQ3(SETL("nm", go), BRANCH(VARL("nm"), shift, SETG("tc", IL_TRUE)), c28x_nz_acc());
}

/**
 * \brief CMPR 0..3 compares AR[ARP] with AR0, unsigned, into TC.
 *
 * 0 tests equal, 1 AR[ARP] < AR0, 2 AR[ARP] > AR0 and 3 not equal. SPRU430F
 * prints the same test for 1 and 2; these are the C2xLP instruction's.
 */
static RzILOpEffect *c28x_lift_cmpr(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 1 || insn->ops[0].kind != C28X_OP_IMM) {
		return NULL;
	}
	RzILOpPure *t;
	switch (insn->ops[0].imm & 3) {
	case 0: t = EQ(VARL("ca"), VARL("c0")); break;
	case 1: t = ULT(VARL("ca"), VARL("c0")); break;
	case 2: t = ULT(VARL("c0"), VARL("ca")); break;
	default: t = INV(EQ(VARL("ca"), VARL("c0"))); break;
	}
	RzILOpPure *ar = UNSIGNED(16, c28x_arp_xar());
	RzILOpPure *ar0 = UNSIGNED(16, VARG("xar0"));
	return SEQ3(SETL("ca", ar), SETL("c0", ar0), SETG("tc", t));
}

/**
 * \brief LOOPZ and LOOPNZ loc16,#16bit re-execute until the masked location
 * becomes non-zero, or zero; the LOOP bit shows a loop in progress.
 */
static RzILOpEffect *c28x_lift_loop(const C28xInsn *insn, ut64 pc) {
	if (insn->nops != 2 || insn->ops[1].kind != C28X_OP_IMM) {
		return NULL;
	}
	const ut64 mask = (ut64)insn->ops[1].imm & 0xffff;
	RzILOpPure *zero = IS_ZERO(LOGAND(VARL(C28X_VAL_LOCAL), UN(16, mask)));
	RzILOpPure *again = insn->id == C28X_INS_LOOPZ ? zero : INV(zero);
	RzILOpEffect *body = SEQ3(SETL("lp", again), SETG("loop", VARL("lp")),
		BRANCH(VARL("lp"), JMP(UN(32, pc)), NOP()));
	return c28x_with_src(&insn->ops[0], 16, body);
}

// EALLOW and EDIS set and clear write access to the protected registers.
static RzILOpEffect *c28x_lift_eallow(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	return SETG("eallow", insn->id == C28X_INS_EALLOW ? IL_TRUE : IL_FALSE);
}

/* status registers and interrupts */

// ST0 bits 0..6 by position; OVC (15:10) and PM (9:7) are fields.
static const char *const c28x_st0_bits[] = { "sxm", "ovm", "tc", "c", "z", "n", "v" };

// ST1 bits 0..12 by position (bit 10 is reserved); ARP is bits 15:13.
static const char *const c28x_st1_bits[] = {
	"intm", "dbgm", "page0", "vmap", "spa", "loop", "eallow", "idlestat",
	"amode", "objmode", NULL, "m0m1map", "xf"
};

// A status register as the 16-bit value its bits and fields make up.
static RzILOpPure *c28x_status(bool st1) {
	const char *const *bits = st1 ? c28x_st1_bits : c28x_st0_bits;
	const size_t n = st1 ? RZ_ARRAY_SIZE(c28x_st1_bits) : RZ_ARRAY_SIZE(c28x_st0_bits);
	RzILOpPure *v;
	if (st1) {
		v = SHIFTL0(UNSIGNED(16, VARG("arp")), UN(4, 13));
	} else {
		RzILOpPure *ovc = SHIFTL0(UNSIGNED(16, VARG("ovc")), UN(4, 10));
		v = LOGOR(ovc, SHIFTL0(UNSIGNED(16, VARG("pm")), UN(4, 7)));
	}
	for (size_t i = 0; i < n; i++) {
		if (bits[i]) {
			v = LOGOR(v, ITE(VARG(bits[i]), UN(16, 1u << i), UN(16, 0)));
		}
	}
	return v;
}

// Load a status register's bits and fields from the 16-bit local \p local.
static RzILOpEffect *c28x_set_status(bool st1, const char *local) {
	const char *const *bits = st1 ? c28x_st1_bits : c28x_st0_bits;
	const size_t n = st1 ? RZ_ARRAY_SIZE(c28x_st1_bits) : RZ_ARRAY_SIZE(c28x_st0_bits);
	RzILOpEffect *eff;
	if (st1) {
		eff = SETG("arp", UNSIGNED(3, SHIFTR0(VARL(local), UN(4, 13))));
	} else {
		eff = SEQ2(SETG("ovc", UNSIGNED(6, SHIFTR0(VARL(local), UN(4, 10)))),
			SETG("pm", UNSIGNED(3, SHIFTR0(VARL(local), UN(4, 7)))));
	}
	for (size_t i = 0; i < n; i++) {
		if (bits[i]) {
			RzILOpPure *set = INV(IS_ZERO(LOGAND(VARL(local), UN(16, 1u << i))));
			eff = SEQ2(eff, SETG(bits[i], set));
		}
	}
	return eff;
}

// The high half of the 32-bit local \p local.
static RzILOpPure *c28x_high16(const char *local) {
	return UNSIGNED(16, SHIFTR0(VARL(local), UN(6, 16)));
}

// Two 16-bit values as one 32-bit word, \p lo at the lower address.
static RzILOpPure *c28x_pair(RzILOpPure *lo, RzILOpPure *hi) {
	return LOGOR(SHIFTL0(UNSIGNED(32, hi), UN(6, 16)), UNSIGNED(32, lo));
}

// A 32-bit stack access: the memory wrapper ignores bit 0 of the address.
static RzILOpPure *c28x_sp_even(void) {
	return c28x_byte(LOGAND(VARG("sp"), UN(16, 0xfffe)));
}

// Save one register pair as the context save does, then step SP past it.
static RzILOpEffect *c28x_save_pair(RzILOpPure *pair) {
	return SEQ2(STOREW(c28x_sp_even(), pair), SETG("sp", ADD(VARG("sp"), UN(16, 2))));
}

/**
 * \brief Take interrupt \p vector, as INTR and TRAP do.
 *
 * SP first steps past the last word in use; seven register pairs are then
 * saved with 32-bit writes, INTM and DBGM set, LOOP, EALLOW and IDLESTAT
 * cleared, and the vector read from the table VMAP selects (SPRU430F section
 * 3.4). A PIE, where the device has one, redirects the fetch outside the CPU
 * and is not modelled.
 * \param bit the IFR and IER bit INTR clears, or -1 for none
 */
static RzILOpEffect *c28x_take_interrupt(const C28xInsn *insn, ut64 pc, ut32 vector, int bit) {
	const ut64 ret = ((pc + insn->size) / C28X_WORD_BYTES) & 0x3fffff;
	RzILOpPure *t = UNSIGNED(16, SHIFTR0(VARG("xt"), UN(6, 16)));
	RzILOpPure *ar = c28x_pair(UNSIGNED(16, VARG("xar0")), UNSIGNED(16, VARG("xar1")));
	RzILOpPure *st1 = c28x_pair(c28x_status(true), VARG("dp"));
	RzILOpPure *ier = c28x_pair(VARG("ier"), VARG("dbgstat"));
	RzILOpEffect *save = SEQ8(SETG("sp", ADD(VARG("sp"), UN(16, 1))),
		c28x_save_pair(c28x_pair(c28x_status(false), t)),
		c28x_save_pair(VARG("acc")), c28x_save_pair(VARG("p")), c28x_save_pair(ar),
		c28x_save_pair(st1), c28x_save_pair(ier), c28x_save_pair(UN(32, ret)));
	RzILOpEffect *bits = NOP();
	if (bit >= 0) {
		const ut16 keep = (ut16) ~(1u << bit);
		bits = SEQ2(SETG("ifr", LOGAND(VARG("ifr"), UN(16, keep))),
			SETG("ier", LOGAND(VARG("ier"), UN(16, keep))));
	}
	RzILOpEffect *masks = SEQ2(SETG("intm", IL_TRUE), SETG("dbgm", IL_TRUE));
	RzILOpEffect *mode = SEQ4(masks, SETG("loop", IL_FALSE), SETG("eallow", IL_FALSE),
		SETG("idlestat", IL_FALSE));
	RzILOpPure *table = ITE(VARG("vmap"), UN(32, 0x3fffc0 + 2 * vector), UN(32, 2 * vector));
	RzILOpPure *target = c28x_byte(LOGAND(VARL("vec"), UN(32, 0x3fffff)));
	return SEQ5(save, bits, mode, SETL("vec", LOADW(32, c28x_byte(table))), JMP(target));
}

// TRAP #0..31 takes the vector without touching IFR or IER.
static RzILOpEffect *c28x_lift_trap(const C28xInsn *insn, ut64 pc) {
	if (insn->nops != 1 || insn->ops[0].kind != C28X_OP_IMM) {
		return NULL;
	}
	return c28x_take_interrupt(insn, pc, (ut32)insn->ops[0].imm & 31, -1);
}

/**
 * \brief INTR INT1..INT14, DLOGINT, RTOSINT and NMI.
 *
 * The maskable ones clear their IFR and IER bits; NMI has none. The page's
 * "INTM = 0" contradicts its own comment and section 3.4: INTM is set, as for
 * any interrupt. EMUINT has no vector in SPRU430F's table and is not lifted.
 */
static RzILOpEffect *c28x_lift_intr(const C28xInsn *insn, ut64 pc) {
	if (insn->nops != 1) {
		return NULL;
	}
	const C28xOperand *o = &insn->ops[0];
	if (o->kind == C28X_OP_INTR) {
		const int f = (int)(o->imm & 15);
		return c28x_take_interrupt(insn, pc, (ut32)f + 1, f);
	}
	if (c28x_is_reg(o, C28X_REG_NMI)) {
		return c28x_take_interrupt(insn, pc, 18, -1);
	}
	return NULL;
}

// Restore one saved pair into the local \p local, SP first stepping back.
static RzILOpEffect *c28x_restore_pair(const char *local) {
	return SEQ2(SETG("sp", SUB(VARG("sp"), UN(16, 2))), SETL(local, LOADW(32, c28x_sp_even())));
}

// IRET undoes the context save in reverse and returns (SPRU430F "IRET").
static RzILOpEffect *c28x_lift_iret(RZ_UNUSED const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	RzILOpPure *lo = UNSIGNED(32, UNSIGNED(16, VARL("ra")));
	RzILOpPure *ar0 = LOGOR(LOGAND(VARG("xar0"), UN(32, 0xffff0000)), lo);
	RzILOpPure *hi = UNSIGNED(32, SHIFTR0(VARL("ra"), UN(6, 16)));
	RzILOpPure *ar1 = LOGOR(LOGAND(VARG("xar1"), UN(32, 0xffff0000)), hi);
	RzILOpPure *t = SHIFTL0(SHIFTR0(VARL("rt"), UN(6, 16)), UN(6, 16));
	RzILOpEffect *regs = SEQ8(
		SEQ2(c28x_restore_pair("rr"), c28x_restore_pair("ri")),
		SEQ2(SETG("ier", UNSIGNED(16, VARL("ri"))), SETG("dbgstat", c28x_high16("ri"))),
		SEQ2(c28x_restore_pair("rs"), SETL("s1", UNSIGNED(16, VARL("rs")))),
		SEQ2(c28x_set_status(true, "s1"), SETG("dp", c28x_high16("rs"))),
		SEQ3(c28x_restore_pair("ra"), SETG("xar0", ar0), SETG("xar1", ar1)),
		SEQ2(c28x_restore_pair("rp"), SETG("p", VARL("rp"))),
		SEQ2(c28x_restore_pair("rc"), SETG("acc", VARL("rc"))),
		SEQ3(c28x_restore_pair("rt"), SETL("s0", UNSIGNED(16, VARL("rt"))),
			c28x_set_status(false, "s0")));
	RzILOpPure *xt = LOGOR(LOGAND(VARG("xt"), UN(32, 0xffff)), t);
	return SEQ4(regs, SETG("xt", xt), SETG("sp", SUB(VARG("sp"), UN(16, 1))),
		JMP(c28x_byte(LOGAND(VARL("rr"), UN(32, 0x3fffff)))));
}

/**
 * \brief PUSH and POP of ST0, ST1 and DP:ST1, built from and spread back to
 * the bits the IL keeps.
 */
static RzILOpEffect *c28x_push_pop_status(const C28xInsn *insn) {
	if (insn->nops != 1 || insn->ops[0].kind != C28X_OP_REG) {
		return NULL;
	}
	const C28xReg r = insn->ops[0].reg;
	if (r != C28X_REG_ST0 && r != C28X_REG_ST1 && r != C28X_REG_DP_ST1) {
		return NULL;
	}
	const bool st1 = r != C28X_REG_ST0;
	const bool wide = r == C28X_REG_DP_ST1;
	if (insn->id == C28X_INS_PUSH) {
		RzILOpPure *v = wide ? c28x_pair(c28x_status(true), VARG("dp")) : c28x_status(st1);
		RzILOpPure *sp = ADD(VARG("sp"), UN(16, wide ? 2 : 1));
		return SEQ2(STOREW(c28x_byte(VARG("sp")), v), SETG("sp", sp));
	}
	RzILOpEffect *pop = SEQ2(SETG("sp", SUB(VARG("sp"), UN(16, wide ? 2 : 1))),
		SETL("sw", LOADW(wide ? 32 : 16, c28x_byte(VARG("sp")))));
	if (!wide) {
		return SEQ2(pop, c28x_set_status(st1, "sw"));
	}
	return SEQ4(pop, SETL("s1", UNSIGNED(16, VARL("sw"))), c28x_set_status(true, "s1"),
		SETG("dp", c28x_high16("sw")));
}

// IACK only drives its constant onto the data bus for external hardware.
static RzILOpEffect *c28x_lift_iack(RZ_UNUSED const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	return NOP();
}

/* byte moves */

/**
 * \brief Latch a byte access's word address in \ref C28X_EA_LOCAL, and in "bs"
 * whether it selects the high byte.
 *
 * *+XARn[AR0], *+XARn[AR1] and *+XARn[3bit] count their offsets in bytes: the
 * word is XARn + offset / 2 and an odd offset selects its high byte (SPRU430F
 * section 5.10, whose byte-swap example fixes the halving). Every other mode
 * addresses a word as usual and accesses its low byte.
 */
static RzILOpEffect *c28x_byte_ea(const C28xOperand *m) {
	const bool indexed = m->mode == C28X_AM_XAR_AR0 || m->mode == C28X_AM_XAR_AR1 ||
		m->mode == C28X_AM_XAR_IMM;
	if (!indexed) {
		RzILOpEffect *ea = c28x_ea_begin(m);
		return ea ? SEQ2(ea, SETL("bs", IL_FALSE)) : NULL;
	}
	RzILOpPure *off;
	if (m->mode == C28X_AM_XAR_IMM) {
		off = UN(32, m->off & 7);
	} else {
		const char *ix = c28x_xar_name(m->mode == C28X_AM_XAR_AR1);
		off = UNSIGNED(32, UNSIGNED(16, VARG(ix)));
	}
	RzILOpPure *word = ADD(VARG(c28x_xar_name(m->arn)), SHIFTR0(VARL("bo"), UN(6, 1)));
	return SEQ3(SETL("bo", off), SETL(C28X_EA_LOCAL, word), SETL("bs", LSB(VARL("bo"))));
}

/**
 * \brief MOVB AX.LSB/AX.MSB,loc16 and MOVB loc16,AX.LSB/AX.MSB.
 *
 * Loads put the byte in the named half of AX (clearing the other for .LSB) and
 * set N and Z; stores replace only the selected byte of the word.
 */
static RzILOpEffect *c28x_lift_movb_byte(const C28xInsn *insn) {
	if (insn->nops != 2) {
		return NULL;
	}
	const bool load = insn->ops[0].kind == C28X_OP_REG && insn->ops[0].byte_sel;
	const C28xOperand *ax = load ? &insn->ops[0] : &insn->ops[1];
	const C28xOperand *m = load ? &insn->ops[1] : &insn->ops[0];
	if (ax->kind != C28X_OP_REG || !ax->byte_sel || m->kind != C28X_OP_MEM) {
		return NULL;
	}
	const bool msb = ax->byte_sel == 2;
	const bool mem = c28x_is_mem(m);
	RzILOpEffect *begin = mem ? c28x_byte_ea(m) : SETL("bs", IL_FALSE);
	RzILOpPure *word = mem ? LOADW(16, c28x_byte(VARL(C28X_EA_LOCAL))) : c28x_read16(m);
	RzILOpPure *axv = c28x_read16(ax);
	if (!begin || !word || !axv) {
		rz_il_op_effect_free(begin);
		rz_il_op_pure_free(word);
		rz_il_op_pure_free(axv);
		return NULL;
	}
	RzILOpPure *hi = SHIFTR0(VARL("bw"), UN(4, 8));
	RzILOpPure *byte = UNSIGNED(16, ITE(VARL("bs"), UNSIGNED(8, hi), UNSIGNED(8, VARL("bw"))));
	RzILOpEffect *body;
	if (load) {
		RzILOpPure *nv = byte;
		if (msb) {
			nv = LOGOR(LOGAND(VARL("av"), UN(16, 0x00ff)), SHIFTL0(byte, UN(4, 8)));
		}
		RzILOpEffect *wr = c28x_write16(ax, VARL("nv"), false);
		RzILOpEffect *nz = SEQ2(SETG("n", MSB(VARL("nv"))), SETG("z", IS_ZERO(VARL("nv"))));
		body = SEQ3(SETL("nv", nv), wr, nz);
	} else {
		rz_il_op_pure_free(byte);
		RzILOpPure *src;
		if (msb) {
			src = SHIFTR0(VARL("av"), UN(4, 8));
		} else {
			src = LOGAND(VARL("av"), UN(16, 0xff));
		}
		RzILOpPure *keep_lo = LOGAND(VARL("bw"), UN(16, 0x00ff));
		RzILOpPure *in_hi = LOGOR(keep_lo, SHIFTL0(src, UN(4, 8)));
		RzILOpPure *in_lo = LOGOR(LOGAND(VARL("bw"), UN(16, 0xff00)), DUP(src));
		RzILOpPure *nw = ITE(VARL("bs"), in_hi, in_lo);
		RzILOpEffect *st = mem ? STOREW(c28x_byte(VARL(C28X_EA_LOCAL)), VARL("nw"))
				       : c28x_write16(m, VARL("nw"), false);
		body = SEQ3(SETL("nw", nw), st, c28x_nz_if_ax(m, "nw"));
	}
	RzILOpEffect *post = mem ? c28x_ea_end(m) : NULL;
	RzILOpEffect *eff = SEQ4(begin, SETL("bw", word), SETL("av", axv), body);
	return post ? SEQ2(eff, post) : eff;
}

/* calls and returns */

// The word address after this instruction: PC counts 16-bit words, and
// return addresses keep that, while the IL VM's pc counts bytes.
static RzILOpPure *c28x_return_word(const C28xInsn *insn, ut64 pc) {
	return UN(32, ((pc + insn->size) / C28X_WORD_BYTES) & 0x3fffff);
}

// Push a 22-bit return address as two words, low half first (SPRU430F "LC").
static RzILOpEffect *c28x_push_ret(RzILOpPure *ret) {
	return SEQ5(SETL("ra", ret),
		STOREW(c28x_byte(VARG("sp")), UNSIGNED(16, VARL("ra"))),
		SETG("sp", ADD(VARG("sp"), UN(16, 1))),
		STOREW(c28x_byte(VARG("sp")), UNSIGNED(16, SHIFTR0(VARL("ra"), UN(6, 16)))),
		SETG("sp", ADD(VARG("sp"), UN(16, 1))));
}

// Pop what c28x_push_ret() pushed into the local \p local.
static RzILOpEffect *c28x_pop_ret(const char *local) {
	RzILOpPure *both = LOGOR(SHIFTL0(VARL("hi"), UN(6, 16)), c28x_stack_word());
	return SEQ4(SETG("sp", SUB(VARG("sp"), UN(16, 1))),
		SETL("hi", c28x_stack_word()),
		SETG("sp", SUB(VARG("sp"), UN(16, 1))),
		SETL(local, LOGAND(both, UN(32, 0x3fffff))));
}

// LC #22bit and LC *XAR7 push the return address and jump.
static RzILOpEffect *c28x_lift_lc(const C28xInsn *insn, ut64 pc) {
	if (insn->nops != 1) {
		return NULL;
	}
	const C28xOperand *o = &insn->ops[0];
	RzILOpPure *target;
	if (c28x_is_target(o)) {
		target = UN(32, (ut64)o->imm);
	} else if (o->kind == C28X_OP_MEM && o->mode == C28X_AM_XAR_NONE) {
		// the register holds a word address
		target = c28x_byte(LOGAND(VARG(c28x_xar_name(o->arn)), UN(32, 0x3fffff)));
	} else {
		return NULL;
	}
	return SEQ3(SETL("tg", target), c28x_push_ret(c28x_return_word(insn, pc)), JMP(VARL("tg")));
}

// LRET pops the return address; LRETE also clears INTM.
static RzILOpEffect *c28x_lift_lret(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	RzILOpEffect *intm = insn->id == C28X_INS_LRETE ? SETG("intm", IL_FALSE) : NOP();
	return SEQ3(c28x_pop_ret("rt"), intm, JMP(c28x_byte(VARL("rt"))));
}

// FFC XAR7,22bit keeps the return address in XAR7 instead of the stack.
static RzILOpEffect *c28x_lift_ffc(const C28xInsn *insn, ut64 pc) {
	if (insn->nops != 2 || !c28x_is_target(&insn->ops[1])) {
		return NULL;
	}
	return SEQ2(SETG("xar7", c28x_return_word(insn, pc)), JMP(UN(32, (ut64)insn->ops[1].imm)));
}

static RzILOpEffect *c28x_lift_nop(RZ_UNUSED const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	return NOP();
}

static RzILOpEffect *c28x_lift_mov(const C28xInsn *insn, ut64 pc) {
	if (insn->nops == 2 && c28x_is_reg(&insn->ops[1], C28X_REG_PC)) {
		// MOV XARn,PC: the word address of this instruction
		const char *r = c28x_reg32(&insn->ops[0]);
		return r ? SETG(r, UN(32, (pc / C28X_WORD_BYTES) & 0x3fffff)) : NULL;
	}
	const C28xInsnId id = insn->id;
	RzILOpEffect *more = c28x_lift_mov_more(insn);
	if (more) {
		return more;
	}
	const bool movz = id == C28X_INS_MOVZ;
	if ((id == C28X_INS_MOV || movz) && insn->nops == 2) {
		if (c28x_is_mem(&insn->ops[1])) {
			return c28x_lift_load_reg(insn, false, movz);
		}
		if (c28x_is_mem(&insn->ops[0])) {
			return c28x_lift_store_reg(insn, false);
		}
		return c28x_lift_move_reg(insn, false, movz);
	}
	return NULL;
}

static RzILOpEffect *c28x_lift_movl(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	const C28xInsnId id = insn->id;
	// MOVL ACC,P<<PM: the generic register move below cannot shift
	if (insn->nops == 2 && c28x_is_acc(&insn->ops[0]) &&
		c28x_is_reg(&insn->ops[1], C28X_REG_P_PM)) {
		return SEQ3(SETL("pv", VARG("p")), SETG("acc", c28x_pm_shifted()), c28x_nz_acc());
	}
	if (id == C28X_INS_MOVL && insn->nops == 2) {
		if (c28x_is_mem(&insn->ops[1])) {
			return c28x_lift_load_reg(insn, true, false);
		}
		if (c28x_is_mem(&insn->ops[0])) {
			return c28x_lift_store_reg(insn, true);
		}
		return c28x_lift_move_reg(insn, true, false);
	}
	if (insn->nops == 3 && insn->ops[2].kind == C28X_OP_COND && c28x_is_acc(&insn->ops[1])) {
		return c28x_lift_store_cond(insn, 32, VARG("acc"));
	}
	return NULL;
}

static RzILOpEffect *c28x_lift_movb(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	RzILOpEffect *byte = c28x_lift_movb_byte(insn);
	if (byte) {
		return byte;
	}
	const C28xInsnId id = insn->id;
	if (id == C28X_INS_MOVB && insn->nops == 2 && insn->ops[1].kind == C28X_OP_IMM) {
		// MOVB ACC,#8bit zero-extends into the whole accumulator; MOVB AX,#8bit
		// writes only the named half
		const char *w = c28x_reg32(&insn->ops[0]);
		if (w) {
			return SETG(w, UN(32, (ut64)insn->ops[1].imm & 0xff));
		}
		return c28x_write16(&insn->ops[0], UN(16, (ut64)insn->ops[1].imm & 0xff), false);
	}
	if (insn->nops == 3 && insn->ops[2].kind == C28X_OP_COND &&
		insn->ops[1].kind == C28X_OP_IMM) {
		return c28x_lift_store_cond(insn, 16, UN(16, (ut64)insn->ops[1].imm & 0xff));
	}
	return NULL;
}

static RzILOpEffect *c28x_lift_push(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	RzILOpEffect *st = c28x_push_pop_status(insn);
	if (st) {
		return st;
	}
	const C28xInsnId id = insn->id;
	if (id == C28X_INS_PUSH && insn->nops == 1) {
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
	return NULL;
}

static RzILOpEffect *c28x_lift_pop(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	RzILOpEffect *st = c28x_push_pop_status(insn);
	if (st) {
		return st;
	}
	const C28xInsnId id = insn->id;
	if (id == C28X_INS_POP && insn->nops == 1) {
		const char *r32 = c28x_reg32(&insn->ops[0]);
		if (r32) {
			return SEQ2(SETG("sp", SUB(VARG("sp"), UN(16, 2))),
				SETG(r32, LOADW(32, c28x_byte(VARG("sp")))));
		}
		RzILOpEffect *w = c28x_write16(&insn->ops[0], LOADW(16, c28x_byte(VARG("sp"))),
			false);
		return w ? SEQ2(SETG("sp", SUB(VARG("sp"), UN(16, 1))), w) : NULL;
	}
	return NULL;
}

static RzILOpEffect *c28x_lift_addb_subb(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	const C28xInsnId id = insn->id;
	if ((id == C28X_INS_ADDB || id == C28X_INS_SUBB) && insn->nops == 2 &&
		insn->ops[1].kind == C28X_OP_IMM) {
		const bool sub = id == C28X_INS_SUBB;
		const ut64 k = (ut64)insn->ops[1].imm;
		// ADDB/SUBB ACC set the full flag set; the SP and XARn forms are
		// pointer arithmetic and touch nothing (SPRU430F "Flags and Modes")
		if (insn->ops[0].kind == C28X_OP_REG && insn->ops[0].reg == C28X_REG_ACC) {
			return c28x_acc_addsub(UN(32, k), sub);
		}
		const char *r32 = c28x_reg32(&insn->ops[0]);
		if (r32) {
			return SETG(r32,
				sub ? SUB(VARG(r32), UN(32, k)) : ADD(VARG(r32), UN(32, k)));
		}
		RzILOpPure *cur = c28x_read16(&insn->ops[0]);
		if (!cur) {
			return NULL;
		}
		return c28x_write16(&insn->ops[0],
			sub ? SUB(cur, UN(16, k)) : ADD(cur, UN(16, k)), false);
	}
	return NULL;
}

static RzILOpEffect *c28x_lift_add_sub(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	const C28xInsnId id = insn->id;
	// ADD/SUB ACC,loc16 (with any shift suffix) and the loc32 forms
	const bool is_add = id == C28X_INS_ADD || id == C28X_INS_ADDL;
	const bool is_sub = id == C28X_INS_SUB || id == C28X_INS_SUBL;
	if ((is_add || is_sub) && insn->nops >= 2 &&
		insn->ops[0].kind == C28X_OP_REG && insn->ops[0].reg == C28X_REG_ACC &&
		c28x_is_mem(&insn->ops[1])) {
		const bool wide = insn->ops[1].wide;
		RzILOpPure *v = wide ? VARL(C28X_VAL_LOCAL)
				     : c28x_apply_shift(insn, c28x_ext16(true));
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
		RzILOpPure *ext = wide ? v : ITE(VARG("sxm"), SIGNED(32, v), UNSIGNED(32, DUP(v)));
		return c28x_acc_addsub(ext, is_sub);
	}
	if ((is_add || is_sub) && insn->nops == 2 &&
		insn->ops[0].kind == C28X_OP_REG && insn->ops[0].reg == C28X_REG_ACC &&
		insn->ops[1].kind == C28X_OP_IMM) {
		return c28x_acc_addsub(UN(32, (ut64)insn->ops[1].imm), is_sub);
	}
	return c28x_lift_alu_more(insn);
}

static RzILOpEffect *c28x_lift_logic(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	const C28xInsnId id = insn->id;
	// AND/OR/XOR ACC,loc16 and the loc32 forms
	if ((id == C28X_INS_AND || id == C28X_INS_OR || id == C28X_INS_XOR) &&
		insn->nops >= 2 && insn->ops[0].kind == C28X_OP_REG &&
		insn->ops[0].reg == C28X_REG_ACC && c28x_is_mem(&insn->ops[1])) {
		const bool wide = insn->ops[1].wide;
		RzILOpPure *v = wide ? VARL(C28X_VAL_LOCAL)
				     : c28x_apply_shift(insn, c28x_ext16(false));
		return c28x_with_val(&insn->ops[1], wide ? 32 : 16, c28x_acc_logic(id, v));
	}
	return c28x_lift_alu_more(insn);
}

static RzILOpEffect *c28x_lift_cmp(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	const C28xInsnId id = insn->id;
	// CMP/CMPL: the difference is discarded, only N/Z/C are set
	if ((id == C28X_INS_CMP || id == C28X_INS_CMPL) && insn->nops == 2 &&
		insn->ops[0].kind == C28X_OP_REG) {
		const bool wide = id == C28X_INS_CMPL;
		RzILOpPure *lhs = c28x_cmp_lhs(&insn->ops[0], wide);
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
		RzILOpPure *l2 = c28x_cmp_lhs(&insn->ops[0], wide);
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
	return NULL;
}

static RzILOpEffect *c28x_lift_cmpb(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	const C28xInsnId id = insn->id;
	// CMPB AX,#8bit compares against a zero-extended constant
	if (id == C28X_INS_CMPB && insn->nops == 2 && insn->ops[1].kind == C28X_OP_IMM) {
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
	return NULL;
}

static RzILOpEffect *c28x_lift_movw(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	const C28xInsnId id = insn->id;
	// MOVW DP,#16bit loads the data page register outright
	if (id == C28X_INS_MOVW && insn->nops == 2 && insn->ops[1].kind == C28X_OP_IMM &&
		insn->ops[0].kind == C28X_OP_REG && insn->ops[0].reg == C28X_REG_DP) {
		return SETG("dp", UN(16, (ut64)insn->ops[1].imm & 0xffff));
	}
	return NULL;
}

static RzILOpEffect *c28x_lift_lcr(const C28xInsn *insn, ut64 pc) {
	// RPC is pushed, then takes the return address, then the call is taken
	// (SPRU430F "LCR #22bit"); RPC holds a word address, as on the stack
	if (insn->nops != 1 || !c28x_is_target(&insn->ops[0])) {
		return NULL;
	}
	return SEQ3(c28x_push_ret(VARG("rpc")), SETG("rpc", c28x_return_word(insn, pc)),
		JMP(UN(32, (ut64)insn->ops[0].imm)));
}

static RzILOpEffect *c28x_lift_lretr(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	// PC comes from RPC, then RPC is popped back off the stack
	if (insn->nops) {
		return NULL;
	}
	return SEQ4(SETL("rt", VARG("rpc")), c28x_pop_ret("np"), SETG("rpc", VARL("np")),
		JMP(c28x_byte(VARL("rt"))));
}

static RzILOpEffect *c28x_lift_shift_const(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	const C28xInsnId id = insn->id;
	// LSL/LSR/ASR/SFR with a constant count. SFR picks arithmetic or logical
	// from SXM, so it is lifted only where the choice is already decided.
	if ((id == C28X_INS_LSL || id == C28X_INS_LSR || id == C28X_INS_ASR) &&
		insn->nops == 2 && insn->ops[0].kind == C28X_OP_REG &&
		insn->ops[1].kind == C28X_OP_SHIFT && insn->ops[1].imm) {
		const ut8 n = (ut8)insn->ops[1].imm;
		const bool right = id == C28X_INS_LSR || id == C28X_INS_ASR;
		const bool arith = id == C28X_INS_ASR;
		const char *r32 = c28x_reg32(&insn->ops[0]);
		if (r32) {
			return c28x_shift_const(r32, 32, n, right, arith);
		}
		C28xSlice sl;
		if (!c28x_slice(&insn->ops[0], &sl)) {
			return NULL;
		}
		RzILOpPure *res = c28x_shift_by(VARL("sv"), n, right, arith);
		return SEQ4(
			SETL("sv", c28x_slice_read(&sl)),
			SETG("c", LSB(SHIFTR0(VARL("sv"), UN(6, right ? n - 1 : 16 - n)))),
			c28x_slice_write(&sl, res, false),
			SEQ2(SETG("n", MSB(c28x_slice_read(&sl))),
				SETG("z", IS_ZERO(c28x_slice_read(&sl)))));
	}
	return c28x_lift_shift_t(insn);
}

static RzILOpEffect *c28x_lift_tbit(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	const C28xInsnId id = insn->id;
	// TBIT loc16,#bit: TC receives the tested bit
	if (id == C28X_INS_TBIT && insn->nops == 2 && c28x_is_mem(&insn->ops[0]) &&
		insn->ops[1].kind == C28X_OP_IMM) {
		const ut8 bit = (ut8)(insn->ops[1].imm & 0xf);
		return c28x_with_val(&insn->ops[0], 16,
			SETG("tc", LSB(SHIFTR0(VARL(C28X_VAL_LOCAL), UN(5, bit)))));
	}
	return NULL;
}

// Status bits SETC and CLRC can also name on their own.
static const char *const c28x_mode_regs[] = {
	[C28X_REG_OBJMODE] = "objmode",
	[C28X_REG_XF] = "xf",
	[C28X_REG_M0M1MAP] = "m0m1map",
	[C28X_REG_AMODE] = "amode",
};

static const char *c28x_mode_reg(C28xReg r) {
	return (size_t)r < RZ_ARRAY_SIZE(c28x_mode_regs) ? c28x_mode_regs[r] : NULL;
}

static RzILOpEffect *c28x_lift_setc_clrc(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	const C28xInsnId id = insn->id;
	// SETC/CLRC: each set bit of the mask names one status bit to write
	if ((id == C28X_INS_SETC || id == C28X_INS_CLRC) && insn->nops == 1 &&
		insn->ops[0].kind == C28X_OP_MODE) {
		const bool set = id == C28X_INS_SETC;
		RzILOpEffect *eff = NULL;
		for (ut8 i = 0; i < 8; i++) {
			if (!(insn->ops[0].imm & (1 << i))) {
				continue;
			}
			RzILOpEffect *one = SETG(c28x_mode_bits[i], set ? IL_TRUE : IL_FALSE);
			eff = eff ? SEQ2(eff, one) : one;
		}
		return eff;
	}
	if (insn->nops == 1 && insn->ops[0].kind == C28X_OP_REG) {
		const char *bit = c28x_mode_reg(insn->ops[0].reg);
		if (!bit) {
			return NULL;
		}
		return SETG(bit, id == C28X_INS_SETC ? IL_TRUE : IL_FALSE);
	}
	return NULL;
}

static RzILOpEffect *c28x_lift_branch(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	const C28xInsnId id = insn->id;
	// branches: the decoder already resolved the target to an absolute address
	if ((id == C28X_INS_B || id == C28X_INS_SB || id == C28X_INS_LB || id == C28X_INS_SBF ||
		    id == C28X_INS_BF) &&
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
		if (insn->cond == C28X_COND_OV || insn->cond == C28X_COND_NOV) {
			// a condition that tests V clears it
			RzILOpEffect *jump = BRANCH(VARL("cc"), JMP(target), NOP());
			return SEQ3(SETL("cc", c), SETG("v", IL_FALSE), jump);
		}
		return BRANCH(c, JMP(target), NOP());
	}
	return NULL;
}

static RzILOpEffect *c28x_lift_estop(RZ_UNUSED const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	// emulation breakpoints; without a debugger attached they do nothing
	return NOP();
}

static RzILOpEffect *c28x_lift_intm(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	// DINT and EINT are SETC INTM and CLRC INTM under their own names
	return SETG("intm", insn->id == C28X_INS_DINT ? IL_TRUE : IL_FALSE);
}

static RzILOpEffect *c28x_lift_lpaddr(RZ_UNUSED const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	return SETG("amode", IL_TRUE);
}

static RzILOpEffect *c28x_lift_zap(RZ_UNUSED const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	return SETG("ovc", UN(6, 0));
}

static RzILOpEffect *c28x_lift_zapa(RZ_UNUSED const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	// SPRU430F's flag table reads "N set, Z cleared", contradicting its own
	// ACC = 0; the flags follow the result, as for every other ACC write
	return SEQ5(SETG("acc", UN(32, 0)), SETG("p", UN(32, 0)), SETG("ovc", UN(6, 0)),
		SETG("n", IL_FALSE), SETG("z", IL_TRUE));
}

static RzILOpEffect *c28x_lift_test(RZ_UNUSED const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	return c28x_nz_acc();
}

static RzILOpEffect *c28x_lift_not(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 1) {
		return NULL;
	}
	if (c28x_is_acc(&insn->ops[0])) {
		return SEQ2(SETG("acc", LOGNOT(VARG("acc"))), c28x_nz_acc());
	}
	RzILOpPure *cur = c28x_read16(&insn->ops[0]);
	RzILOpEffect *nz = c28x_nz16(&insn->ops[0]);
	RzILOpEffect *wr = cur ? c28x_write16(&insn->ops[0], LOGNOT(cur), false) : NULL;
	if (!wr || !nz) {
		rz_il_op_effect_free(wr);
		rz_il_op_effect_free(nz);
		return NULL;
	}
	return SEQ2(wr, nz);
}

/**
 * \brief NEG ACC, and NEGTC ACC when TC is set (SPRU430F "NEG ACC").
 *
 * 0x80000000 has no positive counterpart: V is set and, with OVM, the result
 * saturates to 0x7FFFFFFF.
 */
static RzILOpEffect *c28x_neg_acc(RzILOpPure *when) {
	RzILOpPure *min = EQ(VARL("oa"), UN(32, 0x80000000));
	RzILOpPure *neg = ITE(min, ITE(VARG("ovm"), UN(32, 0x7fffffff), UN(32, 0x80000000)),
		NEG(VARL("oa")));
	return SEQ5(SETL("oa", VARG("acc")),
		SETL("do", when),
		SETG("acc", ITE(VARL("do"), neg, VARL("oa"))),
		SEQ2(SETG("v", OR(VARG("v"), AND(VARL("do"), EQ(VARL("oa"), UN(32, 0x80000000))))),
			SETG("c", ITE(VARL("do"), IS_ZERO(VARL("oa")), VARG("c")))),
		c28x_nz_acc());
}

static RzILOpEffect *c28x_lift_neg(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 1) {
		return NULL;
	}
	if (c28x_is_acc(&insn->ops[0])) {
		return c28x_neg_acc(insn->id == C28X_INS_NEGTC ? VARG("tc") : IL_TRUE);
	}
	if (insn->id != C28X_INS_NEG) {
		return NULL;
	}
	// NEG AX has no saturation: 0x8000 stays 0x8000 and sets V
	RzILOpPure *cur = c28x_read16(&insn->ops[0]);
	RzILOpEffect *wr = c28x_write16(&insn->ops[0],
		ITE(EQ(VARL("ov"), UN(16, 0x8000)), VARL("ov"), NEG(VARL("ov"))), false);
	RzILOpEffect *nz = c28x_nz16(&insn->ops[0]);
	if (!cur || !wr || !nz) {
		rz_il_op_pure_free(cur);
		rz_il_op_effect_free(wr);
		rz_il_op_effect_free(nz);
		return NULL;
	}
	return SEQ5(SETL("ov", cur), wr,
		SETG("v", OR(VARG("v"), EQ(VARL("ov"), UN(16, 0x8000)))),
		SETG("c", IS_ZERO(VARL("ov"))), nz);
}

// ABS ACC and ABSTC ACC; ABSTC also toggles TC for a negative ACC.
static RzILOpEffect *c28x_lift_abs(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	RzILOpPure *min = EQ(VARL("oa"), UN(32, 0x80000000));
	RzILOpPure *abs = ITE(min, ITE(VARG("ovm"), UN(32, 0x7fffffff), UN(32, 0x80000000)),
		ITE(MSB(VARL("oa")), NEG(VARL("oa")), VARL("oa")));
	RzILOpEffect *tc = insn->id == C28X_INS_ABSTC
		? SETG("tc", XOR(VARG("tc"), MSB(VARL("oa"))))
		: NOP();
	return SEQ6(SETL("oa", VARG("acc")), tc, SETG("acc", abs),
		SETG("v", OR(VARG("v"), EQ(VARL("oa"), UN(32, 0x80000000)))),
		SETG("c", IL_FALSE), c28x_nz_acc());
}

/**
 * \brief SAT ACC and SAT64 ACC:P: saturate by the sign of OVC, then clear it.
 *
 * V ends up set exactly when OVC was non-zero.
 */
static RzILOpEffect *c28x_lift_sat(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	RzILOpPure *limit = ITE(MSB(VARL("o")), UN(32, 0x80000000), UN(32, 0x7fffffff));
	RzILOpEffect *eff = SETG("acc", ITE(IS_ZERO(VARL("o")), VARG("acc"), limit));
	if (insn->id == C28X_INS_SAT64) {
		RzILOpPure *p = ITE(MSB(VARL("o")), UN(32, 0), UN(32, 0xffffffff));
		RzILOpPure *z = AND(IS_ZERO(VARG("acc")), IS_ZERO(VARG("p")));
		eff = SEQ4(eff, SETG("p", ITE(IS_ZERO(VARL("o")), VARG("p"), p)),
			SETG("n", MSB(VARG("acc"))), SETG("z", z));
	} else {
		eff = SEQ2(eff, c28x_nz_acc());
	}
	return SEQ5(SETL("o", VARG("ovc")), eff, SETG("v", INV(IS_ZERO(VARL("o")))),
		SETG("ovc", UN(6, 0)), SETG("c", IL_FALSE));
}

static RzILOpEffect *c28x_lift_sxtb(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	RzILOpPure *cur = insn->nops == 1 ? c28x_read16(&insn->ops[0]) : NULL;
	RzILOpEffect *wr = NULL;
	if (cur) {
		wr = c28x_write16(&insn->ops[0], SIGNED(16, UNSIGNED(8, cur)), false);
	}
	RzILOpEffect *nz = wr ? c28x_nz16(&insn->ops[0]) : NULL;
	if (!nz) {
		rz_il_op_effect_free(wr);
		return NULL;
	}
	return SEQ2(wr, nz);
}

// ANDB/ORB/XORB AX,#8bit: the constant is zero-extended.
static RzILOpEffect *c28x_lift_logic_byte(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 2 || insn->ops[1].kind != C28X_OP_IMM) {
		return NULL;
	}
	RzILOpPure *cur = c28x_read16(&insn->ops[0]);
	if (!cur) {
		return NULL;
	}
	RzILOpPure *k = UN(16, (ut64)insn->ops[1].imm & 0xff);
	RzILOpPure *res;
	if (insn->id == C28X_INS_ANDB) {
		res = LOGAND(cur, k);
	} else if (insn->id == C28X_INS_ORB) {
		res = LOGOR(cur, k);
	} else {
		res = LOGXOR(cur, k);
	}
	RzILOpEffect *wr = c28x_write16(&insn->ops[0], res, false);
	RzILOpEffect *nz = c28x_nz16(&insn->ops[0]);
	if (!wr || !nz) {
		rz_il_op_effect_free(wr);
		rz_il_op_effect_free(nz);
		return NULL;
	}
	return SEQ2(wr, nz);
}

// INC/DEC loc16: C is the carry out, or cleared by a borrow; V is sticky.
static RzILOpEffect *c28x_lift_incdec(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 1) {
		return NULL;
	}
	const bool inc = insn->id == C28X_INS_INC;
	RzILOpPure *one = UN(16, 1);
	RzILOpPure *res = inc ? ADD(VARL(C28X_VAL_LOCAL), one) : SUB(VARL(C28X_VAL_LOCAL), one);
	RzILOpPure *ovf = EQ(VARL(C28X_VAL_LOCAL), UN(16, inc ? 0x7fff : 0x8000));
	RzILOpEffect *body = SEQ5(
		SETL("res", res),
		SETG("n", MSB(VARL("res"))),
		SETG("z", IS_ZERO(VARL("res"))),
		SETG("c", inc ? IS_ZERO(VARL("res")) : INV(IS_ZERO(VARL(C28X_VAL_LOCAL)))),
		SETG("v", OR(VARG("v"), ovf)));
	return c28x_rmw16(&insn->ops[0], body);
}

// TSET/TCLR loc16,#bit: N and Z change only when the location is @AX.
static RzILOpEffect *c28x_lift_tset(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 2 || insn->ops[1].kind != C28X_OP_IMM) {
		return NULL;
	}
	const ut16 m = (ut16)(1u << (insn->ops[1].imm & 0xf));
	const C28xOperand *o = &insn->ops[0];
	const bool ax = o->mode == C28X_AM_REG && (o->reg == C28X_REG_AL || o->reg == C28X_REG_AH);
	RzILOpPure *res;
	if (insn->id == C28X_INS_TSET) {
		res = LOGOR(VARL(C28X_VAL_LOCAL), UN(16, m));
	} else {
		res = LOGAND(VARL(C28X_VAL_LOCAL), UN(16, (ut16)~m));
	}
	RzILOpEffect *body = SEQ2(
		SETG("tc", INV(IS_ZERO(LOGAND(VARL(C28X_VAL_LOCAL), UN(16, m))))),
		SETL("res", res));
	if (ax) {
		body = SEQ3(body, SETG("n", MSB(VARL("res"))), SETG("z", IS_ZERO(VARL("res"))));
	}
	return c28x_rmw16(o, body);
}

// ADDU/SUBU/ADDCU/SBBU ACC,loc16 and ADDCL/SUBBL ACC,loc32.
static RzILOpEffect *c28x_lift_acc_unsigned(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 2 || !c28x_is_acc(&insn->ops[0])) {
		return NULL;
	}
	const C28xInsnId id = insn->id;
	const bool sub = id == C28X_INS_SUBU || id == C28X_INS_SBBU || id == C28X_INS_SUBBL;
	const bool wide = id == C28X_INS_ADDCL || id == C28X_INS_SUBBL;
	RzILOpPure *v = wide ? VARL(C28X_VAL_LOCAL) : UNSIGNED(32, VARL(C28X_VAL_LOCAL));
	RzILOpEffect *body = id == C28X_INS_ADDU || id == C28X_INS_SUBU
		? c28x_acc_addsub(v, sub)
		: c28x_acc_addsub_carry(v, sub);
	return c28x_with_src(&insn->ops[1], wide ? 32 : 16, body);
}

// LSLL/LSRL/ASRL ACC,T shift by T(4:0); SFR ACC,T by T(3:0), SFR ACC,#n by n.
static RzILOpEffect *c28x_lift_shift_acc(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 2 || !c28x_is_acc(&insn->ops[0])) {
		return NULL;
	}
	const C28xInsnId id = insn->id;
	RzILOpPure *cnt;
	if (insn->ops[1].kind == C28X_OP_SHIFT && id == C28X_INS_SFR) {
		cnt = UN(32, (ut64)insn->ops[1].imm & 0x1f);
	} else if (insn->ops[1].kind == C28X_OP_REG && insn->ops[1].reg == C28X_REG_T) {
		cnt = c28x_t_count(32, id == C28X_INS_SFR ? 0xf : 0x1f);
	} else {
		return NULL;
	}
	RzILOpPure *arith = NULL;
	if (id == C28X_INS_ASRL) {
		arith = IL_TRUE;
	} else if (id == C28X_INS_SFR) {
		arith = VARG("sxm");
	}
	return SEQ5(SETL("sv", VARG("acc")), SETL("sc", cnt),
		c28x_shift_var(32, id != C28X_INS_LSLL, arith),
		SETG("acc", VARL("sr")), c28x_nz_acc());
}

// LSL64/LSR64/ASR64 ACC:P, by #1..16 or by T(5:0).
static RzILOpEffect *c28x_lift_shift64(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 2) {
		return NULL;
	}
	RzILOpPure *cnt;
	if (insn->ops[1].kind == C28X_OP_SHIFT) {
		cnt = UN(64, (ut64)insn->ops[1].imm & 0x3f);
	} else if (insn->ops[1].kind == C28X_OP_REG && insn->ops[1].reg == C28X_REG_T) {
		cnt = c28x_t_count(64, 0x3f);
	} else {
		return NULL;
	}
	const C28xInsnId id = insn->id;
	return SEQ6(SETL("sv", APPEND(VARG("acc"), VARG("p"))), SETL("sc", cnt),
		c28x_shift_var(64, id != C28X_INS_LSL64, id == C28X_INS_ASR64 ? IL_TRUE : NULL),
		SETG("acc", UNSIGNED(32, SHIFTR0(VARL("sr"), UN(7, 32)))),
		SETG("p", UNSIGNED(32, VARL("sr"))),
		SEQ2(SETG("n", MSB(VARL("sr"))), SETG("z", IS_ZERO(VARL("sr")))));
}

// ROL/ROR ACC rotate through C.
static RzILOpEffect *c28x_lift_rotate(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	const bool left = insn->id == C28X_INS_ROL;
	RzILOpPure *in = ITE(VARG("c"), UN(32, left ? 1 : 0x80000000), UN(32, 0));
	RzILOpPure *res = left ? LOGOR(SHIFTL0(VARL("sv"), UN(5, 1)), in)
			       : LOGOR(SHIFTR0(VARL("sv"), UN(5, 1)), in);
	return SEQ4(SETL("sv", VARG("acc")), SETG("acc", res),
		SETG("c", left ? MSB(VARL("sv")) : LSB(VARL("sv"))), c28x_nz_acc());
}

// BANZ 16bitOffset,ARn--: the branch tests ARn before the decrement.
static RzILOpEffect *c28x_lift_banz(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 2 || insn->ops[0].kind != C28X_OP_PCREL) {
		return NULL;
	}
	RzILOpPure *cur = c28x_read16(&insn->ops[1]);
	RzILOpEffect *dec = c28x_write16(&insn->ops[1], SUB(VARL("t"), UN(16, 1)), false);
	if (!cur || !dec) {
		rz_il_op_pure_free(cur);
		rz_il_op_effect_free(dec);
		return NULL;
	}
	return SEQ3(SETL("t", cur), dec,
		BRANCH(INV(IS_ZERO(VARL("t"))), JMP(UN(32, (ut64)insn->ops[0].imm)), NOP()));
}

// BAR 16bitOffset,ARn,ARm,EQ|NEQ compares two auxiliary registers.
static RzILOpEffect *c28x_lift_bar(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops < 3 || insn->ops[0].kind != C28X_OP_PCREL ||
		(insn->cond != C28X_COND_EQ && insn->cond != C28X_COND_NEQ)) {
		return NULL;
	}
	RzILOpPure *a = c28x_read16(&insn->ops[1]);
	RzILOpPure *b = c28x_read16(&insn->ops[2]);
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	RzILOpPure *eq = EQ(a, b);
	return BRANCH(insn->cond == C28X_COND_EQ ? eq : INV(eq),
		JMP(UN(32, (ut64)insn->ops[0].imm)), NOP());
}

// ASP aligns SP to an even address and records it in SPA; NASP undoes it.
static RzILOpEffect *c28x_lift_asp(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->id == C28X_INS_ASP) {
		return BRANCH(LSB(VARG("sp")),
			SEQ2(SETG("sp", ADD(VARG("sp"), UN(16, 1))), SETG("spa", IL_TRUE)),
			SETG("spa", IL_FALSE));
	}
	return BRANCH(VARG("spa"),
		SEQ2(SETG("sp", SUB(VARG("sp"), UN(16, 1))), SETG("spa", IL_FALSE)), NOP());
}

// ADRK/SBRK #8bit adjust the auxiliary register ARP selects.
static RzILOpEffect *c28x_lift_arp_adjust(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 1 || insn->ops[0].kind != C28X_OP_IMM) {
		return NULL;
	}
	const ut64 k = (ut64)insn->ops[0].imm & 0xff;
	const bool sub = insn->id == C28X_INS_SBRK;
	RzILOpEffect *eff = NULL;
	for (int n = 7; n >= 0; n--) {
		const char *r = c28x_xar_name((ut8)n);
		RzILOpPure *v = sub ? SUB(VARG(r), UN(32, k)) : ADD(VARG(r), UN(32, k));
		RzILOpEffect *one = SETG(r, v);
		eff = eff ? BRANCH(EQ(VARG("arp"), UN(3, n)), one, eff) : one;
	}
	return eff;
}

// MOVU ACC,loc16 zero-extends; MOVU loc16,OVC and MOVU OVC,loc16 move OVC.
static RzILOpEffect *c28x_lift_movu(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 2) {
		return NULL;
	}
	const C28xOperand *d = &insn->ops[0];
	const C28xOperand *s = &insn->ops[1];
	if (c28x_is_acc(d)) {
		return c28x_with_src(s, 16,
			SEQ2(SETG("acc", UNSIGNED(32, VARL(C28X_VAL_LOCAL))), c28x_nz_acc()));
	}
	if (d->kind == C28X_OP_REG && d->reg == C28X_REG_OVC) {
		return c28x_with_src(s, 16, SETG("ovc", UNSIGNED(6, VARL(C28X_VAL_LOCAL))));
	}
	if (s->kind == C28X_OP_REG && s->reg == C28X_REG_OVC) {
		return c28x_store16(d, UNSIGNED(16, VARG("ovc")));
	}
	return NULL;
}

// MOVX TL,loc16 loads TL and sign-extends it through T.
static RzILOpEffect *c28x_lift_movx(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 2) {
		return NULL;
	}
	return c28x_with_src(&insn->ops[1], 16, SETG("xt", SIGNED(32, VARL(C28X_VAL_LOCAL))));
}

// DMOV loc16 copies the word to the next address, for delay lines.
static RzILOpEffect *c28x_lift_dmov(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if (insn->nops != 1 || !c28x_is_mem(&insn->ops[0])) {
		return NULL;
	}
	RzILOpPure *next = ADD(VARL(C28X_EA_LOCAL), UN(C28X_MEM_ADDR_BITS, 1));
	return c28x_with_ea(&insn->ops[0], STOREW(c28x_byte(next), c28x_ea_load(16)));
}

typedef RzILOpEffect *(*C28xLifter)(const C28xInsn *insn, ut64 pc);

// Lifters by instruction id; ids without one are not lifted.
static const C28xLifter c28x_lifters[] = {
	[C28X_INS_NOP] = c28x_lift_nop,
	[C28X_INS_MOV] = c28x_lift_mov,
	[C28X_INS_MOVZ] = c28x_lift_mov,
	[C28X_INS_MOVL] = c28x_lift_movl,
	[C28X_INS_MOVB] = c28x_lift_movb,
	[C28X_INS_PUSH] = c28x_lift_push,
	[C28X_INS_POP] = c28x_lift_pop,
	[C28X_INS_ADDB] = c28x_lift_addb_subb,
	[C28X_INS_SUBB] = c28x_lift_addb_subb,
	[C28X_INS_ADD] = c28x_lift_add_sub,
	[C28X_INS_ADDL] = c28x_lift_add_sub,
	[C28X_INS_SUB] = c28x_lift_add_sub,
	[C28X_INS_SUBL] = c28x_lift_add_sub,
	[C28X_INS_AND] = c28x_lift_logic,
	[C28X_INS_OR] = c28x_lift_logic,
	[C28X_INS_XOR] = c28x_lift_logic,
	[C28X_INS_CMP] = c28x_lift_cmp,
	[C28X_INS_CMPL] = c28x_lift_cmp,
	[C28X_INS_CMPB] = c28x_lift_cmpb,
	[C28X_INS_MOVW] = c28x_lift_movw,
	[C28X_INS_LCR] = c28x_lift_lcr,
	[C28X_INS_LRETR] = c28x_lift_lretr,
	[C28X_INS_LSL] = c28x_lift_shift_const,
	[C28X_INS_LSR] = c28x_lift_shift_const,
	[C28X_INS_ASR] = c28x_lift_shift_const,
	[C28X_INS_TBIT] = c28x_lift_tbit,
	[C28X_INS_MPYB] = c28x_lift_mpyb,
	[C28X_INS_SETC] = c28x_lift_setc_clrc,
	[C28X_INS_CLRC] = c28x_lift_setc_clrc,
	[C28X_INS_B] = c28x_lift_branch,
	[C28X_INS_SB] = c28x_lift_branch,
	[C28X_INS_LB] = c28x_lift_branch,
	[C28X_INS_SBF] = c28x_lift_branch,
	[C28X_INS_LC] = c28x_lift_lc,
	[C28X_INS_LRET] = c28x_lift_lret,
	[C28X_INS_LRETE] = c28x_lift_lret,
	[C28X_INS_FFC] = c28x_lift_ffc,
	[C28X_INS_MPY] = c28x_lift_mpy,
	[C28X_INS_MPYU] = c28x_lift_mpy,
	[C28X_INS_MPYXU] = c28x_lift_mpy,
	[C28X_INS_MPYA] = c28x_lift_mpy,
	[C28X_INS_MPYS] = c28x_lift_mpy,
	[C28X_INS_SQRA] = c28x_lift_sqr,
	[C28X_INS_SQRS] = c28x_lift_sqr,
	[C28X_INS_MOVA] = c28x_lift_movt,
	[C28X_INS_MOVS] = c28x_lift_movt,
	[C28X_INS_MOVP] = c28x_lift_movt,
	[C28X_INS_MOVAD] = c28x_lift_movt,
	[C28X_INS_ADDUL] = c28x_lift_addul,
	[C28X_INS_SUBUL] = c28x_lift_addul,
	[C28X_INS_IMPYL] = c28x_lift_mpy32,
	[C28X_INS_IMPYXUL] = c28x_lift_mpy32,
	[C28X_INS_QMPYL] = c28x_lift_mpy32,
	[C28X_INS_QMPYUL] = c28x_lift_mpy32,
	[C28X_INS_QMPYXUL] = c28x_lift_mpy32,
	[C28X_INS_IMPYAL] = c28x_lift_mpy32,
	[C28X_INS_IMPYSL] = c28x_lift_mpy32,
	[C28X_INS_QMPYAL] = c28x_lift_mpy32,
	[C28X_INS_QMPYSL] = c28x_lift_mpy32,
	[C28X_INS_MOVH] = c28x_lift_movh,
	[C28X_INS_MAX] = c28x_lift_minmax,
	[C28X_INS_MIN] = c28x_lift_minmax,
	[C28X_INS_MAXL] = c28x_lift_minmax,
	[C28X_INS_MINL] = c28x_lift_minmax,
	[C28X_INS_SUBR] = c28x_lift_subr,
	[C28X_INS_SUBRL] = c28x_lift_subr,
	[C28X_INS_SUBCU] = c28x_lift_subcu,
	[C28X_INS_SUBCUL] = c28x_lift_subcu,
	[C28X_INS_ZALR] = c28x_lift_zalr,
	[C28X_INS_CSB] = c28x_lift_csb,
	[C28X_INS_NEG64] = c28x_lift_neg64,
	[C28X_INS_CMP64] = c28x_lift_cmp64,
	[C28X_INS_SPM] = c28x_lift_spm,
	[C28X_INS_FLIP] = c28x_lift_flip,
	[C28X_INS_MOVDL] = c28x_lift_movdl,
	[C28X_INS_PREAD] = c28x_lift_pread,
	[C28X_INS_PWRITE] = c28x_lift_pread,
	[C28X_INS_XB] = c28x_lift_xbranch,
	[C28X_INS_XCALL] = c28x_lift_xbranch,
	[C28X_INS_XRETC] = c28x_lift_xret,
	[C28X_INS_XRET] = c28x_lift_xret,
	[C28X_INS_XBANZ] = c28x_lift_xbanz,
	[C28X_INS_XPREAD] = c28x_lift_xpread,
	[C28X_INS_XPWRITE] = c28x_lift_xpread,
	[C28X_INS_MAXCUL] = c28x_lift_mincul,
	[C28X_INS_MINCUL] = c28x_lift_mincul,
	[C28X_INS_NORM] = c28x_lift_norm,
	[C28X_INS_CMPR] = c28x_lift_cmpr,
	[C28X_INS_LOOPZ] = c28x_lift_loop,
	[C28X_INS_LOOPNZ] = c28x_lift_loop,
	[C28X_INS_EALLOW] = c28x_lift_eallow,
	[C28X_INS_EDIS] = c28x_lift_eallow,
	[C28X_INS_TRAP] = c28x_lift_trap,
	[C28X_INS_INTR] = c28x_lift_intr,
	[C28X_INS_IRET] = c28x_lift_iret,
	[C28X_INS_IACK] = c28x_lift_iack,
	[C28X_INS_ESTOP0] = c28x_lift_estop,
	[C28X_INS_ESTOP1] = c28x_lift_estop,
	[C28X_INS_DINT] = c28x_lift_intm,
	[C28X_INS_EINT] = c28x_lift_intm,
	[C28X_INS_LPADDR] = c28x_lift_lpaddr,
	[C28X_INS_ZAP] = c28x_lift_zap,
	[C28X_INS_ZAPA] = c28x_lift_zapa,
	[C28X_INS_TEST] = c28x_lift_test,
	[C28X_INS_NOT] = c28x_lift_not,
	[C28X_INS_NEG] = c28x_lift_neg,
	[C28X_INS_NEGTC] = c28x_lift_neg,
	[C28X_INS_ABS] = c28x_lift_abs,
	[C28X_INS_ABSTC] = c28x_lift_abs,
	[C28X_INS_SAT] = c28x_lift_sat,
	[C28X_INS_SAT64] = c28x_lift_sat,
	[C28X_INS_SXTB] = c28x_lift_sxtb,
	[C28X_INS_ANDB] = c28x_lift_logic_byte,
	[C28X_INS_ORB] = c28x_lift_logic_byte,
	[C28X_INS_XORB] = c28x_lift_logic_byte,
	[C28X_INS_INC] = c28x_lift_incdec,
	[C28X_INS_DEC] = c28x_lift_incdec,
	[C28X_INS_TSET] = c28x_lift_tset,
	[C28X_INS_TCLR] = c28x_lift_tset,
	[C28X_INS_ADDU] = c28x_lift_acc_unsigned,
	[C28X_INS_SUBU] = c28x_lift_acc_unsigned,
	[C28X_INS_ADDCU] = c28x_lift_acc_unsigned,
	[C28X_INS_SBBU] = c28x_lift_acc_unsigned,
	[C28X_INS_ADDCL] = c28x_lift_acc_unsigned,
	[C28X_INS_SUBBL] = c28x_lift_acc_unsigned,
	[C28X_INS_LSLL] = c28x_lift_shift_acc,
	[C28X_INS_LSRL] = c28x_lift_shift_acc,
	[C28X_INS_ASRL] = c28x_lift_shift_acc,
	[C28X_INS_SFR] = c28x_lift_shift_acc,
	[C28X_INS_LSL64] = c28x_lift_shift64,
	[C28X_INS_LSR64] = c28x_lift_shift64,
	[C28X_INS_ASR64] = c28x_lift_shift64,
	[C28X_INS_ROL] = c28x_lift_rotate,
	[C28X_INS_ROR] = c28x_lift_rotate,
	[C28X_INS_BANZ] = c28x_lift_banz,
	[C28X_INS_BAR] = c28x_lift_bar,
	[C28X_INS_BF] = c28x_lift_branch,
	[C28X_INS_ASP] = c28x_lift_asp,
	[C28X_INS_NASP] = c28x_lift_asp,
	[C28X_INS_ADRK] = c28x_lift_arp_adjust,
	[C28X_INS_SBRK] = c28x_lift_arp_adjust,
	[C28X_INS_MOVU] = c28x_lift_movu,
	[C28X_INS_MOVX] = c28x_lift_movx,
	[C28X_INS_DMOV] = c28x_lift_dmov,
};

RZ_IPI RZ_OWN RzILOpEffect *c28x_lift(RZ_NONNULL const C28xInsn *insn, ut64 pc) {
	rz_return_val_if_fail(insn, NULL);
	RzILOpEffect *eff = NULL;
	if ((size_t)insn->id < RZ_ARRAY_SIZE(c28x_lifters) && c28x_lifters[insn->id]) {
		eff = c28x_lifters[insn->id](insn, pc);
	}
	// the VCU lifts its own instructions
	return eff ? eff : c28x_lift_vcu(insn, pc);
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
