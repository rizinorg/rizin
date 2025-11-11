// SPDX-FileCopyrightText: 2022 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "ppc_il.h"
#include "ppc_analysis.h"
#include "rz_types_base.h"
#include <rz_il/rz_il_opcodes.h>
#include <rz_util/rz_assert.h>
#include <capstone/capstone.h>
#include <rz_il/rz_il_opbuilder_begin.h>

static RzILOpEffect *load_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, EMPTY());
	ut32 id = insn->id;
	// READ
	const char *rT = cs_reg_name(handle, INSOP(0).reg);
	const char *rA = cs_reg_name(handle, INSOP(1).mem.base);
#if CS_NEXT_VERSION < 6
	const char *rB = cs_reg_name(handle, INSOP(2).reg);
#else
	const char *rB = cs_reg_name(handle, INSOP(1).mem.offset);
#endif
	st64 d = INSOP(1).mem.disp; // RA = base ; D = Disposition
	st64 sI = INSOP(1).imm; // liX instructions (alias for addX).
	bool update_ra = ppc_updates_ra_with_ea(id); // Save ea in RA?
	ut32 mem_acc_size = ppc_get_mem_acc_size(id);
	RzILOpPure *base;
	RzILOpPure *disp;
	RzILOpPure *ea;
	RzILOpPure *into_rt;

	if (mem_acc_size < 0) {
		NOT_IMPLEMENTED;
	}

	// How to read instruction ids:
	// Letter			Meaning
	// L 				Load
	// B/H/W/D/F 		Byte, Half Word, Word, Double Word, Float
	// Z/A/B			Zero extend, Algebraic, Byte reversal
	// U/R				Update (store EA in RA), Reserve indexed
	// X				X Form instruction (uses RB instead of immediate)
	// CIX				Caching Inhibited Indexed
	// V				Vector indexed

	// EXEC
	switch (id) {
	default:
		NOT_IMPLEMENTED;
	case PPC_INS_LI: // RT = sI
		into_rt = EXTEND(PPC_ARCH_BITS, SN(16, sI));
		update_ra = false;
		break;
	case PPC_INS_LIS: // RT = SI << 16
		into_rt = EXTEND(PPC_ARCH_BITS, APPEND(SN(16, sI), U16(0)));
		update_ra = false;
		break;
	case PPC_INS_LA: // RT = EA
		NOT_IMPLEMENTED;
	case PPC_INS_LBZ:
	case PPC_INS_LBZX:
	case PPC_INS_LBZU:
	case PPC_INS_LBZUX:
	case PPC_INS_LHZ:
	case PPC_INS_LHZX:
	case PPC_INS_LHZU:
	case PPC_INS_LHZUX:
	case PPC_INS_LWZ:
	case PPC_INS_LWZU:
	case PPC_INS_LWZUX:
	case PPC_INS_LWZX:
	case PPC_INS_LD:
	case PPC_INS_LDX:
	case PPC_INS_LDU:
	case PPC_INS_LDUX:
	case PPC_INS_LHA:
	case PPC_INS_LHAX:
	case PPC_INS_LHAU:
	case PPC_INS_LHAUX:
	case PPC_INS_LWA:
	case PPC_INS_LWAX:
	case PPC_INS_LWAUX:
	case PPC_INS_LBZCIX:
	case PPC_INS_LHZCIX:
	case PPC_INS_LWZCIX:
	case PPC_INS_LDCIX:
#if CS_NEXT_VERSION >= 6
		base = VARG(rA);
#else
		base = rA ? VARG(rA) : NULL;
#endif
		if (ppc_is_x_form(id)) {
			disp = VARG(rB);
		} else {
			// "disp << 2" done by capstone.
			RzILOpPure *imm = SN(16, d);
			disp = EXTEND(PPC_ARCH_BITS, imm);
		}
		ea = base ? ADD(base, disp) : disp;
		RzILOpPure *loadw = LOADW(mem_acc_size, VARLP("ea"));
		if (ppc_is_algebraic(id)) {
			into_rt = EXTEND(PPC_ARCH_BITS, VARLP("loadw"));
		} else {
			into_rt = EXTZ(VARLP("loadw"));
		}
		into_rt = LET("ea", ea, LET("loadw", loadw, into_rt));
		break;
	case PPC_INS_LWARX:
	case PPC_INS_LDARX:
		NOT_IMPLEMENTED;
	// Byte reverse and reserved indexed
	case PPC_INS_LHBRX:
	case PPC_INS_LWBRX:
	case PPC_INS_LDBRX:
#if CS_NEXT_VERSION >= 6
		base = VARG(rA);
#else
		base = rA ? VARG(rA) : NULL;
#endif
		disp = VARG(rB);
		ea = base ? ADD(base, disp) : disp;

#define LB(i) LOADW(8, ADD(VARLP("ea"), UA(i)))
		if (IN_BE_MODE) {
			if (id == PPC_INS_LHBRX) {
				into_rt = LET("ea", ea, APPEND(LB(0), LB(1)));
			} else if (id == PPC_INS_LWBRX) {
				into_rt = LET("ea", ea, APPEND(LB(0), APPEND(LB(1), APPEND(LB(2), LB(3)))));
			} else {
				into_rt = LET("ea", ea, APPEND(LB(0), APPEND(LB(1), APPEND(LB(2), APPEND(LB(3), APPEND(LB(4), APPEND(LB(5), APPEND(LB(6), LB(7)))))))));
			}
		} else {
			if (id == PPC_INS_LHBRX) {
				into_rt = LET("ea", ea, APPEND(LB(1), LB(0)));
			} else if (id == PPC_INS_LWBRX) {
				into_rt = LET("ea", ea, APPEND(LB(3), APPEND(LB(2), APPEND(LB(1), LB(0)))));
			} else {
				into_rt = LET("ea", ea, APPEND(LB(7), APPEND(LB(6), APPEND(LB(5), APPEND(LB(4), APPEND(LB(3), APPEND(LB(2), APPEND(LB(1), LB(0)))))))));
			}
		}
		into_rt = EXTZ(into_rt);
		break;
	// Floats
	case PPC_INS_LFD:
	case PPC_INS_LFDX:
	case PPC_INS_LFDU:
	case PPC_INS_LFDUX:
	case PPC_INS_LFIWAX:
	case PPC_INS_LFIWZX:
	case PPC_INS_LFS:
	case PPC_INS_LFSX:
	case PPC_INS_LFSU:
	case PPC_INS_LFSUX:
		NOT_IMPLEMENTED;
	// Vector
	case PPC_INS_LVEBX:
	case PPC_INS_LVEHX:
	case PPC_INS_LVEWX:
	case PPC_INS_LVSL:
	case PPC_INS_LVSR:
	case PPC_INS_LVX:
	case PPC_INS_LVXL:
		NOT_IMPLEMENTED;
	// String word
	case PPC_INS_LSWI:
		NOT_IMPLEMENTED;
	// VSX Scalar
	case PPC_INS_LXSDX:
	// VSX Vector
	case PPC_INS_LXVD2X:
	case PPC_INS_LXVDSX:
	case PPC_INS_LXVW4X:
		NOT_IMPLEMENTED;
	}

	rz_return_val_if_fail(into_rt, NULL);
	RzILOpEffect *res = SETG(rT, into_rt);
	RzILOpEffect *update = update_ra ? SETG(rA, DUP(ea)) : EMPTY();
	return SEQ2(res, update);
}

/**
 * \brief Determine log_2( \p v ). \p v must be a multiple of 2.
 * See: https://graphics.stanford.edu/~seander/bithacks.html#IntegerLog
 *
 * \param v Value to determine lg(v) for.
 * \return ut32 lg(v)
 */
static inline ut32 ppc_log_2(const ut32 v) {
	static const ut32 b[] = { 0xAAAAAAAA, 0xCCCCCCCC, 0xF0F0F0F0,
		0xFF00FF00, 0xFFFF0000 };
	register ut32 r = (v & b[0]) != 0;
	r |= ((v & b[4]) != 0) << 4;
	r |= ((v & b[3]) != 0) << 3;
	r |= ((v & b[2]) != 0) << 2;
	r |= ((v & b[1]) != 0) << 1;
	return r;
}

static RzILOpEffect *store_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, EMPTY());
	ut32 id = insn->id;

	// How to read instruction ids:
	// Letter			Meaning
	// ST 				Store
	// B/H/W/D/F 		Byte, Half Word, Word, Double Word, Float
	// BR				Byte reversal
	// U/X				Update (store EA in RA), X Form instruction (uses RB instead of immediate)
	// MW/CIX			Multiple word, Caching Inhibited Indexed
	// V				Vector

	// READ
	const char *rS = cs_reg_name(handle, INSOP(0).reg);
	const char *rA = cs_reg_name(handle, INSOP(1).mem.base);
#if CS_NEXT_VERSION < 6
	const char *rB = cs_reg_name(handle, INSOP(2).reg);
#else
	const char *rB = cs_reg_name(handle, INSOP(1).mem.offset);
#endif
	st64 d = INSOP(1).mem.disp; // RA = base ; D = Disposition
	bool update_ra = ppc_updates_ra_with_ea(id); // Save ea in RA?
	ut32 mem_acc_size = ppc_get_mem_acc_size(id);
	RzILOpPure *base;
	RzILOpPure *disp;
	RzILOpPure *ea;
	RzILOpEffect *store;

	if (mem_acc_size < 0) {
		NOT_IMPLEMENTED;
	}

	// EXEC
	switch (id) {
	default:
		NOT_IMPLEMENTED;
	case PPC_INS_DCBZ: {
		ut32 r = ppc_log_2(DCACHE_LINE_SIZE);
#if CS_NEXT_VERSION >= 6
		rA = cs_reg_name(handle, INSOP(0).mem.base);
		rB = cs_reg_name(handle, INSOP(0).mem.offset);
		base = VARG(rA);
#else
		rA = cs_reg_name(handle, INSOP(0).reg);
		rB = cs_reg_name(handle, INSOP(1).reg);
		base = rA ? VARG(rA) : NULL;
#endif

		ea = base ? ADD(base, VARG(rB)) : VARG(rB);
		// Align EA
		ea = LOGAND(ea, SHIFTL0(UA(-1), U8(r)));
		//! DCACHE_LINE_SIZE is currently hard coded. Should be replaced by config option.
		store = STOREW(ea, UN(DCACHE_LINE_SIZE * 8, 0));
		break;
	}
	case PPC_INS_STB:
	case PPC_INS_STH:
	case PPC_INS_STW:
	case PPC_INS_STD:
	case PPC_INS_STBX:
	case PPC_INS_STHX:
	case PPC_INS_STWX:
	case PPC_INS_STDX:
	case PPC_INS_STBU:
	case PPC_INS_STDU:
	case PPC_INS_STHU:
	case PPC_INS_STWU:
	case PPC_INS_STBUX:
	case PPC_INS_STHUX:
	case PPC_INS_STWUX:
	case PPC_INS_STDUX:
	case PPC_INS_STBCIX:
	case PPC_INS_STHCIX:
	case PPC_INS_STWCIX:
	case PPC_INS_STDCIX:
#if CS_NEXT_VERSION >= 6
		base = VARG(rA);
#else
		base = rA ? VARG(rA) : NULL;
#endif
		if (ppc_is_x_form(id)) {
			disp = VARG(rB);
		} else {
			disp = EXTEND(PPC_ARCH_BITS, S16(d));
		}
		ea = base ? ADD(base, disp) : disp;
		store = STOREW(ea, CAST(mem_acc_size, IL_FALSE, VARG(rS)));
		break;
	case PPC_INS_STDCX:
	case PPC_INS_STWCX:
	// Float
	case PPC_INS_STFD:
	case PPC_INS_STFDU:
	case PPC_INS_STFDUX:
	case PPC_INS_STFDX:
	case PPC_INS_STFIWX:
	case PPC_INS_STFS:
	case PPC_INS_STFSU:
	case PPC_INS_STFSUX:
	case PPC_INS_STFSX:
		NOT_IMPLEMENTED;
	// Byte reverse and reserved indexed
	case PPC_INS_STHBRX:
	case PPC_INS_STWBRX:
	case PPC_INS_STDBRX:
		NOT_IMPLEMENTED;
	// Multiple word
	case PPC_INS_STMW:
		NOT_IMPLEMENTED;
	// String word
	case PPC_INS_STSWI:
		NOT_IMPLEMENTED;
	// Vector
	case PPC_INS_STVEBX:
	case PPC_INS_STVEHX:
	case PPC_INS_STVEWX:
	case PPC_INS_STVX:
	case PPC_INS_STVXL:
		NOT_IMPLEMENTED;
	// VSX Vector
	case PPC_INS_STXSDX:
	case PPC_INS_STXVD2X:
	case PPC_INS_STXVW4X:
		NOT_IMPLEMENTED;
	}

	// WRITE
	rz_return_val_if_fail(store, NULL);
	RzILOpEffect *update = update_ra ? SETG(rA, DUP(ea)) : EMPTY();
	return SEQ2(store, update);
}

/**
 * NOTE: Instructions which set the 'OV' bit are not yet supported by capstone.
 */
static RzILOpEffect *add_sub_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, bool add, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, EMPTY());
	ut32 id = insn->id;

	// READ
	const char *rT = cs_reg_name(handle, INSOP(0).reg);
	const char *rA = cs_reg_name(handle, INSOP(1).reg);
	const char *rB = cs_reg_name(handle, INSOP(2).reg);
	st64 sI = INSOP(2).imm;

	bool set_ca = (id != PPC_INS_ADD && id != PPC_INS_ADDI && id != PPC_INS_ADDIS && id != PPC_INS_SUBF && id != PPC_INS_NEG);
	bool cr0 = insn->detail->ppc.update_cr0;

	RzILOpPure *a = NULL;
	RzILOpPure *b = NULL;
	RzILOpPure *c = NULL;
	RzILOpPure *res = NULL;

	// How to read instruction ids:
	// Letter		Meaning
	// ADD/SUBF		Add, Subtract from
	// I/M/Z 		Immediate, Minus one, Zero extend,
	// C/E/S		Carry (sets it), Extends (adds carry it), Shift immediate

#if CS_NEXT_VERSION >= 6
	// Handle Add alias
	switch (insn->alias_id) {
	default:
		break;
	case PPC_INS_ALIAS_LI: // RT = sI
		return SETG(rT, EXTEND(PPC_ARCH_BITS, SN(16, sI)));
	case PPC_INS_ALIAS_LIS: // RT = SI << 16
		return SETG(rT, EXTEND(PPC_ARCH_BITS, APPEND(SN(16, sI), U16(0))));
	}
#endif

	// EXEC
	switch (id) {
	default:
		NOT_IMPLEMENTED;
	case PPC_INS_ADD:
	case PPC_INS_ADDC:
	case PPC_INS_SUBF:
	case PPC_INS_SUBFC:
		a = add ? VARG(rA) : ADD(LOGNOT(VARG(rA)), UA(1));
		b = VARG(rB);
		res = ADD(VARL("a"), VARL("b"));
		break;
	case PPC_INS_ADDE:
	case PPC_INS_SUBFE:
		a = add ? VARG(rA) : LOGNOT(VARG(rA));
		b = VARG(rB);
		c = BOOL_TO_BV(VARG("ca"), PPC_ARCH_BITS);
		res = ADD(VARL("a"), ADD(VARL("b"), VARL("c")));
		break;
	case PPC_INS_ADDI:
	case PPC_INS_ADDIC:
	case PPC_INS_ADDIS:
	case PPC_INS_SUBFIC:
		a = add ? VARG(rA) : LOGNOT(VARG(rA));
		if (id == PPC_INS_ADDIS) {
			b = EXTEND(PPC_ARCH_BITS, APPEND(SN(16, sI), U16(0)));
		} else if (id == PPC_INS_SUBFIC) {
			b = EXTEND(PPC_ARCH_BITS, SN(16, sI));
			c = UA(1);
		} else {
			b = EXTEND(PPC_ARCH_BITS, SN(16, sI));
		}

		if (c) {
			res = ADD(VARL("a"), ADD(VARL("b"), VARL("c")));
			break;
		}
		res = ADD(VARL("a"), VARL("b"));
		break;
	case PPC_INS_ADDME:
	case PPC_INS_ADDZE:
	case PPC_INS_SUBFME:
	case PPC_INS_SUBFZE:
		a = add ? VARG(rA) : LOGNOT(VARG(rA));
		b = BOOL_TO_BV(VARG("ca"), PPC_ARCH_BITS);
		if (id == PPC_INS_ADDME || id == PPC_INS_SUBFME) {
			c = UA(-1);
			res = ADD(VARL("a"), ADD(VARL("b"), VARL("c")));
		} else {
			res = ADD(VARL("a"), VARL("b"));
		}
		break;
	case PPC_INS_NEG:
		a = LOGNOT(VARG(rA));
		b = UA(1);
		res = ADD(VARL("a"), VARL("b"));
	}
	if (!(a && b)) {
		rz_warn_if_reached();
		return NULL;
	}

	RzILOpEffect *set_carry = set_ca ? ppc_set_carry_add_sub(VARL("a"), VARL("b"), c ? VARL("c") : NULL, mode) : EMPTY();

	// Instructions which set the OV bit are not supported in capstone.
	// See: https://github.com/capstone-engine/capstone/issues/944
	RzILOpPure *zero = UA(0);
	RzILOpEffect *overflow = EMPTY();
	RzILOpEffect *update_cr0 = cr0 ? ppc_cmp_set_cr(res, zero, true, "cr0", mode) : EMPTY();
	RzILOpEffect *set = SETG(rT, res);
	RzILOpEffect *set_ops = SEQ3(SETL("a", a), SETL("b", b), c ? SETL("c", c) : EMPTY());
	rz_il_op_pure_free(zero);
	return SEQ5(set_ops, set, set_carry, overflow, update_cr0);
}

static bool is_logical_compare(ut32 id) {
	switch (id) {
	case PPC_INS_CMPW:
	case PPC_INS_CMPD:
	case PPC_INS_CMPWI:
	case PPC_INS_CMPDI:
		return true;
	default:
		return false;
	}
}

static RzILOpEffect *compare_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, EMPTY());
	ut32 id = insn->id;
	const char *crX = NULL;
	const char *rA = NULL;
	const char *rB = NULL;
	st64 imm = 0;

	RzILOpPure *left = NULL;
	RzILOpPure *right = NULL;

	bool signed_cmp = false;

#if CS_API_MAJOR == 5 && CS_NEXT_VERSION < 6
	// weird bug on cmp/cmpl in capstone v5
	if (id == PPC_INS_CMP) {
		if (!strcmp(insn->mnemonic, "cmpw")) {
			id = PPC_INS_CMPW;
		} else if (!strcmp(insn->mnemonic, "cmpd")) {
			id = PPC_INS_CMPD;
		} else {
			rz_warn_if_reached();
		}
	} else if (id == PPC_INS_CMPL) {
		if (!strcmp(insn->mnemonic, "cmplw")) {
			id = PPC_INS_CMPLW;
		} else if (!strcmp(insn->mnemonic, "cmpld")) {
			id = PPC_INS_CMPLD;
		} else {
			rz_warn_if_reached();
		}
	} else if (id == PPC_INS_CMPI) {
		if (!strcmp(insn->mnemonic, "cmpwi")) {
			id = PPC_INS_CMPWI;
		} else if (!strcmp(insn->mnemonic, "cmpdi")) {
			id = PPC_INS_CMPDI;
		} else {
			rz_warn_if_reached();
		}
	} else if (id == PPC_INS_CMPLI) {
		if (!strcmp(insn->mnemonic, "cmplwi")) {
			id = PPC_INS_CMPLWI;
		} else if (!strcmp(insn->mnemonic, "cmpldi")) {
			id = PPC_INS_CMPLDI;
		} else {
			rz_warn_if_reached();
		}
	}
#endif

	// READ
#if CS_NEXT_VERSION >= 6
	// Uses REAL instruction operand set.
	crX = cs_reg_name(handle, INSOP(0).reg);
	rA = cs_reg_name(handle, INSOP(1).reg);
	rB = cs_reg_name(handle, INSOP(2).reg);
	imm = INSOP(2).imm;
#else
	// cr0 reg is not explicitly stored in the operands list.
	if (OP_CNT == 2) {
		crX = "cr0";
		rA = cs_reg_name(handle, INSOP(0).reg);
		rB = cs_reg_name(handle, INSOP(1).reg);
		imm = INSOP(1).imm;
	} else {
		crX = cs_reg_name(handle, INSOP(0).reg);
		rA = cs_reg_name(handle, INSOP(1).reg);
		rB = cs_reg_name(handle, INSOP(2).reg);
		imm = INSOP(2).imm;
	}
#endif

	// How to read instruction ids:
	// Letter			Meaning
	// CMP				Compare
	// B/H/W/D	 		Byte, Half Word, Word, Double Word
	// I/L				Immediate, Logical (unsigned compare)

	// EXEC
	// Logical <=> unsigned comparisons ; Not logical <=> signed comparison.
	signed_cmp = is_logical_compare(id);

	// Left operand is always RA
	if (id == PPC_INS_CMPW || id == PPC_INS_CMPWI || id == PPC_INS_CMPLW || id == PPC_INS_CMPLWI) {
		left = EXTS(CAST(32, IL_FALSE, VARG(rA)));
	} else {
		left = VARG(rA);
	}

	// Right operand differs between instructions.
	switch (id) {
	default:
		NOT_IMPLEMENTED;
	case PPC_INS_CMPW:
	case PPC_INS_CMPLW:
		right = EXTS(CAST(32, IL_FALSE, VARG(rB)));
		break;
	case PPC_INS_CMPD:
	case PPC_INS_CMPLD:
		right = VARG(rB);
		break;
	case PPC_INS_CMPWI:
	case PPC_INS_CMPLWI:
		right = (id == PPC_INS_CMPWI) ? EXTS(S16(imm)) : EXTZ(U16(imm));
		break;
	case PPC_INS_CMPDI:
	case PPC_INS_CMPLDI:
		right = (id == PPC_INS_CMPDI) ? EXTEND(64, S16(imm)) : APPEND(U48(0), U16(imm));
		break;
	}
	RzILOpEffect *ret = ppc_cmp_set_cr(left, right, signed_cmp, crX, mode);
	rz_il_op_pure_free(left);
	rz_il_op_pure_free(right);
	return ret;
}

#if CS_API_MAJOR == 5 && CS_NEXT_VERSION < 6
// bug on xori in capstone v5
static bool is_xnop(cs_insn *insn) {
	return insn->id == PPC_INS_XNOP &&
		INSOP(0).reg == 0 &&
		INSOP(1).reg == 0 &&
		INSOP(2).imm == 0;
}
#endif

static RzILOpEffect *bitwise_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, EMPTY());
#if CS_API_MAJOR == 5 && CS_NEXT_VERSION < 6
	if (is_xnop(insn)) {
		return NOP();
	}
#endif

	ut32 id = insn->id;
	// READ
	const char *rA = cs_reg_name(handle, INSOP(0).reg);
	const char *rS = cs_reg_name(handle, INSOP(1).reg);
	const char *rB = cs_reg_name(handle, INSOP(2).reg);
	st64 uI = INSOP(2).imm;
	bool cr0 = insn->detail->ppc.update_cr0;
	RzILOpPure *op0;
	RzILOpPure *op1;
	RzILOpPure *res;

	// How to read instruction ids:
	// Letter			Meaning
	// AND/OR/... 		AND, OR etc.
	// B/H/W/D	 		Byte, Half Word, Word, Double Word
	// I/C/S			Immediate, Complement, Shifted

	// EXEC
	switch (id) {
	default:
		NOT_IMPLEMENTED;
	case PPC_INS_AND:
	case PPC_INS_ANDC:
	case PPC_INS_ANDIS:
	case PPC_INS_ANDI:
		op0 = VARG(rS);
		if (id == PPC_INS_AND || id == PPC_INS_ANDC) {
			op1 = (id == PPC_INS_AND) ? VARG(rB) : LOGNOT(VARG(rB));
		} else {
			op1 = (id == PPC_INS_ANDI) ? EXTZ(U16(uI)) : EXTZ(APPEND(U16(uI), U16(0)));
		}
		res = LOGAND(op0, op1);
		break;
	case PPC_INS_OR:
	case PPC_INS_ORC:
	case PPC_INS_ORI:
	case PPC_INS_ORIS:
		op0 = VARG(rS);
		if (id == PPC_INS_OR || id == PPC_INS_ORC) {
			op1 = (id == PPC_INS_OR) ? VARG(rB) : LOGNOT(VARG(rB));
		} else {
			op1 = (id == PPC_INS_ORI) ? EXTZ(U16(uI)) : EXTZ(APPEND(U16(uI), U16(0)));
		}
		res = LOGOR(op0, op1);
		break;
#if CS_NEXT_VERSION < 6
		// bug on xori in capstone v5
	case PPC_INS_XNOP:
		op0 = VARG(rS);
		op1 = EXTZ(U16(uI));
		res = LOGXOR(op0, op1);
		break;
#endif
	case PPC_INS_XOR:
	case PPC_INS_XORI:
	case PPC_INS_XORIS:
		op0 = VARG(rS);
		if (id == PPC_INS_XOR) {
			op1 = VARG(rB);
		} else {
			op1 = (id == PPC_INS_XORI) ? EXTZ(U16(uI)) : EXTZ(APPEND(U16(uI), U16(0)));
		}
		res = LOGXOR(op0, op1);
		break;
	case PPC_INS_NAND:
	case PPC_INS_NOR:
		op0 = VARG(rS);
		op1 = VARG(rB);
		res = LOGNOT(
			(id == PPC_INS_NAND) ? LOGAND(op0, op1) : LOGOR(op0, op1));
		break;
	// Compare bytes
	case PPC_INS_CMPB: {
		//	do n = 0 to (64BIT_CPU ? 7 : 3)
		//		if RS[8×n:8×n+7] = RB[8×n:8×n+7] then
		// 			RA[8×n:8×n+7] ← 0b1111_1111
		//		else
		//			RA[8×n:8×n+7] ← 0b0000_0000

		ut8 bits = PPC_ARCH_BITS;
		RzILOpEffect *loop, *init_n, *init_bitmask, *ones_rA;

		RzILOpPure *bitmask_n_n7 = BIT_MASK(bits, MUL(U8(8), VARL("n")), ADD(MUL(U8(8), VARL("n")), U8(7)));
		//  RS[8×n:8×n+7]
		RzILOpPure *rS_8n_8n7 = LOGAND(VARL("bitmask_n_n7"), VARG(rS));
		//  RB[8×n:8×n+7]
		RzILOpPure *rB_8n_8n7 = LOGAND(VARL("bitmask_n_n7"), VARG(rB));
		RzILOpPure *b_cond = EQ(rS_8n_8n7, rB_8n_8n7);

		init_n = SETL("n", U8(0));
		init_bitmask = SETL("bitmask_n_n7", bitmask_n_n7);
		// RA[8×n:8×n+7] ← 0b1111_1111
		ones_rA = SETL("res", LOGOR(VARL("res"), LOGAND(UA(-1), VARL("bitmask_n_n7"))));
		ut8 m = IN_64BIT_MODE ? 8 : 4;

		loop = REPEAT(ULT(VARL("n"), U8(m)),
			SEQ3(BRANCH(b_cond,
				     ones_rA, EMPTY()),
				SETL("n", ADD(VARL("n"), U8(1))),
				SETL("bitmask_n_n7", DUP(bitmask_n_n7))));

		return SEQ5(SETL("res", UA(0)), init_n, init_bitmask, loop, SETG(rA, VARL("res")));
	}
	case PPC_INS_EQV:
		op0 = VARG(rS);
		op1 = VARG(rB);
		res = LOGXOR(op0, LOGNOT(op1));
		break;
	// Extend
	case PPC_INS_EXTSB:
		res = EXTS(UNSIGNED(PPC_BYTE, VARG(rS)));
		break;
	case PPC_INS_EXTSH:
		res = EXTS(UNSIGNED(PPC_HWORD, VARG(rS)));
		break;
	case PPC_INS_EXTSW:
		res = EXTS(UNSIGNED(PPC_WORD, VARG(rS)));
		break;
	// Count leading zeros
	case PPC_INS_CNTLZD:
	case PPC_INS_CNTLZW: {
		RzILOpEffect *n, *set_m;
		if ((id == PPC_INS_CNTLZW) && IN_64BIT_MODE) {
			n = SETL("n", UA(32));
			set_m = SETL("m", UA(32));
		} else {
			n = SETL("n", UA(0));
			set_m = SETL("m", UA(0));
		}
		RzILOpPure *cond = AND(ULT(VARL("n"), UA(PPC_ARCH_BITS)), INV(BIT_IS_SET(VARG(rS), PPC_ARCH_BITS, VARL("n"))));
		RzILOpEffect *cloop = REPEAT(cond, SETL("n", ADD(VARL("n"), UA(1))));
		return SEQ4(set_m, n, cloop, SETG(rA, SUB(VARL("n"), VARL("m"))));
	}
	// Population count
	case PPC_INS_POPCNTD:
	case PPC_INS_POPCNTW:
		NOT_IMPLEMENTED;
	}

	// WRITE
	RzILOpPure *zero = UA(0);
	RzILOpPure *old_res = VARL("res");
	RzILOpEffect *update_cr0 = cr0 ? ppc_cmp_set_cr(old_res, zero, true, "cr0", mode) : EMPTY();
	RzILOpEffect *set = SETG(rA, old_res);
	rz_il_op_pure_free(zero);
	return SEQ3(SETL("res", res), set, update_cr0);
}

static RzILOpEffect *branch_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, EMPTY());
#if CS_NEXT_VERSION >= 6
	bool is_conditional = ppc_insn_is_conditional(insn);
#else
	ut32 id = insn->id;
	bool is_conditional = ppc_is_conditional(id);
#endif
	RzILOpEffect *set_cia; // Current instruction address
	RzILOpEffect *set_nia; // Next instruction address
	RzILOpEffect *set_lr; // Set Link Register
	RzILOpEffect *decr_ctr; // Effect to decrement CTR

	// How to read instruction ids:
	// Letter			Meaning
	// B 				Branch
	// C/D				Conditional, Decrement CTR
	// Z/NZ/T/F			Branch if CTR is: zero/not zero, branch if CR=1 (true)/CR=0 (false)
	// L/A/LR/CTR/TAR	Set LR, branch to absolute address, branch to LR, branch to CTR, branch to target address register

	// Determine next instruction address.
	if (!is_conditional) {
		set_nia = SETL("NIA", ppc_get_branch_ta(insn, mode));
	} else {
		set_nia = SETL("NIA", ITE(ppc_get_branch_cond(handle, insn, mode), ppc_get_branch_ta(insn, mode), ADD(VARL("CIA"), UA(4))));
	}

	set_cia = SETL("CIA", UA(insn->address));
#if CS_NEXT_VERSION >= 6
	set_lr = ppc_insn_sets_lr(insn) ? SETG("lr", ADD(VARL("CIA"), UA(4))) : EMPTY();
#else
	set_lr = ppc_sets_lr(id) ? SETG("lr", ADD(VARL("CIA"), UA(4))) : EMPTY();
#endif
	decr_ctr = ppc_decrements_ctr(insn, mode) ? SETG("ctr", SUB(VARG("ctr"), UA(1))) : EMPTY();

	return SEQ5(set_cia, decr_ctr, set_lr, set_nia, JMP(VARL("NIA")));
}

/**
 * NOTE: Instructions which set the 'OV' bit are not yet supported by Capstone.
 */
static RzILOpEffect *div_mul_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, EMPTY());
	ut32 id = insn->id;

	// READ
	const char *rT = cs_reg_name(handle, INSOP(0).reg);
	const char *rA = cs_reg_name(handle, INSOP(1).reg);
	const char *rB = cs_reg_name(handle, INSOP(2).reg);
	st64 sI = INSOP(2).imm;
	bool set_cr0 = insn->detail->ppc.update_cr0;

	RzILOpPure *op0;
	RzILOpPure *op1;
	RzILOpPure *prod;

	// How to read instruction IDs:
	// Letter			Meaning
	// MUL/DIV 			Multiply, Divide
	// W/D/LW/HW/LI		Word, double word, low word, high word, Low immediate
	// O/U/E			Overflow (not supported), Unsigned, Extended

	if (id == PPC_INS_MULLI) {
		op0 = VARG(rA);
		op1 = S16(sI);
	} else {
		op0 = VARG(rA);
		op1 = VARG(rB);
	}

	if (id == PPC_INS_MULHW || id == PPC_INS_MULLW || id == PPC_INS_DIVW) {
		op0 = UNSIGNED(32, op0);
		op1 = UNSIGNED(32, op1);
	} else if (id == PPC_INS_DIVWU || id == PPC_INS_MULHWU) {
		op0 = SIGNED(32, op0);
		op1 = SIGNED(32, op1);
	}

	if (ppc_is_mul_div_u(id) && ppc_is_mul_div_d(id, mode)) {
		op0 = UNSIGNED(128, op0);
		op1 = UNSIGNED(128, op1);
	} else if (ppc_is_mul_div_u(id) && !ppc_is_mul_div_d(id, mode)) {
		op0 = UNSIGNED(64, op0);
		op1 = UNSIGNED(64, op1);
	} else if (!ppc_is_mul_div_u(id) && ppc_is_mul_div_d(id, mode)) {
		op0 = SIGNED(128, op0);
		op1 = SIGNED(128, op1);
	} else {
		op0 = SIGNED(64, op0);
		op1 = SIGNED(64, op1);
	}

	switch (id) {
	default:
		NOT_IMPLEMENTED;
	case PPC_INS_MULHD:
	case PPC_INS_MULHDU:
	case PPC_INS_MULHW:
	case PPC_INS_MULHWU:
	case PPC_INS_MULLI:
	case PPC_INS_MULLD:
	case PPC_INS_MULLW:
		prod = MUL(op0, op1);
		break;
	case PPC_INS_DIVWU:
	case PPC_INS_DIVDU:
		prod = DIV(op0, op1);
		break;
	case PPC_INS_DIVW:
	case PPC_INS_DIVD:
		prod = SDIV(op0, op1);
		break;
	}

	// Get high word/double word of product.
	if (id == PPC_INS_MULHW || id == PPC_INS_MULHWU) {
		prod = SHIFTR0(prod, U8(32));
	} else if (id == PPC_INS_MULHD || id == PPC_INS_MULHDU) {
		prod = SHIFTR0(prod, U8(64));
	}

	RzILOpEffect *cr0 = set_cr0 ? ppc_cmp_set_cr(VARG(rT), UA(0), true, "cr0", mode) : EMPTY();
	return SEQ2(SETG(rT, CAST(PPC_ARCH_BITS, IL_FALSE, prod)), cr0);
}

static RzILOpEffect *move_from_to_spr_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, EMPTY());
	ut32 id = insn->id;

#if CS_NEXT_VERSION >= 6
	const char *rS;
	const char *rT;
	if (insn->id == PPC_INS_MFSPR || insn->id == PPC_INS_MTSPR) {
		rT = cs_reg_name(handle, INSOP(0).reg);
		rS = cs_reg_name(handle, INSOP(1).reg);
	} else {
		rS = cs_reg_name(handle, INSOP(0).reg);
		rT = cs_reg_name(handle, INSOP(0).reg);
	}
#else
	const char *rS = cs_reg_name(handle, INSOP(0).reg);
	const char *rT = cs_reg_name(handle, INSOP(0).reg);
#endif
	const char *spr_name = "";
	// Some registers need to assemble the value before it is read or written (e.g. XER with all its bits).
	// Leave it NULL if the value of the SPR or RS should be used.
	RzILOpEffect *set_val = NULL;
	// Size of the value written to the target register (SPR or RT)
	ut32 size = PPC_ARCH_BITS;

	switch (id) {
	default:
		NOT_IMPLEMENTED;
	case PPC_INS_MTDCR:
	case PPC_INS_MFDCR:
		NOT_IMPLEMENTED;
	case PPC_INS_MFVSCR:
	case PPC_INS_MTVSCR:
		NOT_IMPLEMENTED;
		break;
	case PPC_INS_MFMSR:
		spr_name = "msr";
		break;
	case PPC_INS_MTMSR:
	case PPC_INS_MTMSRD:
		NOT_IMPLEMENTED;
	case PPC_INS_MTCRF: {
		ut32 mask = 0xffffffff;
		if (id == PPC_INS_MTCRF) {
			ut8 fxm = INSOP(0).imm;
			rS = cs_reg_name(handle, INSOP(1).reg);
			mask = ppc_fmx_to_mask(fxm);
		}
		RzILOpEffect *set_cr = SETL("cr", LOGAND(UNSIGNED(32, VARG(rS)), U32(mask)));
		return SEQ2(set_cr, ppc_sync_crx_cr(false, mask));
	}
	case PPC_INS_MFCR:
		return SEQ2(ppc_sync_crx_cr(true, 0x0), SETG(rT, EXTZ(VARL("cr"))));

	// Note: We do not update CR after the OCRF operations.
	case PPC_INS_MTOCRF:
	case PPC_INS_MFOCRF:
#if CS_NEXT_VERSION >= 6
		rS = cs_reg_name(handle, INSOP(1).reg);
		rT = cs_reg_name(handle, INSOP(0).reg);
		spr_name = rT;
		size = 4;
		set_val = SETL("val", VARG(rS));
#else
		NOT_IMPLEMENTED;
#endif
		break;
	// IBM POWER specific Segment Register
	case PPC_INS_MTSRIN:
	case PPC_INS_MFSRIN:
		// Indirect set.
	case PPC_INS_MFSR:
	case PPC_INS_MTSR:
		// Direct set.
		NOT_IMPLEMENTED;
	case PPC_INS_MFLR:
	case PPC_INS_MTLR:
		spr_name = "lr";
		break;
	case PPC_INS_MFCTR:
	case PPC_INS_MTCTR:
		spr_name = "ctr";
		break;
#if CS_NEXT_VERSION < 6
	case PPC_INS_MFXER:
	case PPC_INS_MTXER:
		if (id == PPC_INS_MTXER) {
			return ppc_set_xer(VARG(rS), mode);
		}
		spr_name = "xer";
		set_val = SETL("val", ppc_get_xer(mode));
		break;
#endif
	case PPC_INS_MFSPR:
	case PPC_INS_MTSPR: {
#if CS_NEXT_VERSION >= 6
		if (insn->alias_id == PPC_INS_ALIAS_MTXER) {
			return ppc_set_xer(VARG(rS), mode);
		} else if (insn->alias_id == PPC_INS_ALIAS_MFXER) {
			set_val = SETL("val", ppc_get_xer(mode));
			break;
		}
#endif
		ut32 spr = INSOP(1).imm;
		switch (spr) {
		default:
			// TODO Invoke different exception handlers. But they are not implemented yet.
			NOT_IMPLEMENTED;
		case 808:
		case 809:
		case 810:
		case 811:
			// Reserved. Treated as No-ops
			RZ_LOG_WARN("Reserved SPR instruction encountered at 0x%" PFMT64x "\n", (ut64)insn->address);
			return EMPTY();
		case 1:
		case 3:
		case 8:
		case 9:
		case 13:
		case 256:
		case 769:
		case 770:
		case 771:
		case 772:
		case 773:
		case 774:
		case 775:
		case 776:
		case 779:
		case 800:
		case 801:
		case 802:
		case 803:
		case 804:
		case 805:
		case 806:
		case 898:
		case 815:
		case 896:
			NOT_IMPLEMENTED;
		}
		break;
	}
	// WRITE/READ only
	case PPC_INS_MTFSB0:
	case PPC_INS_MTFSB1:
	case PPC_INS_MTFSF:
	case PPC_INS_MFFS:
	case PPC_INS_MFTB:
#if CS_NEXT_VERSION < 6
	case PPC_INS_MFRTCU:
	case PPC_INS_MFRTCL:
		NOT_IMPLEMENTED;
	// Not yet handled
	case PPC_INS_MFBR0:
	case PPC_INS_MFBR1:
	case PPC_INS_MFBR2:
	case PPC_INS_MFBR3:
	case PPC_INS_MFBR4:
	case PPC_INS_MFBR5:
	case PPC_INS_MFBR6:
	case PPC_INS_MFBR7:
	case PPC_INS_MTBR0:
	case PPC_INS_MTBR1:
	case PPC_INS_MTBR2:
	case PPC_INS_MTBR3:
	case PPC_INS_MTBR4:
	case PPC_INS_MTBR5:
	case PPC_INS_MTBR6:
	case PPC_INS_MTBR7:
		NOT_IMPLEMENTED;
	case PPC_INS_MFDSCR:
	case PPC_INS_MTDSCR:
		NOT_IMPLEMENTED;
	case PPC_INS_MFDSISR:
	case PPC_INS_MFDAR:
	case PPC_INS_MFSRR2:
	case PPC_INS_MFSRR3:
	case PPC_INS_MFCFAR:
	case PPC_INS_MFAMR:
	case PPC_INS_MFPID:
	case PPC_INS_MFTBLO:
	case PPC_INS_MFTBHI:
#if CS_NEXT_VERSION >= 6
	case PPC_INS_MFDBATU0:
	case PPC_INS_MFDBATL0:
	case PPC_INS_MFDBATU1:
	case PPC_INS_MFDBATL1:
	case PPC_INS_MFDBATU2:
	case PPC_INS_MFDBATL2:
	case PPC_INS_MFDBATU3:
	case PPC_INS_MFDBATL3:
	case PPC_INS_MFIBATU0:
	case PPC_INS_MFIBATL0:
	case PPC_INS_MFIBATU1:
	case PPC_INS_MFIBATL1:
	case PPC_INS_MFIBATU2:
	case PPC_INS_MFIBATL2:
	case PPC_INS_MFIBATU3:
	case PPC_INS_MFIBATL3:
#endif
	case PPC_INS_MFDBATU:
	case PPC_INS_MFDBATL:
	case PPC_INS_MFIBATU:
	case PPC_INS_MFIBATL:
	case PPC_INS_MFDCCR:
	case PPC_INS_MFICCR:
	case PPC_INS_MFDEAR:
	case PPC_INS_MFESR:
	case PPC_INS_MFSPEFSCR:
	case PPC_INS_MFTCR:
	case PPC_INS_MFASR:
	case PPC_INS_MFPVR:
	case PPC_INS_MFTBU:
	case PPC_INS_MTDSISR:
	case PPC_INS_MTDAR:
	case PPC_INS_MTSRR2:
	case PPC_INS_MTSRR3:
	case PPC_INS_MTCFAR:
	case PPC_INS_MTAMR:
	case PPC_INS_MTPID:
	case PPC_INS_MTTBL:
	case PPC_INS_MTTBU:
	case PPC_INS_MTTBLO:
	case PPC_INS_MTTBHI:
#if CS_NEXT_VERSION >= 6
	case PPC_INS_MTDBATU0:
	case PPC_INS_MTDBATL0:
	case PPC_INS_MTDBATU1:
	case PPC_INS_MTDBATL1:
	case PPC_INS_MTDBATU2:
	case PPC_INS_MTDBATL2:
	case PPC_INS_MTDBATU3:
	case PPC_INS_MTDBATL3:
	case PPC_INS_MTIBATU0:
	case PPC_INS_MTIBATL0:
	case PPC_INS_MTIBATU1:
	case PPC_INS_MTIBATL1:
	case PPC_INS_MTIBATU2:
	case PPC_INS_MTIBATL2:
	case PPC_INS_MTIBATU3:
	case PPC_INS_MTIBATL3:
#endif
	case PPC_INS_MTDBATU:
	case PPC_INS_MTDBATL:
	case PPC_INS_MTIBATU:
	case PPC_INS_MTIBATL:
	case PPC_INS_MTDCCR:
	case PPC_INS_MTICCR:
	case PPC_INS_MTDEAR:
	case PPC_INS_MTESR:
	case PPC_INS_MTSPEFSCR:
	case PPC_INS_MTTCR:
#endif
		NOT_IMPLEMENTED;
	}
	if (set_val) {
		RzILOpEffect *write_spr = ppc_moves_to_spr(id) ? SETG(spr_name, UNSIGNED(size, VARL("val"))) : SETG(rT, EXTZ(VARL("val")));
		return SEQ2(set_val, write_spr);
	}
	return ppc_moves_to_spr(id) ? SETG(spr_name, UNSIGNED(size, VARG(rS))) : SETG(rT, EXTZ(VARG(spr_name)));
}

/**
 *
 * NOTE: Shift instructions are not implemented as in the programmer reference manual.
 * The manual uses rotate, here we simply use SHIFT ops.
 */
static RzILOpEffect *shift_and_rotate(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, EMPTY());
	ut32 id = insn->id;
	bool sets_cr0 = insn->detail->ppc.update_cr0;

	// READ
	const char *rA = cs_reg_name(handle, INSOP(0).reg);
	const char *rS = cs_reg_name(handle, INSOP(1).reg);
	const char *rB = cs_reg_name(handle, INSOP(2).reg);
	ut64 sH = INSOP(2).imm;
	ut64 mB = INSOP(3).imm;
	ut64 mE = INSOP(4).imm;
	ut8 b, e; // Mask begin/end
	bool all_bits_set = false;

	RzILOpPure *n; // Shift/rotate steps
	RzILOpPure *r; // Rotate result
	RzILOpPure *into_rA = NULL;
	RzILOpPure *ca_val; // Arithmetic shift instructions set the ca field.
	RzILOpEffect *set_mask = NULL, *set_ca = NULL, *update_cr0 = NULL;

	// How to read instruction ids:
	// Letter			Meaning
	// R/S				Rotate, Shift
	// L/R				Left, Right
	// W/D		 		Word, Double Word
	// A/I				Algebraic, Immediate
	// C/CL/CR			Clear, clear left/right
	// M/NM/MI			Mask, AND with mask, mask insert

// FIXME: With update to auto-sync ppc arch
#if CS_API_MAJOR == 5 && CS_API_MINOR == 0 && CS_NEXT_VERSION < 6
	// weird bug on capstone v5.0
	if (id == PPC_INS_CLRLDI && !strcmp(insn->mnemonic, "rldicl")) {
		id = PPC_INS_RLDICL;
	} else if (id == PPC_INS_CLRLWI && !strcmp(insn->mnemonic, "rlwinm")) {
		id = PPC_INS_RLWINM;
	}
#endif
#if CS_NEXT_VERSION >= 6
	if (insn->alias_id == PPC_INS_ALIAS_SLWI) {
		id = PPC_INS_SLWI;
	} else if (insn->alias_id == PPC_INS_ALIAS_SRWI) {
		id = PPC_INS_SRWI;
	} else if (insn->alias_id == PPC_INS_ALIAS_SLDI) {
		id = PPC_INS_SLDI;
	}
#endif

	switch (id) {
	default:
		NOT_IMPLEMENTED;
#if CS_NEXT_VERSION < 6
	case PPC_INS_ROTLW:
	case PPC_INS_ROTLWI:
#endif
	case PPC_INS_RLWIMI:
	case PPC_INS_RLWINM:
	case PPC_INS_RLWNM:
#if CS_NEXT_VERSION >= 6
		if (insn->alias_id == PPC_INS_ALIAS_CLRLWI ||
			insn->alias_id == PPC_INS_ALIAS_CLRLWI_) {
			break; // Handle down below
		}
		if (id == PPC_INS_RLWNM) {
#else
		if (id == PPC_INS_RLWNM || id == PPC_INS_ROTLW) {
#endif
			n = CAST(6, IL_FALSE, LOGAND(VARG(rB), UA(0x1f)));
		} else {
			n = U8(sH);
		}
		r = ROTL32(UNSIGNED(32, VARG(rS)), n);
#if CS_NEXT_VERSION >= 6
		b = mB + 32;
		e = mE + 32;
#else
		if (id == PPC_INS_ROTLW || id == PPC_INS_ROTLWI) {
			b = 32; // mb: 0 + 32
			e = 63; // me: 31 + 32
		} else {
			b = mB + 32;
			e = mE + 32;
		}
#endif
		// Mask has all bits set.
		all_bits_set = (((b - 1) & 0x3f) == e);
		set_mask = all_bits_set ? NULL : SET_MASK(U8(b), U8(e));
		into_rA = all_bits_set ? r : LOGAND(r, VARL("mask"));
		if (id == PPC_INS_RLWIMI && !all_bits_set) {
			into_rA = LOGOR(into_rA, LOGAND(VARG(rA), LOGNOT(VARL("mask"))));
		}
		break;
#if CS_NEXT_VERSION < 6
	case PPC_INS_ROTLD:
	case PPC_INS_ROTLDI:
#endif
	case PPC_INS_RLDCL:
	case PPC_INS_RLDCR:
	case PPC_INS_RLDIC:
	case PPC_INS_RLDICL:
	case PPC_INS_RLDICR:
	case PPC_INS_RLDIMI:
#if CS_NEXT_VERSION >= 6
		if (insn->alias_id == PPC_INS_ALIAS_CLRLDI ||
			insn->alias_id == PPC_INS_ALIAS_CLRLDI_) {
			break; // Handle below
		}
		if (id == PPC_INS_RLDCR || id == PPC_INS_RLDCL) {
#else
		if (id == PPC_INS_RLDCR || id == PPC_INS_RLDCL || id == PPC_INS_ROTLD) {
#endif
			// For these instruction ME is the third operand, not MB.
			mE = INSOP(3).imm;
			n = UNSIGNED(8, VARG(rB));
		} else if (id == PPC_INS_RLDICR) {
			mE = INSOP(3).imm;
			n = U8(sH);
		} else {
			n = U8(sH);
		}
		n = LOGAND(U8(0x3f), n);
		r = ROTL64(VARG(rS), n);
#if CS_NEXT_VERSION >= 6
		if (id == PPC_INS_RLDICR || id == PPC_INS_RLDCR) {
			b = 0;
			e = mE;
		} else {
			b = mB;
			if (id == PPC_INS_RLDCL || id == PPC_INS_RLDICL) {
				e = 63;
			} else if (id == PPC_INS_RLDIMI) {
				e = (63 - sH) & 0x3f;
			} else {
				e = sH;
			}
		}
#else
		if (id == PPC_INS_RLDICR || id == PPC_INS_RLDCR || id == PPC_INS_ROTLDI || id == PPC_INS_ROTLD) {
			b = 0;
			if (id == PPC_INS_ROTLDI || id == PPC_INS_ROTLD) {
				e = 63;
			} else {
				e = mE;
			}
		} else {
			b = mB;
			if (id == PPC_INS_RLDCL || id == PPC_INS_RLDICL) {
				e = 63;
			} else if (id == PPC_INS_RLDIMI) {
				e = (63 - sH) & 0x3f;
			} else {
				e = sH;
			}
		}
#endif

		all_bits_set = (((b - 1) & 0x3f) == e);
		set_mask = all_bits_set ? NULL : SET_MASK(U8(b), U8(e));
		into_rA = all_bits_set ? r : LOGAND(r, VARL("mask"));
		if (id == PPC_INS_RLDIMI && !all_bits_set) {
			into_rA = LOGOR(into_rA, LOGAND(VARG(rA), LOGNOT(VARL("mask"))));
		}
		break;
	case PPC_INS_SLDI:
#if CS_NEXT_VERSION < 6
		// Currently broken in rizins capstone version.
		// Immediate is not in instruction.
		NOT_IMPLEMENTED;
#endif
	case PPC_INS_SLD:
	case PPC_INS_SRD:
	case PPC_INS_SLWI:
	case PPC_INS_SRWI:
		if (id == PPC_INS_SLD || id == PPC_INS_SRD) {
			n = VARG(rB);
		} else {
			n = UA(sH);
		}
		n = LOGAND(UA(0x3f), n);
		if (id == PPC_INS_SRD) {
			into_rA = SHIFTR0(VARG(rS), n);
		} else if (id == PPC_INS_SRWI) {
			into_rA = SHIFTR0(LOGAND(VARG(rS), UA(0xffffffff)), n);
		} else {
			into_rA = SHIFTL0(VARG(rS), n);
		}
		if (id == PPC_INS_SLWI || id == PPC_INS_SRWI) {
			into_rA = LOGAND(into_rA, UA(0xffffffff)); // Clear high 32bits
		}
		break;
	case PPC_INS_SRAD:
	case PPC_INS_SRADI:
		if (id == PPC_INS_SRAD) {
			n = CAST(6, IL_FALSE, LOGAND(VARG(rB), UA(0x3f)));
		} else {
			n = U8(sH);
		}
		into_rA = SHIFTRA(VARG(rS), n);
		// Set ca to 1 if RS is negative and 1s were shifted out.
		ca_val = ITE(AND(MSB(VARG(rS)),
				     NON_ZERO(MOD(VARG(rS), EXTZ(SHIFTL0(UA(1), DUP(n)))))), // (RS % (1 << n)) != 0
			IL_TRUE,
			IL_FALSE);
		set_ca = SETG("ca", ca_val);
		break;
	case PPC_INS_SLW:
	case PPC_INS_SRW:
		into_rA = (id == PPC_INS_SLW) ? SHIFTL0(UNSIGNED(32, VARG(rS)), VARG(rB)) : SHIFTR0(UNSIGNED(32, VARG(rS)), VARG(rB));
		if (IN_64BIT_MODE) {
			into_rA = APPEND(U32(0), into_rA);
		}
		break;
	case PPC_INS_SRAW:
	case PPC_INS_SRAWI:
		n = (id == PPC_INS_SRAW) ? CAST(6, IL_FALSE, LOGAND(VARG(rB), UA(0x3f))) : U8(sH);
		into_rA = EXTS(SHIFTRA(UNSIGNED(32, VARG(rS)), n));

		// Set ca to 1 if RS is negative and 1s were shifted out.
		ca_val = ITE(AND(MSB(SIGNED(32, VARG(rS))), // (RS < 0) &&
				     NON_ZERO(MOD(UNSIGNED(32, VARG(rS)), UNSIGNED(32, SHIFTL0(UA(1), DUP(n)))))), // (RS % (1 << n)) != 0
			IL_TRUE,
			IL_FALSE);
		set_ca = SETG("ca", ca_val);
		break;
#if CS_NEXT_VERSION < 6
	case PPC_INS_CLRLDI:
	case PPC_INS_CLRLWI:
		r = VARG(rS);
		b = (id == PPC_INS_CLRLWI) ? INSOP(2).imm + 32 : INSOP(2).imm;
		e = 63;
		all_bits_set = (((b - 1) & 0x3f) == e);
		set_mask = all_bits_set ? NULL : SET_MASK(U8(b), U8(e));
		into_rA = all_bits_set ? r : LOGAND(r, VARL("mask"));
	}
#else
	}
	if (insn->alias_id == PPC_INS_ALIAS_CLRLDI ||
		insn->alias_id == PPC_INS_ALIAS_CLRLWI ||
		insn->alias_id == PPC_INS_ALIAS_CLRLDI_ ||
		insn->alias_id == PPC_INS_ALIAS_CLRLWI_) {
		r = VARG(rS);
		b = (insn->alias_id == PPC_INS_ALIAS_CLRLWI) ? INSOP(3).imm + 32 : INSOP(3).imm;
		e = 63;
		all_bits_set = (((b - 1) & 0x3f) == e);
		set_mask = all_bits_set ? NULL : SET_MASK(U8(b), U8(e));
		into_rA = all_bits_set ? r : LOGAND(r, VARL("mask"));
	}
#endif

	RzILOpPure *zero = UA(0);
	RzILOpPure *old_res = VARL("result");
	update_cr0 = sets_cr0 ? ppc_cmp_set_cr(old_res, zero, true, "cr0", mode) : EMPTY();
	set_mask = set_mask ? set_mask : EMPTY();
	set_ca = set_ca ? set_ca : EMPTY();
	rz_il_op_pure_free(zero);

	return SEQ5(set_mask, set_ca, SETL("result", into_rA), SETG(rA, old_res), update_cr0);
}

static RzILOpEffect *sys(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, EMPTY());
	ut32 id = insn->id;

	switch (id) {
	default:
		NOT_IMPLEMENTED;
	case PPC_INS_SC:
	case PPC_INS_TRAP:
	case PPC_INS_TW:
	case PPC_INS_TD:
	case PPC_INS_TWI:
	case PPC_INS_TDI:
		return NOP();
	}
}

static RzILOpEffect *cr_logical(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, EMPTY());
	ut32 id = insn->id;

	if (id == PPC_INS_MCRF) {
		return SETG(cs_reg_name(handle, INSOP(0).reg), VARG(cs_reg_name(handle, INSOP(1).reg)));
	}
	NOT_IMPLEMENTED;
}

/**
 * \brief Returns the RZIL implementation of a given capstone instruction.
 * Or NULL if the instruction is not yet implemented.
 *
 * \param handle The capstone handle.
 * \param insn The capstone instruction.
 * \param mode The capstone mode.
 * \return RzILOpEffect* Sequence of effects which emulate the instruction.
 */
RZ_IPI RzILOpEffect *rz_ppc_cs_get_il_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, EMPTY());
	rz_return_val_if_fail(insn->detail, EMPTY());
	RzILOpEffect *lop;
	switch (insn->id) {
	default:
		NOT_IMPLEMENTED;
	case PPC_INS_INVALID:
		// TODO Exception
		NOT_IMPLEMENTED;
	case PPC_INS_NOP:
#if CS_API_MAJOR < 5
		// bug on xori in capstone v5
	case PPC_INS_XNOP:
#endif
	case PPC_INS_DCBT:
	case PPC_INS_DCBTST:
	// Everything is executed linear => Sync instructions are NOP()s.
	case PPC_INS_ISYNC:
	case PPC_INS_SYNC:
#if CS_NEXT_VERSION < 6
	case PPC_INS_LWSYNC:
	case PPC_INS_MSYNC:
	case PPC_INS_PTESYNC:
#endif
	case PPC_INS_TLBSYNC:
		lop = NOP();
		break;
	case PPC_INS_ADD:
	case PPC_INS_ADDC:
	case PPC_INS_ADDE:
	case PPC_INS_ADDI:
	case PPC_INS_ADDIC:
	case PPC_INS_ADDIS:
	case PPC_INS_ADDME:
	case PPC_INS_ADDZE:
		lop = add_sub_op(handle, insn, true, mode);
		break;
	case PPC_INS_NEG:
	case PPC_INS_SUBF:
	case PPC_INS_SUBFC:
	case PPC_INS_SUBFE:
	case PPC_INS_SUBFIC:
	case PPC_INS_SUBFME:
	case PPC_INS_SUBFZE:
		lop = add_sub_op(handle, insn, false, mode);
		break;
	case PPC_INS_DIVD:
	case PPC_INS_DIVDU:
	case PPC_INS_DIVW:
	case PPC_INS_DIVWU:
	case PPC_INS_MULHD:
	case PPC_INS_MULHDU:
	case PPC_INS_MULHW:
	case PPC_INS_MULHWU:
	case PPC_INS_MULLD:
	case PPC_INS_MULLI:
	case PPC_INS_MULLW:
		lop = div_mul_op(handle, insn, mode);
		break;
	case PPC_INS_LI:
	case PPC_INS_LIS:
	case PPC_INS_LA:
	case PPC_INS_LBZ:
	case PPC_INS_LBZU:
	case PPC_INS_LBZUX:
	case PPC_INS_LBZX:
	case PPC_INS_LD:
	case PPC_INS_LDARX:
	case PPC_INS_LDBRX:
	case PPC_INS_LDU:
	case PPC_INS_LDUX:
	case PPC_INS_LDX:
	case PPC_INS_LHA:
	case PPC_INS_LHAU:
	case PPC_INS_LHAUX:
	case PPC_INS_LHAX:
	case PPC_INS_LHBRX:
	case PPC_INS_LHZ:
	case PPC_INS_LHZU:
	case PPC_INS_LHZUX:
	case PPC_INS_LHZX:
	case PPC_INS_LWA:
	case PPC_INS_LWARX:
	case PPC_INS_LWAUX:
	case PPC_INS_LWAX:
	case PPC_INS_LWBRX:
	case PPC_INS_LWZ:
	case PPC_INS_LWZU:
	case PPC_INS_LWZUX:
	case PPC_INS_LWZX:
	case PPC_INS_LBZCIX:
	case PPC_INS_LHZCIX:
	case PPC_INS_LWZCIX:
	case PPC_INS_LDCIX:
		lop = load_op(handle, insn, mode);
		break;
	case PPC_INS_STB:
	case PPC_INS_STBU:
	case PPC_INS_STBUX:
	case PPC_INS_STBX:
	case PPC_INS_STD:
	case PPC_INS_STDBRX:
	case PPC_INS_STDCX:
	case PPC_INS_STDU:
	case PPC_INS_STDUX:
	case PPC_INS_STDX:
	case PPC_INS_STFD:
	case PPC_INS_STFDU:
	case PPC_INS_STFDUX:
	case PPC_INS_STFDX:
	case PPC_INS_STFIWX:
	case PPC_INS_STFS:
	case PPC_INS_STFSU:
	case PPC_INS_STFSUX:
	case PPC_INS_STFSX:
	case PPC_INS_STH:
	case PPC_INS_STHBRX:
	case PPC_INS_STHU:
	case PPC_INS_STHUX:
	case PPC_INS_STHX:
	case PPC_INS_STMW:
	case PPC_INS_STSWI:
	case PPC_INS_STVEBX:
	case PPC_INS_STVEHX:
	case PPC_INS_STVEWX:
	case PPC_INS_STVX:
	case PPC_INS_STVXL:
	case PPC_INS_STW:
	case PPC_INS_STWBRX:
	case PPC_INS_STWCX:
	case PPC_INS_STWU:
	case PPC_INS_STWUX:
	case PPC_INS_STWX:
	case PPC_INS_STXSDX:
	case PPC_INS_STXVD2X:
	case PPC_INS_STXVW4X:
	case PPC_INS_DCBZ:
	case PPC_INS_STHCIX:
	case PPC_INS_STWCIX:
	case PPC_INS_STBCIX:
	case PPC_INS_STDCIX:
		lop = store_op(handle, insn, mode);
		break;
#if CS_NEXT_VERSION < 6
	case PPC_INS_MR:
#endif
	case PPC_INS_AND:
	case PPC_INS_ANDC:
	case PPC_INS_ANDIS:
	case PPC_INS_ANDI:
	case PPC_INS_OR:
	case PPC_INS_ORC:
	case PPC_INS_ORI:
	case PPC_INS_ORIS:
	case PPC_INS_NAND:
	case PPC_INS_NOR:
#if CS_API_MAJOR == 5 && CS_NEXT_VERSION < 6
		// bug on xori in capstone v5
	case PPC_INS_XNOP:
#endif
	case PPC_INS_XOR:
	case PPC_INS_XORI:
#if CS_NEXT_VERSION >= 6
		if (insn->is_alias && insn->alias_id == PPC_INS_ALIAS_XNOP) {
			return NOP();
		}
#endif
		// fallthrough
	case PPC_INS_XORIS:
	case PPC_INS_EQV:
	case PPC_INS_EXTSB:
	case PPC_INS_EXTSH:
	case PPC_INS_EXTSW:
	case PPC_INS_CNTLZD:
	case PPC_INS_CNTLZW:
	case PPC_INS_POPCNTD:
	case PPC_INS_POPCNTW:
	case PPC_INS_CMPB:
#if CS_API_MAJOR == 5
	case PPC_INS_CMPRB:
	case PPC_INS_CMPEQB:
#endif
		lop = bitwise_op(handle, insn, mode);
		break;
#if CS_API_MAJOR == 5 && CS_NEXT_VERSION < 6
	case PPC_INS_CMP:
	case PPC_INS_CMPI:
	case PPC_INS_CMPL:
	case PPC_INS_CMPLI:
#endif
	case PPC_INS_CMPD:
	case PPC_INS_CMPDI:
	case PPC_INS_CMPLD:
	case PPC_INS_CMPLDI:
	case PPC_INS_CMPLW:
	case PPC_INS_CMPLWI:
	case PPC_INS_CMPW:
	case PPC_INS_CMPWI:
		lop = compare_op(handle, insn, mode);
		break;
	case PPC_INS_B:
	case PPC_INS_BA:
	case PPC_INS_BC:
	case PPC_INS_BCCTR:
	case PPC_INS_BCCTRL:
	case PPC_INS_BCL:
	case PPC_INS_BCLR:
	case PPC_INS_BCLRL:
	case PPC_INS_BCTR:
	case PPC_INS_BCTRL:
	case PPC_INS_BL:
	case PPC_INS_BLA:
	case PPC_INS_BLR:
	case PPC_INS_BLRL:
	case PPC_INS_BCA:
	case PPC_INS_BCLA:
#if CS_NEXT_VERSION < 6
	case PPC_INS_BDNZ:
	case PPC_INS_BDNZA:
	case PPC_INS_BDNZL:
	case PPC_INS_BDNZLA:
	case PPC_INS_BDNZLR:
	case PPC_INS_BDNZLRL:
	case PPC_INS_BDZ:
	case PPC_INS_BDZA:
	case PPC_INS_BDZL:
	case PPC_INS_BDZLA:
	case PPC_INS_BDZLR:
	case PPC_INS_BDZLRL:
	case PPC_INS_BDNZT:
	case PPC_INS_BDNZTL:
	case PPC_INS_BDNZTA:
	case PPC_INS_BDNZTLA:
	case PPC_INS_BDNZF:
	case PPC_INS_BDNZFL:
	case PPC_INS_BDNZFA:
	case PPC_INS_BDNZFLA:
	case PPC_INS_BDZT:
	case PPC_INS_BDZTA:
	case PPC_INS_BDZTL:
	case PPC_INS_BDZTLA:
	case PPC_INS_BDZF:
	case PPC_INS_BDZFA:
	case PPC_INS_BDZFL:
	case PPC_INS_BDZFLA:
#endif
#if CS_API_MAJOR == 5 && CS_NEXT_VERSION < 6
	case PPC_INS_BCDCFN:
	case PPC_INS_BCDCFSQ:
	case PPC_INS_BCDCFZ:
	case PPC_INS_BCDCPSGN:
	case PPC_INS_BCDCTN:
	case PPC_INS_BCDCTSQ:
	case PPC_INS_BCDCTZ:
	case PPC_INS_BCDS:
	case PPC_INS_BCDSETSGN:
	case PPC_INS_BCDSR:
	case PPC_INS_BCDTRUNC:
	case PPC_INS_BCDUS:
	case PPC_INS_BCDUTRUNC:
	case PPC_INS_BDNZFLR:
	case PPC_INS_BDNZFLRL:
	case PPC_INS_BDNZTLR:
	case PPC_INS_BDNZTLRL:
	case PPC_INS_BDZFLR:
	case PPC_INS_BDZFLRL:
	case PPC_INS_BDZTLR:
	case PPC_INS_BDZTLRL:
	case PPC_INS_BEQ:
	case PPC_INS_BEQA:
	case PPC_INS_BEQCTR:
	case PPC_INS_BEQCTRL:
	case PPC_INS_BEQL:
	case PPC_INS_BEQLA:
	case PPC_INS_BEQLR:
	case PPC_INS_BEQLRL:
	case PPC_INS_BF:
	case PPC_INS_BFA:
	case PPC_INS_BFCTR:
	case PPC_INS_BFCTRL:
	case PPC_INS_BFL:
	case PPC_INS_BFLA:
	case PPC_INS_BFLR:
	case PPC_INS_BFLRL:
	case PPC_INS_BGE:
	case PPC_INS_BGEA:
	case PPC_INS_BGECTR:
	case PPC_INS_BGECTRL:
	case PPC_INS_BGEL:
	case PPC_INS_BGELA:
	case PPC_INS_BGELR:
	case PPC_INS_BGELRL:
	case PPC_INS_BGT:
	case PPC_INS_BGTA:
	case PPC_INS_BGTCTR:
	case PPC_INS_BGTCTRL:
	case PPC_INS_BGTL:
	case PPC_INS_BGTLA:
	case PPC_INS_BGTLR:
	case PPC_INS_BGTLRL:
	case PPC_INS_BLE:
	case PPC_INS_BLEA:
	case PPC_INS_BLECTR:
	case PPC_INS_BLECTRL:
	case PPC_INS_BLEL:
	case PPC_INS_BLELA:
	case PPC_INS_BLELR:
	case PPC_INS_BLELRL:
	case PPC_INS_BLT:
	case PPC_INS_BLTA:
	case PPC_INS_BLTCTR:
	case PPC_INS_BLTCTRL:
	case PPC_INS_BLTL:
	case PPC_INS_BLTLA:
	case PPC_INS_BLTLR:
	case PPC_INS_BLTLRL:
	case PPC_INS_BNE:
	case PPC_INS_BNEA:
	case PPC_INS_BNECTR:
	case PPC_INS_BNECTRL:
	case PPC_INS_BNEL:
	case PPC_INS_BNELA:
	case PPC_INS_BNELR:
	case PPC_INS_BNELRL:
	case PPC_INS_BNG:
	case PPC_INS_BNGA:
	case PPC_INS_BNGCTR:
	case PPC_INS_BNGCTRL:
	case PPC_INS_BNGL:
	case PPC_INS_BNGLA:
	case PPC_INS_BNGLR:
	case PPC_INS_BNGLRL:
	case PPC_INS_BNL:
	case PPC_INS_BNLA:
	case PPC_INS_BNLCTR:
	case PPC_INS_BNLCTRL:
	case PPC_INS_BNLL:
	case PPC_INS_BNLLA:
	case PPC_INS_BNLLR:
	case PPC_INS_BNLLRL:
	case PPC_INS_BNS:
	case PPC_INS_BNSA:
	case PPC_INS_BNSCTR:
	case PPC_INS_BNSCTRL:
	case PPC_INS_BNSL:
	case PPC_INS_BNSLA:
	case PPC_INS_BNSLR:
	case PPC_INS_BNSLRL:
	case PPC_INS_BNU:
	case PPC_INS_BNUA:
	case PPC_INS_BNUCTR:
	case PPC_INS_BNUCTRL:
	case PPC_INS_BNUL:
	case PPC_INS_BNULA:
	case PPC_INS_BNULR:
	case PPC_INS_BNULRL:
	case PPC_INS_BPERMD:
	case PPC_INS_BSO:
	case PPC_INS_BSOA:
	case PPC_INS_BSOCTR:
	case PPC_INS_BSOCTRL:
	case PPC_INS_BSOL:
	case PPC_INS_BSOLA:
	case PPC_INS_BSOLR:
	case PPC_INS_BSOLRL:
	case PPC_INS_BT:
	case PPC_INS_BTA:
	case PPC_INS_BTCTR:
	case PPC_INS_BTCTRL:
	case PPC_INS_BTL:
	case PPC_INS_BTLA:
	case PPC_INS_BTLR:
	case PPC_INS_BTLRL:
	case PPC_INS_BUN:
	case PPC_INS_BUNA:
	case PPC_INS_BUNCTR:
	case PPC_INS_BUNCTRL:
	case PPC_INS_BUNL:
	case PPC_INS_BUNLA:
	case PPC_INS_BUNLR:
	case PPC_INS_BUNLRL:
#endif
		lop = branch_op(handle, insn, mode);
		break;
	// These instruction are not in the ISA manual v3.1B.
	case PPC_INS_BRINC:
		NOT_IMPLEMENTED;
	case PPC_INS_MFCR:
	case PPC_INS_MFCTR:
	case PPC_INS_MFDCR:
	case PPC_INS_MFFS:
	case PPC_INS_MFLR:
	case PPC_INS_MFMSR:
	case PPC_INS_MFOCRF:
	case PPC_INS_MFSPR:
	case PPC_INS_MFSR:
	case PPC_INS_MFSRIN:
	case PPC_INS_MFTB:
	case PPC_INS_MFVSCR:
	case PPC_INS_MTCRF:
	case PPC_INS_MTCTR:
	case PPC_INS_MTDCR:
	case PPC_INS_MTFSB0:
	case PPC_INS_MTFSB1:
	case PPC_INS_MTFSF:
	case PPC_INS_MTLR:
	case PPC_INS_MTMSR:
	case PPC_INS_MTMSRD:
	case PPC_INS_MTOCRF:
	case PPC_INS_MTSPR:
	case PPC_INS_MTSR:
	case PPC_INS_MTSRIN:
	case PPC_INS_MTVSCR:
#if CS_NEXT_VERSION < 6
	case PPC_INS_MFBR0:
	case PPC_INS_MFBR1:
	case PPC_INS_MFBR2:
	case PPC_INS_MFBR3:
	case PPC_INS_MFBR4:
	case PPC_INS_MFBR5:
	case PPC_INS_MFBR6:
	case PPC_INS_MFBR7:
	case PPC_INS_MFXER:
	case PPC_INS_MFRTCU:
	case PPC_INS_MFRTCL:
	case PPC_INS_MFDSCR:
	case PPC_INS_MFDSISR:
	case PPC_INS_MFDAR:
	case PPC_INS_MFSRR2:
	case PPC_INS_MFSRR3:
	case PPC_INS_MFCFAR:
	case PPC_INS_MFAMR:
	case PPC_INS_MFPID:
	case PPC_INS_MFTBLO:
	case PPC_INS_MFTBHI:
	case PPC_INS_MFDBATU:
	case PPC_INS_MFDBATL:
	case PPC_INS_MFIBATU:
	case PPC_INS_MFIBATL:
	case PPC_INS_MFTBU:
	case PPC_INS_MTCR:
	case PPC_INS_MTDBATU:
	case PPC_INS_MTDBATL:
	case PPC_INS_MTIBATU:
	case PPC_INS_MTIBATL:
	case PPC_INS_MFDCCR:
	case PPC_INS_MFICCR:
	case PPC_INS_MFDEAR:
	case PPC_INS_MFESR:
	case PPC_INS_MFSPEFSCR:
	case PPC_INS_MFTCR:
	case PPC_INS_MFASR:
	case PPC_INS_MFPVR:
	case PPC_INS_MTBR0:
	case PPC_INS_MTBR1:
	case PPC_INS_MTBR2:
	case PPC_INS_MTBR3:
	case PPC_INS_MTBR4:
	case PPC_INS_MTBR5:
	case PPC_INS_MTBR6:
	case PPC_INS_MTBR7:
	case PPC_INS_MTXER:
	case PPC_INS_MTDSCR:
	case PPC_INS_MTDSISR:
	case PPC_INS_MTDAR:
	case PPC_INS_MTSRR2:
	case PPC_INS_MTSRR3:
	case PPC_INS_MTCFAR:
	case PPC_INS_MTAMR:
	case PPC_INS_MTPID:
	case PPC_INS_MTTBL:
	case PPC_INS_MTTBU:
	case PPC_INS_MTTBLO:
	case PPC_INS_MTTBHI:
	case PPC_INS_MTDCCR:
	case PPC_INS_MTICCR:
	case PPC_INS_MTDEAR:
	case PPC_INS_MTESR:
	case PPC_INS_MTSPEFSCR:
	case PPC_INS_MTTCR:
#endif
		lop = move_from_to_spr_op(handle, insn, mode);
		break;
	case PPC_INS_ISEL:
		NOT_IMPLEMENTED;
		break;
	case PPC_INS_CREQV:
	case PPC_INS_CRXOR:
	case PPC_INS_CRAND:
	case PPC_INS_CRANDC:
	case PPC_INS_CRNAND:
	case PPC_INS_CRNOR:
	case PPC_INS_CROR:
	case PPC_INS_CRORC:
#if CS_NEXT_VERSION < 6
	case PPC_INS_CRSET:
	case PPC_INS_CRNOT:
	case PPC_INS_CRMOVE:
	case PPC_INS_CRCLR:
#endif
		NOT_IMPLEMENTED;
	case PPC_INS_MCRF:
		lop = cr_logical(handle, insn, mode);
		break;
	// Rotate and rotate
	case PPC_INS_RLDCL:
	case PPC_INS_RLDCR:
	case PPC_INS_RLDIC:
	case PPC_INS_RLDICL:
	case PPC_INS_RLDICR:
	case PPC_INS_RLDIMI:
	case PPC_INS_RLWIMI:
	case PPC_INS_RLWINM:
	case PPC_INS_RLWNM:
#if CS_NEXT_VERSION < 6
	case PPC_INS_ROTLD:
	case PPC_INS_ROTLDI:
	case PPC_INS_CLRLDI:
	case PPC_INS_ROTLWI:
	case PPC_INS_CLRLWI:
	case PPC_INS_ROTLW:
#endif
	case PPC_INS_SLD:
	case PPC_INS_SLW:
	case PPC_INS_SRAD:
	case PPC_INS_SRADI:
	case PPC_INS_SRAW:
	case PPC_INS_SRAWI:
	case PPC_INS_SRD:
	case PPC_INS_SRW:
	case PPC_INS_SLWI:
	case PPC_INS_SLDI:
	case PPC_INS_SRWI:
		lop = shift_and_rotate(handle, insn, mode);
		break;
	case PPC_INS_SC:
	case PPC_INS_TRAP:
	case PPC_INS_TW:
	case PPC_INS_TD:
	case PPC_INS_TWI:
	case PPC_INS_TDI:
		lop = sys(handle, insn, mode);
		break;
	}

	return lop;
}

#include <rz_il/rz_il_opbuilder_end.h>
