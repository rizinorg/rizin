// SPDX-FileCopyrightText: 2022 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "ppc.h"
#include "ppc_il.h"
#include "ppc_analysis.h"
#include "rz_types_base.h"
#include <rz_il/rz_il_opcodes.h>
#include <rz_util/rz_assert.h>
#include <capstone.h>
#include <rz_il/rz_il_opbuilder_begin.h>

static RzILOpEffect *load_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, EMPTY());
	ut32 id = insn->id;
	// READ
	const char *rT = cs_reg_name(handle, INSOP(0).reg);
	const char *rA = cs_reg_name(handle, INSOP(1).mem.base);
	const char *rB = cs_reg_name(handle, INSOP(2).reg);
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
		base = IFREG0(rA);
		disp = EXTEND(PPC_ARCH_BITS, SN(16, d));
		ea = ADD(base, disp);
		into_rt = ea;
		update_ra = false;
		break;
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
	case PPC_INS_LWARX:
	case PPC_INS_LDARX:
		base = IFREG0(rA); // Not all instructions use the plain value 0 if rA = 0. But we ignore this here.
		if (ppc_is_x_form(id)) {
			disp = VARG(rB);
		} else {
			// "disp << 2" done by capstone.
			RzILOpPure *imm = SN(16, d);
			disp = EXTEND(PPC_ARCH_BITS, imm);
		}
		ea = ADD(base, disp);
		RzILOpPure *loadw = LOADW(mem_acc_size, VARLP("ea"));
		if (ppc_is_algebraic(id)) {
			into_rt = EXTEND(PPC_ARCH_BITS, VARLP("loadw"));
		} else {
			into_rt = EXTZ(VARLP("loadw"));
		}
		into_rt = LET("ea", ea, LET("loadw", loadw, into_rt));
		break;
	// Byte reverse and reserved indexed
	case PPC_INS_LHBRX:
	case PPC_INS_LDBRX:
		NOT_IMPLEMENTED;
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
	RzILOpEffect *update = update_ra ? SETG(rA, DUP(ea)) : NOP();
	return SEQ2(res, update);
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
	const char *rB = cs_reg_name(handle, INSOP(2).reg);
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
	case PPC_INS_DCBZ:
		ea = ADD(IFREG0(rA), VARG(rB));
		//! DCACHE_LINE_SIZE is currently hardcoded. Should be replaced by config option.
		store = STOREW(ea, UN(DCACHE_LINE_SIZE, 0));
		break;
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
	case PPC_INS_STDCX:
	case PPC_INS_STWCX:
		base = IFREG0(rA); // Not all instructions use the plain value 0 if (rA) == 0. But we ignore this here.
		if (ppc_is_x_form(id)) {
			disp = VARG(rB);
		} else {
			disp = EXTEND(PPC_ARCH_BITS, S16(d));
		}
		ea = ADD(base, disp);
		store = STOREW(ea, CAST(mem_acc_size, IL_FALSE, VARG(rS)));
		break;
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

	RzILOpPure *op0;
	RzILOpPure *op1;
	RzILOpPure *op2;
	RzILOpPure *res;

	// How to read instruction ids:
	// Letter		Meaning
	// ADD/SUBF		Add, Subtract from
	// I/M/Z 		Immediate, Minus one, Zero extend,
	// C/E/S		Carry (sets it), Extends (adds carry it), Shift immediate

	// EXEC
	switch (id) {
	default:
		NOT_IMPLEMENTED;
	case PPC_INS_ADD:
	case PPC_INS_ADDC:
	case PPC_INS_SUBF:
	case PPC_INS_SUBFC:
		op0 = add ? VARG(rA) : ADD(LOGNOT(VARG(rA)), UA(1));
		op1 = VARG(rB);
		res = ADD(op0, op1);
		break;
	case PPC_INS_ADDE:
	case PPC_INS_SUBFE:
		op0 = add ? VARG(rA) : LOGNOT(VARG(rA));
		op2 = VARG(rB);
		op1 = ADD(op2, BOOL_TO_BV(VARG("ca"), PPC_ARCH_BITS));
		res = ADD(op0, op1);
		break;
	case PPC_INS_ADDI:
	case PPC_INS_ADDIC:
	case PPC_INS_ADDIS:
	case PPC_INS_SUBFIC:
		op0 = add ? ((id == PPC_INS_ADDIS) ? IFREG0(rA) : VARG(rA)) : ADD(LOGNOT(VARG(rA)), UA(1));
		if (id == PPC_INS_ADDIS) {
			op1 = EXTEND(PPC_ARCH_BITS, APPEND(SN(16, sI), U16(0))); // Shift immediate << 16
		} else {
			op1 = EXTEND(PPC_ARCH_BITS, SN(16, sI));
		}
		res = ADD(op0, op1);
		break;
	case PPC_INS_ADDME:
	case PPC_INS_ADDZE:
	case PPC_INS_SUBFME:
	case PPC_INS_SUBFZE:
		op0 = add ? VARG(rA) : LOGNOT(VARG(rA));
		if (id == PPC_INS_ADDME || id == PPC_INS_SUBFME) {
			op1 = ADD(BOOL_TO_BV(VARG("ca"), PPC_ARCH_BITS), SA(-1)); // Minus 1
		} else {
			op1 = BOOL_TO_BV(VARG("ca"), PPC_ARCH_BITS);
		}
		res = ADD(op0, op1);
		break;
	case PPC_INS_NEG:
		op0 = LOGNOT(VARG(rA));
		op1 = UA(1);
		res = ADD(op0, op1);
	}
	rz_return_val_if_fail(op0 && op1, NULL);

	// WRITE
	RzILOpEffect *set;
	RzILOpEffect *set_carry = set_ca ? set_carry_add_sub(DUP(op0), DUP(op1), mode, true) : NOP();

	// Instructions which set the OV bit are not supported in capstone.
	// See: https://github.com/capstone-engine/capstone/issues/944
	RzILOpEffect *overflow = NOP();
	RzILOpEffect *update_cr0 = cr0 ? cmp_set_cr(res, UA(0), true, "cr0", mode) : NOP();
	set = SETG(rT, res);
	return SEQ4(set, set_carry, overflow, update_cr0);
}

static RzILOpEffect *compare_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, EMPTY());
	ut32 id = insn->id;
	const char *crX;
	const char *rA;
	const char *rB;
	st64 imm;

	RzILOpPure *left;
	RzILOpPure *right;

	bool signed_cmp = false;

	// READ
	// cr0 reg is not explicitly stored in the operands list.
	if (OP_CNT == 2) {
		crX = "cr0";
		rA = cs_reg_name(handle, INSOP(0).reg);
		rB = cs_reg_name(handle, INSOP(1).reg);
		imm = INSOP(1).imm;
	} else {
		crX = cs_reg_name(handle, INSOP(0).imm);
		rA = cs_reg_name(handle, INSOP(1).reg);
		rB = cs_reg_name(handle, INSOP(2).reg);
		imm = INSOP(2).imm;
	}

	// How to read instruction ids:
	// Letter			Meaning
	// CMP				Compare
	// B/H/W/D	 		Byte, Half Word, Word, Double Word
	// I/L				Immediate, Logical (unsigned compare)

	// EXEC
	// Logical <=> unsigned comparisons ; Not logical <=> signed comparison.
	signed_cmp = (id == PPC_INS_CMPW || id == PPC_INS_CMPD || id == PPC_INS_CMPWI || id == PPC_INS_CMPDI);

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
	return cmp_set_cr(left, right, signed_cmp, crX, mode);
}

static RzILOpEffect *bitwise_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, EMPTY());
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
	case PPC_INS_MR:
	case PPC_INS_OR:
	case PPC_INS_ORC:
	case PPC_INS_ORI:
	case PPC_INS_ORIS:
		op0 = VARG(rS);
		if (id == PPC_INS_OR || id == PPC_INS_ORC) {
			op1 = (id == PPC_INS_OR) ? VARG(rB) : LOGNOT(VARG(rB));
		} else if (id == PPC_INS_MR) {
			op1 = DUP(op0); // Extended Mnemonic for `or   RA, RS, RS`
		} else {
			op1 = (id == PPC_INS_ORI) ? EXTZ(U16(uI)) : EXTZ(APPEND(U16(uI), U16(0)));
		}
		res = LOGOR(op0, op1);
		break;
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
	// Compare bytes & Equivalent
	case PPC_INS_CMPB:;
		ut8 bits = PPC_ARCH_BITS;
		RzILOpEffect *loop, *init_n, *ones_rA, *zeros_rA;
		// RA[8×n:8×n+7] ← 0b1111_1111
		ones_rA = SETG(rA, SET_RANGE(VARG(rA), VARL("n"), ADD(VARL("n"), U8(7)), BIT_MASK(bits, VARL("n"), ADD(VARL("n"), U8(7))), bits));
		// RA[8×n:8×n+7] ← 0b0000_0000
		zeros_rA = SETG(rA, SET_RANGE(VARG(rA), VARL("n"), ADD(VARL("n"), U8(7)), UA(0), bits));
		RzILOpPure *bitmask_n_n7 = BIT_MASK(bits, MUL(U8(8), VARL("n")), ADD(MUL(U8(8), VARL("n")), U8(7)));
		//  RS[8×n:8×n+7]
		RzILOpPure *rS_8n_8n7 = LOGAND(bitmask_n_n7, VARG(rS));
		//  RB[8×n:8×n+7]
		RzILOpPure *rB_8n_8n7 = LOGAND(DUP(bitmask_n_n7), VARG(rB));
		RzILOpPure *b_cond = EQ(rS_8n_8n7, rB_8n_8n7);

		//	do n = 0 to (64BIT_CPU ? 7 : 3)
		//		if RS[8×n:8×n+7] = RB[8×n:8×n+7] then
		// 			RA[8×n:8×n+7] ← 0b1111_1111
		//		else
		//			RA[8×n:8×n+7] ← 0b0000_0000

		init_n = SETL("n", U8(0));
		ut8 m = IN_64BIT_MODE ? 8 : 4;
		loop = REPEAT(ULT(VARL("n"), U8(m)),
			SEQ2(BRANCH(b_cond,
				     ones_rA, zeros_rA),
				SETL("n", ADD(VARL("n"), U8(1)))));
		return SEQ2(init_n, loop);
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
	case PPC_INS_CNTLZW:
		NOT_IMPLEMENTED;
	// Population count
	case PPC_INS_POPCNTD:
	case PPC_INS_POPCNTW:
		NOT_IMPLEMENTED;
	}

	// WRITE
	RzILOpEffect *update_cr0 = cr0 ? cmp_set_cr(res, UA(0), true, "cr0", mode) : NOP();
	RzILOpEffect *set = SETG(rA, res);
	return SEQ2(set, update_cr0);
}

static RzILOpEffect *branch_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, EMPTY());
	ut32 id = insn->id;
	bool is_conditional = ppc_is_conditional(id);
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
		set_nia = SETL("NIA", ITE(ppc_get_branch_cond(insn, mode), ppc_get_branch_ta(insn, mode), ADD(VARL("CIA"), UA(4))));
	}

	set_cia = SETL("CIA", UA(insn->address));
	set_lr = ppc_sets_lr(id) ? SETG("lr", ADD(VARL("CIA"), UA(4))) : NOP();
	decr_ctr = ppc_decrements_ctr(insn, mode) ? SETG("ctr", SUB(VARG("ctr"), UA(1))) : NOP();

	return SEQ5(set_cia, decr_ctr, set_lr, set_nia, JMP(VARL("NIA")));
}

/**
 * NOTE: Instructions which set the 'OV' bit are not yet supported by capstone.
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

	// How to read instruction ids:
	// Letter			Meaning
	// MUL/DIV 			Multiply/Divide
	// W/D/LW/HW/LI		Word, Double WOrd, Low word, high word, low immediate
	// O/U/E			Overflow (not supported), Unsigned, Extended

	if (id == PPC_INS_MULLI) {
		op0 = VARG(rA);
		op1 = S16(sI);
	} else {
		op0 = VARG(rA);
		op1 = VARG(rB);
	}
	if (id == PPC_INS_MULHWU || id == PPC_INS_DIVWU || id == PPC_INS_MULHDU || id == PPC_INS_DIVDU) {
		op0 = UNSIGNED(128, op0);
		op1 = UNSIGNED(128, op1);
	} else {
		op0 = SIGNED(128, op0);
		op1 = SIGNED(128, op1);
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
	case PPC_INS_DIVW:
	case PPC_INS_DIVD:
	case PPC_INS_DIVDU:
		prod = DIV(op0, op1);
		break;
	}

	RzILOpEffect *cr0 = set_cr0 ? cmp_set_cr(VARG(rT), UA(0), true, "cr0", mode) : EMPTY();
	return SEQ2(SETG(rT, CAST(PPC_ARCH_BITS, IL_FALSE, prod)), cr0);
}

static RzILOpEffect *move_from_to_spr_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, EMPTY());
	ut32 id = insn->id;

	const char *rS = cs_reg_name(handle, INSOP(0).reg);
	const char *rT = cs_reg_name(handle, INSOP(0).reg);
	const char *spr_name;
	// Some registers need to assemble the value before it is read or written (e.g. XER with all its bits).
	// Leave it NULL if the value of the SPR or RS should be used.
	RzILOpEffect *set_val = NULL;
	// Size of the value written to the target register (SPR or RT)
	ut32 size = PPC_ARCH_BITS;

	switch (id) {
	default:
		NOT_IMPLEMENTED;
	// ???
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
	case PPC_INS_MTMSRD:;
		ut8 l = INSOP(1).imm;
		if (l == 1) {
			RzILOpPure *rs_48 = BIT_IS_SET(VARG(rS), PPC_ARCH_BITS, U8(48));
			RzILOpPure *rs_49 = BIT_IS_SET(VARG(rS), PPC_ARCH_BITS, U8(49));
			RzILOpPure *rs_58 = BIT_IS_SET(VARG(rS), PPC_ARCH_BITS, U8(58));
			RzILOpPure *rs_59 = BIT_IS_SET(VARG(rS), PPC_ARCH_BITS, U8(59));
			RzILOpPure *msr_3 = BIT_IS_SET(VARG("msr"), PPC_ARCH_BITS, U8(3));
			RzILOpPure *msr_41 = BIT_IS_SET(VARG("msr"), PPC_ARCH_BITS, U8(41));
			RzILOpEffect *set_msr_48 = BRANCH(OR(rs_48, rs_49), SET_BIT("msr", 64, U8(48)), UNSET_BIT("msr", 64, U8(48)));
			RzILOpEffect *set_msr_58 = BRANCH(AND(OR(rs_58, DUP(rs_49)), INV(AND(msr_41, AND(msr_3, INV(DUP(rs_49)))))),
				SET_BIT("msr", 64, U8(48)), UNSET_BIT("msr", 64, U8(48)));
			RzILOpEffect *set_msr_59 = BRANCH(AND(OR(rs_59, DUP(rs_49)), INV(AND(DUP(msr_41), AND(DUP(msr_3), INV(DUP(rs_49)))))),
				SET_BIT("msr", 64, U8(48)), UNSET_BIT("msr", 64, U8(48)));
			RzILOpPure *rs_0_2 = SHIFTR0(LOGAND(EXTZ(VARG(rS)), BIT_MASK(64, U8(0), U8(2))), U8(61));
			RzILOpPure *rs_4_40 = SHIFTR0(LOGAND(EXTZ(VARG(rS)), BIT_MASK(64, U8(4), U8(40))), U8(23));
			RzILOpPure *rs_32_40 = SHIFTR0(LOGAND(EXTZ(VARG(rS)), BIT_MASK(64, U8(32), U8(40))), U8(23));
			RzILOpPure *rs_42_47 = SHIFTR0(LOGAND(EXTZ(VARG(rS)), BIT_MASK(64, U8(42), U8(47))), U8(16));
			RzILOpPure *rs_49_50 = SHIFTR0(LOGAND(EXTZ(VARG(rS)), BIT_MASK(64, U8(49), U8(50))), U8(13));
			RzILOpPure *rs_52_57 = SHIFTR0(LOGAND(EXTZ(VARG(rS)), BIT_MASK(64, U8(52), U8(57))), U8(6));
			RzILOpPure *rs_60_62 = SHIFTR0(LOGAND(EXTZ(VARG(rS)), BIT_MASK(64, U8(60), U8(62))), U8(1));
			RzILOpPure *res;
			if (IN_64BIT_MODE) {
				res = LOGOR(rs_0_2, LOGOR(rs_4_40, LOGOR(rs_42_47, LOGOR(rs_49_50, LOGOR(rs_52_57, rs_60_62)))));
			} else {
				res = LOGOR(rs_32_40, LOGOR(rs_42_47, LOGOR(rs_49_50, LOGOR(rs_52_57, rs_60_62))));
			}
			return SEQ4(set_msr_48, set_msr_58, set_msr_59, SETG("msr", res));
		} else {
			RzILOpPure *rs_48_62 = SHIFTR0(LOGAND(EXTZ(VARG(rS)), BIT_MASK(64, U8(48), U8(62))), U8(1));
			return SETG("msr", SET_RANGE(VARG("msr"), U8(48), U8(62), rs_48_62, 64));
		}
		break;
	case PPC_INS_MTCR:
	case PPC_INS_MTCRF:;
		ut32 mask = 0xffffffff;
		if (id == PPC_INS_MTCRF) {
			ut8 fxm = INSOP(0).imm;
			rS = cs_reg_name(handle, INSOP(1).reg);
			mask = ppc_fmx_to_mask(fxm);
		}
		RzILOpEffect *set_cr = SETG("cr", LOGOR(LOGAND(UNSIGNED(32, VARG(rS)), U32(mask)), LOGAND(VARG("cr"), LOGNOT(U32(mask)))));
		return SEQ2(set_cr, sync_crx_cr(false, mask));

	case PPC_INS_MFCR:
		return SEQ2(sync_crx_cr(true, 0x0), SETG(rT, EXTZ(VARG(rT))));

	// Note: We do not update CR after the OCRF operations.
	case PPC_INS_MTOCRF:
	case PPC_INS_MFOCRF:;
		//! Untested code. Capstone < v5 does not store the fxm value in the operands.
		// See: https://github.com/capstone-engine/capstone/issues/1903
		rS = cs_reg_name(handle, INSOP(1).reg);
		ut8 fxm = INSOP(0).imm;
		ut8 tmp = fxm;
		ut8 x = 0;
		// Convert fxm to CRx number. fxm bit 7 set, means cr7
		while (tmp & UT8_MAX) {
			tmp >>= 1;
			++x;
		}
		spr_name = (id == PPC_INS_MFOCRF) ? rT : ppc_get_cr_name(x);
		RzILOpPure *crx = ppc_get_cr(x);
		if (!crx) {
			RZ_LOG_WARN("Invalid instruction encountered. fxm = %" PFMT32d " has more than one bit set.\n", fxm);
			set_val = SETL("val", UA(0));
			break;
		}
		set_val = (id == PPC_INS_MFOCRF) ? SETL("val", SHIFTL0(EXTZ(crx), U8(x * 4))) : SETL("val", UNSIGNED(4, SHIFTR0(VARG(rT), U8(x * 4))));
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
	case PPC_INS_MFSPR:
	case PPC_INS_MTSPR:;
		ut32 spr = INSOP(1).imm;
		switch (spr) {
		default:
			if (spr & 1) {
				// Invoke system privileged instruction error handler
			} else {
				// Invoke illegal instruction handler
			}
			NOT_IMPLEMENTED;
		case 808:
		case 809:
		case 810:
		case 811:
			// Reserved. Treated as No-ops
			RZ_LOG_WARN("Reserved SPR instruction encountered at 0x%" PFMTSZx "\n", insn->address);
			return NOP();
		case 1:
			if (id == PPC_INS_MTSPR) {
				return ppc_set_xer(VARG(rS), mode);
			}
			spr_name = "xer";
			set_val = SETL("val", ppc_get_xer(mode));
			break;
		case 3:
			spr_name = "dscr";
			break;
		case 8:
			spr_name = "lr";
			break;
		case 9:
			spr_name = "ctr";
			break;
		case 13:
			spr_name = "amr";
			break;
		case 256:
			spr_name = "vrsave";
			break;
		case 769:
			spr_name = "mmcr2";
			break;
		case 770:
			spr_name = "mmcra";
			break;
		case 771:
			spr_name = "pmc1";
			break;
		case 772:
			spr_name = "pmc2";
			break;
		case 773:
			spr_name = "pmc3";
			break;
		case 774:
			spr_name = "pmc4";
			break;
		case 775:
			spr_name = "pmc5";
			break;
		case 776:
			spr_name = "pmc6";
			break;
		case 779:
			spr_name = "mmcr0";
			break;
		case 800:
			spr_name = "bescrs";
			break;
		case 801:
			spr_name = "bescrsu";
			break;
		case 802:
			spr_name = "bescrr";
			break;
		case 803:
			spr_name = "bescrru";
			break;
		case 804:
			spr_name = "ebbhr";
			break;
		case 805:
			spr_name = "ebbrr";
			break;
		case 806:
			spr_name = "bescr";
			break;
		case 815:
			spr_name = "tar";
			break;
		case 896:
			spr_name = "ppr";
			break;
		case 898:
			spr_name = "ppr32";
			break;
		}
		break;
	// WRITE/READ only
	case PPC_INS_MTFSB0:
	case PPC_INS_MTFSB1:
	case PPC_INS_MTFSF:
	case PPC_INS_MTFSFI:
	case PPC_INS_MFFS:
	case PPC_INS_MFTB:
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
	case PPC_INS_MFXER:
	case PPC_INS_MTXER:
		if (id == PPC_INS_MTXER) {
			return ppc_set_xer(VARG(rS), mode);
		}
		spr_name = "xer";
		set_val = SETL("val", ppc_get_xer(mode));
		break;
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
		NOT_IMPLEMENTED;
	}
	if (set_val) {
		RzILOpEffect *write_spr = ppc_moves_to_spr(id) ? SETG(spr_name, UNSIGNED(size, VARL("val"))) : SETG(rT, UNSIGNED(size, VARL("val")));
		return SEQ2(set_val, write_spr);
	}
	return ppc_moves_to_spr(id) ? SETG(spr_name, UNSIGNED(size, VARG(rS))) : SETG(rT, UNSIGNED(size, VARG(spr_name)));
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

	RzILOpPure *n; // Shift/rotate steps
	RzILOpPure *r; // Rotate result
	RzILOpPure *b, *e; // Mask begin/end
	RzILOpPure *into_rA;
	RzILOpPure *ca_val; // Arithmetic shift instructions set the ca and ca32 field.
	RzILOpEffect *set_mask = NULL, *set_ca = NULL, *update_cr0 = NULL;

	// How to read instruction ids:
	// Letter			Meaning
	// R/S				Rotate, Shift
	// L/R				Left, Right
	// W/D		 		Word, Double Word
	// A/I				Algebraic, Immediate
	// C/CL/CR			Clear, clear left/right
	// M/NM/MI			Mask, AND with mask, mask insert

	switch (id) {
	default:
		NOT_IMPLEMENTED;
	case PPC_INS_ROTLW:
	case PPC_INS_ROTLWI:
	case PPC_INS_RLWIMI:
	case PPC_INS_RLWINM:
	case PPC_INS_RLWNM:;
		if (id == PPC_INS_RLWNM || id == PPC_INS_ROTLW) {
			n = CAST(6, IL_FALSE, LOGAND(VARG(rB), UA(0x1f)));
		} else {
			n = U8(sH);
		}
		r = ROTL32(UNSIGNED(32, VARG(rS)), n);
		if (id == PPC_INS_ROTLW || id == PPC_INS_ROTLWI) {
			b = U8(32); // mb: 0 + 32
			e = U8(63); // me: 31 + 32
		} else {
			b = ADD(U8(mB), U8(32));
			e = ADD(U8(mE), U8(32));
		}
		set_mask = SET_MASK(b, e);
		into_rA = LOGAND(r, VARL("mask"));
		if (id == PPC_INS_RLWIMI) {
			into_rA = LOGOR(into_rA, LOGAND(VARG(rA), LOGNOT(VARL("mask"))));
		}
		break;
	case PPC_INS_ROTLD:
	case PPC_INS_ROTLDI:
	case PPC_INS_RLDCL:
	case PPC_INS_RLDCR:
	case PPC_INS_RLDIC:
	case PPC_INS_RLDICL:
	case PPC_INS_RLDICR:
	case PPC_INS_RLDIMI:;
		if (id == PPC_INS_RLDCR || id == PPC_INS_RLDCL || id == PPC_INS_ROTLD) {
			// For these instruction ME is the third operand, not MB.
			mE = INSOP(3).imm;
			n = CAST(6, IL_FALSE, LOGAND(VARG(rB), UA(0x3f)));
		} else if (id == PPC_INS_RLDICR) {
			mE = INSOP(3).imm;
			n = U8(sH);
		} else {
			n = U8(sH);
		}
		r = ROTL64(VARG(rS), n);
		if (id == PPC_INS_RLDICR || id == PPC_INS_RLDCR) {
			e = U8(mE);
			set_mask = SET_MASK(U8(0), e);
		} else {
			b = U8(mB);
			if (id == PPC_INS_RLDCL || id == PPC_INS_RLDICL) {
				set_mask = SET_MASK(b, U8(63));
			} else if (id == PPC_INS_ROTLDI || id == PPC_INS_ROTLD) {
				set_mask = SET_MASK(U8(0), U8(63));
			} else {
				set_mask = SET_MASK(b, LOGAND(U8(0x3f), LOGNOT(DUP(n)))); // AND with 0x3f since n is a 6bit number.
			}
		}

		into_rA = LOGAND(r, VARL("mask"));
		if (id == PPC_INS_RLDIMI) {
			into_rA = LOGOR(into_rA, LOGAND(VARG(rA), LOGNOT(VARL("mask"))));
		}
		break;
	case PPC_INS_SLDI:
		// Currently broken in rizins capstone version.
		// Immediate is not in instruction.
		NOT_IMPLEMENTED;
	case PPC_INS_SLD:
	case PPC_INS_SRD:
	case PPC_INS_SLWI:
	case PPC_INS_SRWI:
		if (id == PPC_INS_SLD || id == PPC_INS_SRD) {
			n = VARG(rB);
		} else {
			n = U8(sH);
		}
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
		// Set ca, ca32 to 1 if RS is negative and 1s were shifted out.
		ca_val = ITE(AND(SLT(VARG(rS), UA(0)),
				     NON_ZERO(MOD(VARG(rS), EXTZ(SHIFTL0(UA(1), DUP(n)))))), // (RS % (1 << n)) != 0
			IL_TRUE,
			IL_FALSE);
		set_ca = SEQ2(SETG("ca", ca_val), SETG("ca32", DUP(ca_val)));
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
		ca_val = ITE(AND(SLT(UNSIGNED(32, VARG(rS)), U32(0)),
				     NON_ZERO(MOD(UNSIGNED(32, VARG(rS)), UNSIGNED(32, SHIFTL0(UA(1), DUP(n)))))), // (RS % (1 << n)) != 0
			IL_TRUE,
			IL_FALSE);
		set_ca = SEQ2(SETG("ca", ca_val), IN_64BIT_MODE ? SETG("ca32", DUP(ca_val)) : EMPTY());
		break;
	case PPC_INS_CLRLDI:
	case PPC_INS_CLRLWI:
		n = U8(0);
		r = ROTL64(VARG(rS), n);
		b = (id == PPC_INS_CLRLWI) ? ADD(U8(INSOP(2).imm), U8(32)) : U8(INSOP(2).imm);
		e = U8(63);
		set_mask = SET_MASK(b, e);
		into_rA = LOGAND(r, VARL("mask"));
	}

	update_cr0 = sets_cr0 ? cmp_set_cr(DUP(into_rA), UA(0), true, "cr0", mode) : NOP();
	set_mask = set_mask ? set_mask : NOP();
	set_ca = set_ca ? set_ca : NOP();

	return SEQ4(set_mask, SETG(rA, into_rA), update_cr0, set_ca);
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

// TODO
//! Untested. Musl and gnu compile did not recognized isel as instruction.
static RzILOpEffect *iselect(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, EMPTY());
	if (insn->id != PPC_INS_ISEL) {
		NULL;
	}
	const char *rT = cs_reg_name(handle, INSOP(0).reg);
	const char *rA = cs_reg_name(handle, INSOP(1).reg);
	const char *rB = cs_reg_name(handle, INSOP(2).reg);
	ut8 bc = INSOP(3).imm;
	const char *crx = ppc_get_cr_name(bc / 4);
	ut8 crx_bit = bc % 4;
	RzILOpBool *bit_set = BIT_IS_SET(VARG(crx), 4, U8(crx_bit));
	return SETG(rT, ITE(bit_set, VARG(rA), VARG(rB)));
}

/**
 * \brief Returns the RZIL implementation of a given capstone instruction.
 * Or NOP() if the instruction is not yet implemented.
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
	case PPC_INS_XNOP:
	case PPC_INS_DCBT:
	case PPC_INS_DCBTST:
	// Everything is executed liniar => Sync instructions are NOP()s.
	case PPC_INS_ISYNC:
	case PPC_INS_SYNC:
	case PPC_INS_LWSYNC:
	case PPC_INS_MSYNC:
	case PPC_INS_PTESYNC:
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
	case PPC_INS_LBZCIX:
	case PPC_INS_LBZU:
	case PPC_INS_LBZUX:
	case PPC_INS_LBZX:
	case PPC_INS_LD:
	case PPC_INS_LDARX:
	case PPC_INS_LDBRX:
	case PPC_INS_LDCIX:
	case PPC_INS_LDU:
	case PPC_INS_LDUX:
	case PPC_INS_LDX:
	case PPC_INS_LHA:
	case PPC_INS_LHAU:
	case PPC_INS_LHAUX:
	case PPC_INS_LHAX:
	case PPC_INS_LHBRX:
	case PPC_INS_LHZ:
	case PPC_INS_LHZCIX:
	case PPC_INS_LHZU:
	case PPC_INS_LHZUX:
	case PPC_INS_LHZX:
	case PPC_INS_LWA:
	case PPC_INS_LWARX:
	case PPC_INS_LWAUX:
	case PPC_INS_LWAX:
	case PPC_INS_LWBRX:
	case PPC_INS_LWZ:
	case PPC_INS_LWZCIX:
	case PPC_INS_LWZU:
	case PPC_INS_LWZUX:
	case PPC_INS_LWZX:
		lop = load_op(handle, insn, mode);
		break;
	case PPC_INS_STB:
	case PPC_INS_STBCIX:
	case PPC_INS_STBU:
	case PPC_INS_STBUX:
	case PPC_INS_STBX:
	case PPC_INS_STD:
	case PPC_INS_STDBRX:
	case PPC_INS_STDCIX:
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
	case PPC_INS_STHCIX:
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
	case PPC_INS_STWCIX:
	case PPC_INS_STWCX:
	case PPC_INS_STWU:
	case PPC_INS_STWUX:
	case PPC_INS_STWX:
	case PPC_INS_STXSDX:
	case PPC_INS_STXVD2X:
	case PPC_INS_STXVW4X:
	case PPC_INS_DCBZ:
		lop = store_op(handle, insn, mode);
		break;
	case PPC_INS_MR:
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
	case PPC_INS_XOR:
	case PPC_INS_XORI:
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
		lop = bitwise_op(handle, insn, mode);
		break;
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
	case PPC_INS_BL:
	case PPC_INS_BLA:
	case PPC_INS_BLR:
	case PPC_INS_BLRL:
	case PPC_INS_BCA:
	case PPC_INS_BCLA:
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
		lop = branch_op(handle, insn, mode);
		break;
	// These instruction are not in the ISA manual v3.1B.
	case PPC_INS_BRINC:
	case PPC_INS_BCT:
	case PPC_INS_ATTN:
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
	case PPC_INS_MTFSFI:
	case PPC_INS_MTLR:
	case PPC_INS_MTMSR:
	case PPC_INS_MTMSRD:
	case PPC_INS_MTOCRF:
	case PPC_INS_MTSPR:
	case PPC_INS_MTSR:
	case PPC_INS_MTSRIN:
	case PPC_INS_MTVSCR:
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
	case PPC_INS_MFDCCR:
	case PPC_INS_MFICCR:
	case PPC_INS_MFDEAR:
	case PPC_INS_MFESR:
	case PPC_INS_MFSPEFSCR:
	case PPC_INS_MFTCR:
	case PPC_INS_MFASR:
	case PPC_INS_MFPVR:
	case PPC_INS_MFTBU:
	case PPC_INS_MTCR:
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
		lop = move_from_to_spr_op(handle, insn, mode);
		break;
	case PPC_INS_ISEL:
		lop = iselect(handle, insn, mode);
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
	case PPC_INS_ROTLD:
	case PPC_INS_ROTLDI:
	case PPC_INS_CLRLDI:
	case PPC_INS_ROTLWI:
	case PPC_INS_CLRLWI:
	case PPC_INS_ROTLW:
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
