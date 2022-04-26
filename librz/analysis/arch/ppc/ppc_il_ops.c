// SPDX-FileCopyrightText: 2022 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "ppc_il.h"
#include "ppc_analysis.h"
#include <rz_il/rz_il_opcodes.h>
#include <rz_util/rz_assert.h>
#include <capstone.h>
#include <rz_il/rz_il_opbuilder_begin.h>

/**
 * \brief Handles all supported LOAD operations.
 *
 * \param handle The capstone handle.
 * \param insn The capstone instruction.
 * \param mode The capstone mode.
 * \return RzILOpEffect* Sequence of effects.
 */
static RzILOpEffect *load_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, NOP);
	ut32 id = insn->id;
	// READ
	const char *rT = cs_reg_name(handle, INSOP(0).reg);
	const char *rA = cs_reg_name(handle, INSOP(1).reg);
	const char *rB = cs_reg_name(handle, INSOP(2).reg);
	st64 d = INSOP(1).imm;
	st64 sI = d;
	bool update_ra = ppc_updates_ra_with_ea(id); // Save ea in RA?
	ut32 mem_acc_size = ppc_get_mem_acc_size(id);
	RzILOpPure *op0;
	RzILOpPure *op1;
	RzILOpPure *ea;
	RzILOpPure *into_rt;

	// How to read instruction ids:
	// Letter			Meaning
	// L 				Load
	// B/H/.. 			Byte, Half Word, ...
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
		into_rt = EXTEND(PPC_ARCH_BITS, IMM_SN(16, sI));
		update_ra = false;
		break;
	case PPC_INS_LIS: // RT = SI << 16
		into_rt = EXTEND(PPC_ARCH_BITS, APPEND(IMM_SN(16, sI), U16(0)));
		update_ra = false;
		break;
	case PPC_INS_LA: // RT = EA
		op0 = IFREG0(rA);
		op1 = EXTEND(PPC_ARCH_BITS, IMM_SN(16, d));
		ea = ADD(op0, op1);
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
		op0 = IFREG0(rA); // Not all instructions use the plain value 0 if rA = 0. But we ignore this here.
		if (ppc_is_x_form(id)) {
			op1 = VARG(rB);
		} else {
			RzILOpPure *imm = (id == PPC_INS_LD || id == PPC_INS_LWA) ? APPEND(IMM_SN(16, d), UN(2, 0)) : IMM_SN(16, d);
			op1 = EXTEND(PPC_ARCH_BITS, imm);
		}
		ea = ADD(op0, op1);
		if (ppc_is_algebraic(id)) {
			into_rt = (mem_acc_size == 64) ? LOADW(mem_acc_size, ea) : EXTEND(PPC_ARCH_BITS, LOADW(mem_acc_size, ea));
		} else {
			into_rt = (mem_acc_size == 64) ? LOADW(mem_acc_size, ea) : EXTZ(LOADW(mem_acc_size, ea));
		}
		break;
	// Byte reverse and reserved indexed
	case PPC_INS_LWARX:
	case PPC_INS_LHBRX:
	case PPC_INS_LDARX:
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
	// Caching Inhibited Indexed
	case PPC_INS_LBZCIX:
	case PPC_INS_LHZCIX:
	case PPC_INS_LWZCIX:
	case PPC_INS_LDCIX:
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
	RzILOpEffect *update = update_ra ? SETG(rA, DUP(ea)) : NOP;
	return SEQ2(res, update);
}

static RzILOpEffect *store_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, NOP);
	ut32 id = insn->id;
	// READ
	const char *rS = cs_reg_name(handle, INSOP(0).reg);
	const char *rA = cs_reg_name(handle, INSOP(1).reg);
	const char *rB = cs_reg_name(handle, INSOP(2).reg);
	st64 d = INSOP(1).imm;
	bool update_ra = ppc_updates_ra_with_ea(id); // Save ea in RA?
	ut32 mem_acc_size = ppc_get_mem_acc_size(id);
	RzILOpPure *op0;
	RzILOpPure *op1;
	RzILOpPure *ea;
	RzILOpEffect *store;

	switch (id) {
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
		op0 = IFREG0(rA); // Not all instructions use the plain value 0 if rA = 0. But we ignore this here.
		if (ppc_is_x_form(id)) {
			op1 = VARG(rB);
		} else {
			RzILOpPure *imm = (id == PPC_INS_STD) ? APPEND(IMM_SN(16, d), UN(2, 0)) : IMM_SN(16, d);
			op1 = EXTEND(PPC_ARCH_BITS, imm);
		}
		ea = ADD(op0, op1);
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
	// Caching Inhibited Indexed
	case PPC_INS_STBCIX:
	case PPC_INS_STHCIX:
	case PPC_INS_STWCIX:
	case PPC_INS_STDCIX:
		NOT_IMPLEMENTED;
	case PPC_INS_STDCX:
	case PPC_INS_STWCX:
		NOT_IMPLEMENTED;
	// Byte reverse and reserved indexed
	case PPC_INS_STHBRX:
	case PPC_INS_STWBRX:
	case PPC_INS_STDBRX:
		NOT_IMPLEMENTED;
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

	rz_return_val_if_fail(ea, NULL);
	RzILOpEffect *update = update_ra ? SETG(rA, DUP(ea)) : NOP;
	return SEQ2(store, update);
}

/**
 * \brief Handles all supported ADD operations.
 *
 * NOTE: Instructions which set the 'OV' bit are not supported yet.
 *
 * \param handle The capstone handle.
 * \param insn The capstone instruction.
 * \param add Is add instructions.
 * \param mode The capstone mode.
 * \return RzILOpEffect* Sequence of effects.
 */
static RzILOpEffect *add_sub_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, bool add, const cs_mode mode) {
	ut32 id = insn->id;
	rz_return_val_if_fail(handle && insn, NOP);
	// READ
	const char *rT = cs_reg_name(handle, INSOP(0).reg);
	const char *rA = cs_reg_name(handle, INSOP(1).reg);
	const char *rB = cs_reg_name(handle, INSOP(2).reg);
	st64 sI = INSOP(2).imm;

	bool set_ca = (id != PPC_INS_ADD && id != PPC_INS_ADDI && id != PPC_INS_ADDIS && id != PPC_INS_SUBF);
	bool cr0 = insn->detail->ppc.update_cr0;
	if (cr0) {
		RZ_LOG_WARN("Capstone fixed a bug!"
			    "The implcit \"cr0\" write is now stored in \"insn->detail->ppc.update_cr0\"."
			    "Explicit flag setting can be removed. Please fix me.\n");
	}

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
		cr0 = true;
		op0 = add ? VARG(rA) : ADD(LOGNOT(VARG(rA)), UA(1));
		op1 = VARG(rB);
		res = ADD(op0, op1);
		break;
	case PPC_INS_ADDE:
	case PPC_INS_SUBFE:
		cr0 = true;
		op0 = add ? VARG(rA) : LOGNOT(VARG(rA));
		op2 = VARG(rB);
		op1 = ADD(op2, BOOL_TO_BV(VARG("ca"), PPC_ARCH_BITS));
		res = ADD(op0, op1);
		break;
	case PPC_INS_ADDI:
	case PPC_INS_ADDIC:
	case PPC_INS_ADDIS:
	case PPC_INS_SUBFIC:
		cr0 = (id == PPC_INS_ADDIC);
		RzILOpPure *a = add ? VARG(rA) : ADD(LOGNOT(VARG(rA)), UA(1));
		op0 = ITE(EQ(a, UA(0)), UA(0), DUP(a)); // RA == 0 ? 0 : (RA)
		if (id == PPC_INS_ADDIS) {
			op1 = EXTEND(PPC_ARCH_BITS, APPEND(IMM_SN(16, sI), U16(0))); // Shift immediate << 16
		} else {
			op1 = EXTEND(PPC_ARCH_BITS, IMM_SN(16, sI));
		}
		res = ADD(op0, op1);
		break;
	case PPC_INS_ADDME:
	case PPC_INS_ADDZE:
	case PPC_INS_SUBFME:
	case PPC_INS_SUBFZE:
		cr0 = true;
		op0 = add ? VARG(rA) : LOGNOT(VARG(rA));
		if (id == PPC_INS_ADDME || id == PPC_INS_SUBFME) {
			op1 = ADD(BOOL_TO_BV(VARG("ca"), PPC_ARCH_BITS), SA(-1)); // Minus 1
		} else {
			op1 = BOOL_TO_BV(VARG("ca"), PPC_ARCH_BITS);
		}
		res = ADD(op0, op1);
		break;
	}
	rz_return_val_if_fail(op0 && op1, NULL);

	// WRITE
	RzILOpEffect *set;
	RzILOpEffect *set_carry = set_ca ? set_carry_add_sub(DUP(op0), DUP(op1), mode, true) : NOP;

	// Instructions which set the OV bit are not supported in capstone.
	// See: https://github.com/capstone-engine/capstone/issues/944
	RzILOpEffect *overflow = NOP;
	RzILOpEffect *update_cr0 = cr0 ? set_cr0(res, mode) : NOP;
	set = SETG(rT, res);
	return SEQ4(set, set_carry, overflow, update_cr0);
}

RZ_IPI RzILOpEffect *rz_ppc_cs_get_il_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, NOP);
	rz_return_val_if_fail(insn->detail, NOP);
	RzILOpEffect *lop;
	switch (insn->id) {
	default:
		NOT_IMPLEMENTED;
	case PPC_INS_INVALID:
		// TODO Exception
		return NOP;
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
	case PPC_INS_SUBF:
	case PPC_INS_SUBFC:
	case PPC_INS_SUBFE:
	case PPC_INS_SUBFIC:
	case PPC_INS_SUBFME:
	case PPC_INS_SUBFZE:
		lop = add_sub_op(handle, insn, false, mode);
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
		lop = store_op(handle, insn, mode);
		break;
	}
	return lop;
}

#include <rz_il/rz_il_opbuilder_end.h>
