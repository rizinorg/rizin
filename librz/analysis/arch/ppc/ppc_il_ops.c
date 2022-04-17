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
	bool update_ra = false; // Save ea in RA?
	ut32 mem_acc_size = ppc_get_mem_acc_size(id);
	RzILOpPure *op0;
	RzILOpPure *op1;
	RzILOpPure *ea;
	RzILOpPure *into_rt;

	if (!rA && id == PPC_INS_LI) {
		// LLVM/capstone bug?
		// rA is NULL although it shouldn't (`li RT, RA`).
		// Possibly a confusion?
		// Because "li rA, rB" becomes "lis rA, 0" if (rB) = 0.
		// We set the id here again.
		id = PPC_INS_LIS;
	}

	// How to read instruction ids:
	// Letter			Meaning
	// L 				Load
	// B/H/.. 			Byte, Half Word, ...
	// Z/A/BR			Zero extend, Algebraic, Byte reversal
	// U				Update (store EA in RA)
	// X				X Form instruction (uses RB instead of immediate)

	// EXEC
	switch (id) {
	default:
		NOT_IMPLEMENTED;
	case PPC_INS_LI: // RT = sI
		into_rt = EXTEND(PPC_ARCH_BITS, IMM_SN(16, sI));
		break;
	case PPC_INS_LIS:; // RT = SI
		into_rt = EXTEND(PPC_ARCH_BITS, APPEND(IMM_SN(32, sI), U16(0)));
		break;
	case PPC_INS_LA: // RT = EA
		op0 = IFREG0(rA);
		op1 = EXTEND(PPC_ARCH_BITS, IMM_SN(16, d));
		ea = ADD(op0, op1);
		into_rt = ea;
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
		op0 = IFREG0(rA); // Not all instructions use the plain value 0 if rA = 0. But we ignore this here.
		op1 = ppc_is_x_form(id) ? VARG(rB) : EXTEND(PPC_ARCH_BITS, IMM_SN(16, d));
		ea = ADD(op0, op1);
		into_rt = (mem_acc_size == 64) ? LOADW(mem_acc_size, ea) : EXTZ(LOADW(mem_acc_size, ea));
		update_ra = ppc_updates_ra_with_ea(id);
		break;
	case PPC_INS_LBZCIX:
	case PPC_INS_LHZCIX:
	case PPC_INS_LWZCIX:
	case PPC_INS_LDCIX:
	case PPC_INS_LDARX:
	case PPC_INS_LHA:
	case PPC_INS_LHAU:
	case PPC_INS_LHAUX:
	case PPC_INS_LHAX:
	case PPC_INS_LHBRX:
	case PPC_INS_LDBRX:
		NOT_IMPLEMENTED;
	case PPC_INS_LSWI:
	case PPC_INS_LVEBX:
	case PPC_INS_LVEHX:
	case PPC_INS_LVEWX:
	case PPC_INS_LVSL:
	case PPC_INS_LVSR:
	case PPC_INS_LVX:
	case PPC_INS_LVXL:
	case PPC_INS_LXSDX:
	case PPC_INS_LXVD2X:
	case PPC_INS_LXVDSX:
	case PPC_INS_LXVW4X:
		NOT_IMPLEMENTED;
	// Floats
	case PPC_INS_LFD:
	case PPC_INS_LFDU:
	case PPC_INS_LFDUX:
	case PPC_INS_LFDX:
	case PPC_INS_LFIWAX:
	case PPC_INS_LFIWZX:
	case PPC_INS_LFS:
	case PPC_INS_LFSU:
	case PPC_INS_LFSUX:
	case PPC_INS_LFSX:
		NOT_IMPLEMENTED;
	}

	// rz_return_val_if_fail(op0, NULL);
	RzILOpEffect *res = SETG(rT, into_rt);
	RzILOpEffect *update = update_ra ? SETG(rA, ea) : NOP;
	return SEQ2(res, update);
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
	}
	return lop;
}

#include <rz_il/rz_il_opbuilder_end.h>
