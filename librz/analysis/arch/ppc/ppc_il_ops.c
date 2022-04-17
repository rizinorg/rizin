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
	// READ
	const char *rT = cs_reg_name(handle, INSOP(0).reg);
	const char *rA = cs_reg_name(handle, INSOP(1).reg);
	st64 sI = INSOP(1).imm;
	RzILOpPure *op0;

	if (!rA && insn->id == PPC_INS_LI) {
		// LLVM/capstone bug?
		// rA is NULL although it the instruction is marked as LI.
		// Possibly a confusion?
		// Because "li rA, rB" becomes "lis rA, 0" if (rB) = 0.
		insn->id = PPC_INS_LIS;
	}

	// EXEC
	switch (insn->id) {
	default:
		NOT_IMPLEMENTED;
	case PPC_INS_LI: // Equvialent to ADDI with 0
		op0 = VARG(rA);
		break;
	case PPC_INS_LIS:; // Equvialent to ADDIS with 0
		op0 = EXTEND(PPC_ARCH_BITS, IMM_SN(16, sI));
		break;
	}

	rz_return_val_if_fail(op0, NULL);
	RzILOpEffect *res = SETG(rT, op0);
	return res;
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
	rz_return_val_if_fail(handle && insn, NOP);
	// READ
	const char *rT = cs_reg_name(handle, INSOP(0).reg);
	const char *rA = cs_reg_name(handle, INSOP(1).reg);
	const char *rB = cs_reg_name(handle, INSOP(2).reg);
	st64 sI = INSOP(2).imm;

	bool set_ca = (insn->id != PPC_INS_ADD && insn->id != PPC_INS_ADDI && insn->id != PPC_INS_SUBF);
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

	// EXEC
	switch (insn->id) {
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
	case PPC_INS_SUBFIC:
		cr0 = insn->id == PPC_INS_ADDIC;
		op0 = add ? VARG(rA) : ADD(LOGNOT(VARG(rA)), UA(1));
		op1 = IMM_S(sI);
		res = ADD(op0, op1);
		break;
	case PPC_INS_ADDIS:;
		RzILOpPure *a = add ? VARG(rA) : ADD(LOGNOT(VARG(rA)), UA(1));
		op0 = ITE(EQ(a, UA(0)), UA(0), DUP(a)); // RA == 0 ? 0 : (RA)
		op1 = EXTEND(PPC_ARCH_BITS, IMM_SN(16, sI));
		res = ADD(op0, op1);
		break;
	case PPC_INS_ADDME:
	case PPC_INS_SUBFME:
		cr0 = true;
		op0 = add ? VARG(rA) : LOGNOT(VARG(rA));
		op2 = BOOL_TO_BV(VARG("ca"), PPC_ARCH_BITS);
		op1 = ADD(op2, SA(-1));
		res = ADD(op0, op1);
		break;
	case PPC_INS_ADDZE:
	case PPC_INS_SUBFZE:
		cr0 = true;
		op0 = add ? VARG(rA) : LOGNOT(VARG(rA));
		op1 = BOOL_TO_BV(VARG("ca"), PPC_ARCH_BITS);
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
		lop = load_op(handle, insn, mode);
		break;
	}
	return lop;
}

#include <rz_il/rz_il_opbuilder_end.h>
