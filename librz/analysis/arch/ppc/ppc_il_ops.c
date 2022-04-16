// SPDX-FileCopyrightText: 2022 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "ppc_il.h"
#include "ppc_analysis.h"
#include <rz_il/rz_il_opcodes.h>
#include <rz_util/rz_assert.h>
#include <capstone.h>
#include <rz_il/rz_il_opbuilder_begin.h>

#define UA(i)    (IN_64BIT_MODE ? U64(i) : U32(i))
#define SA(i)    (IN_64BIT_MODE ? S64(i) : S32(i))
#define IMM_U(i) UA(i)
#define IMM_S(i) SA(i)
#define NOT_IMPLEMENTED \
	do { \
		RZ_LOG_INFO("IL instruction not implemented."); \
		return NOP; \
	} while (0)

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
		RzILOpPure *imm = LOGOR(U32(0), IMM_S(sI));
		op0 = CAST(16, MSB(imm), DUP(imm));
		rz_return_val_if_fail(imm && op0, NULL);
		break;
	}

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
 * \param mode The capstone mode.
 * \return RzILOpEffect* Sequence of effects.
 */
static RzILOpEffect *add_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(handle && insn, NOP);
	// READ
	const char *rT = cs_reg_name(handle, INSOP(0).reg);
	const char *rA = cs_reg_name(handle, INSOP(1).reg);
	const char *rB = cs_reg_name(handle, INSOP(2).reg);
	st64 sI = INSOP(2).imm;

	bool rc = insn->detail->ppc.update_cr0;
	bool set_ca = (insn->id == PPC_INS_ADD || insn->id == PPC_INS_ADDI) ? false : true;

	RzILOpPure *op0;
	RzILOpPure *op1;
	RzILOpPure *op2;
	RzILOpPure *add;

	// EXEC
	switch (insn->id) {
	default:
		NOT_IMPLEMENTED;
	case PPC_INS_ADD:
	case PPC_INS_ADDC:
		op0 = VARG(rA);
		op1 = VARG(rB);
		add = ADD(op0, op1);
		break;
	case PPC_INS_ADDE:
		op0 = VARG(rA);
		op2 = VARG(rB);
		op1 = ADD(op2, VARG("ca"));
		add = ADD(op0, op1);
		break;
	case PPC_INS_ADDI:
	case PPC_INS_ADDIC:
		op0 = VARG(rA);
		op1 = IMM_S(sI);
		add = ADD(op0, op1);
		break;
	case PPC_INS_ADDIS:;
		RzILOpPure *imm = LOGOR(U16(0), IMM_S(sI));
		op0 = ITE(EQ(VARG(rA), UA(0)), UA(0), VARG(rA)); // RA == 0 ? 0 : (RA)
		op1 = CAST(32, MSB(imm), DUP(imm));
		add = ADD(op0, op1);
		break;
	case PPC_INS_ADDME:;
		op0 = VARG(rA);
		op2 = VARG("ca");
		op1 = ADD(op2, SA(-1));
		add = ADD(op0, op1);
		break;
	case PPC_INS_ADDZE:
		op0 = VARG(rA);
		op1 = VARG("ca");
		add = ADD(op0, op1);
		break;
	}

	// WRITE
	RzILOpEffect *res;
	RzILOpEffect *set_carry = set_ca ? set_carry_add_sub(DUP(op0), DUP(op1), mode, true) : NOP;

	// Instructions which set the OV bit are not supported in capstone.
	// See: https://github.com/capstone-engine/capstone/issues/944
	RzILOpEffect *overflow = NOP;
	RzILOpEffect *update_cr0 = rc ? set_cr0(DUP(add)) : NOP;

	res = SETG(rT, add);
	return SEQ4(res, set_carry, overflow, update_cr0);
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
		lop = add_op(handle, insn, mode);
		break;
	case PPC_INS_LI:
	case PPC_INS_LIS:
		lop = load_op(handle, insn, mode);
		break;
	}
	return lop;
}

#include <rz_il/rz_il_opbuilder_end.h>
