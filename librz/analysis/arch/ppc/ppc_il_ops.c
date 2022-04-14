// SPDX-FileCopyrightText: 2022 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "ppc_il.h"
#include "ppc_analysis.h"
#include <rz_il/rz_il_opcodes.h>
#include <rz_util/rz_assert.h>
#include <capstone.h>
#include <rz_il/rz_il_opbuilder_begin.h>

#define UA(i)    ((mode & CS_MODE_64) ? U64(i) : U32(i))
#define SA(i)    ((mode & CS_MODE_64) ? S64(i) : S32(i))
#define IMM_U(i) ((mode & CS_MODE_64) ? U64(i) : U32(i))
#define IMM_S(i) ((mode & CS_MODE_64) ? S64(i) : S32(i))
// Extends x from s on with sign bits.
#define EXTS(x, s) ITE(MSB(x), \
	LOGOR(x, SHIFTL0(UNMAX(PURE_BV_LEN(x)), s)), \
	LOGAND(x, UNMAX(PURE_BV_LEN(x))))

#define NOT_IMPLEMENTED \
	do { \
		RZ_LOG_INFO("IL instruction not implemented."); \
		return NOP; \
	} while (0)

static RzILOpPure *get_bit_dependend_reg(const char *name, cs_mode mode) {
	rz_return_val_if_fail(name, NULL);

	if (mode & CS_MODE_64) {
		return VARG(name);
	}
	char *reg = strdup(name);
	char *reg_32 = rz_str_append(reg, "_32");
	RzILOpPure *res = VARG(reg_32);
	free(reg_32);
	return res;
}

static RzILOpEffect *set_bit_dependend_reg(const char *name, RZ_NONNULL RzILOpPure *x, cs_mode mode) {
	rz_return_val_if_fail(name, NULL);

	if (mode & CS_MODE_64) {
		return SETG(name, x);
	}
	char *reg = strdup(name);
	char *reg_32 = rz_str_append(reg, "_32");
	RzILOpEffect *res = SETG(reg_32, x);
	free(reg_32);
	return res;
}

#define GET_GPR(name)    get_bit_dependend_reg(name, mode)
#define SET_GPR(name, x) set_bit_dependend_reg(name, x, mode)

/**
 * \brief Handles all supported ADD operations.
 *
 * NOTE: Any operations which set the 'OV' bit are not supported yet.
 *
 * \param handle The capstone handle.
 * \param insn The capstone instruction.
 * \param mode The capstone mode.
 * \return RzILOpEffect* Sequence of effects.
 */
static RzILOpEffect *add_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
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
		op0 = GET_GPR(rA);
		op1 = GET_GPR(rB);
		add = ADD(op0, op1);
		break;
	case PPC_INS_ADDE:
		op0 = GET_GPR(rA);
		op1 = GET_GPR(rB);
		op2 = ADD(op1, VARG("ca"));
		add = ADD(op0, op2);
		break;
	case PPC_INS_ADDI:
	case PPC_INS_ADDIC:
		op0 = GET_GPR(rA);
		op1 = IMM_S(sI);
		add = ADD(op0, op1);
		break;
	case PPC_INS_ADDIS:
		op0 = ITE(EQ(GET_GPR(rA), UA(0)),
			UA(0),
			GET_GPR(rA));
		op1 = EXTS(LOGOR(U16(0), IMM_S(sI)), UA(16));
		add = ADD(op0, op1);
		break;
	case PPC_INS_ADDME:
		op0 = GET_GPR(rA);
		op1 = VARG("ca");
		op2 = ADD(op1, SA(-1));
		add = ADD(op0, op2);
		break;
	case PPC_INS_ADDZE:
		op0 = GET_GPR(rA);
		op1 = VARG("ca");
		add = ADD(op0, op1);
		break;
	}

	// WRITE
	RzILOpEffect *res;
	RzILOpEffect *set_carry = set_ca ? set_carry_add_sub(op0, op1, mode, true) : NOP;
	// Instructions which set the OV bit are not supported in capstone.
	// See: https://github.com/capstone-engine/capstone/issues/944
	RzILOpEffect *overflow = NOP;
	RzILOpEffect *update_cr0 = rc ? set_cr0(add) : NOP;

	res = SET_GPR(rT, add);
	return SEQ4(res, set_carry, overflow, update_cr0);
}

RZ_IPI RzILOpEffect *rz_ppc_cs_get_il_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode) {
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
	}
	return lop;
}

#include <rz_il/rz_il_opbuilder_end.h>
