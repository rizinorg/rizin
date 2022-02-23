// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <capstone.h>

#include "arm_cs.h"
#include "arm_accessors64.h"

#include <rz_il/rz_il_opbuilder_begin.h>
// This source file is 64-bit specific, so avoid having to type 64 all the time:
#define IMM IMM64
#define REGID REGID64
#define ISIMM ISIMM64
#define ISREG ISREG64
#define ISMEM ISMEM64

/**
 * All regs available as global IL variables
 */
static const char *regs_bound[] = {
	"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
	"x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp",
	NULL
};

/**
 * Variable name for a register given by cs
 */
static const char *reg_var_name(arm64_reg reg) {
	if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) {
		reg = ARM64_REG_X0 + (reg - ARM64_REG_W0);
	}
	switch (reg) {
	case ARM64_REG_X0: return "x0";
	case ARM64_REG_X1: return "x1";
	case ARM64_REG_X2: return "x2";
	case ARM64_REG_X3: return "x3";
	case ARM64_REG_X4: return "x4";
	case ARM64_REG_X5: return "x5";
	case ARM64_REG_X6: return "x6";
	case ARM64_REG_X7: return "x7";
	case ARM64_REG_X8: return "x8";
	case ARM64_REG_X9: return "x9";
	case ARM64_REG_X10: return "x10";
	case ARM64_REG_X11: return "x11";
	case ARM64_REG_X12: return "x12";
	case ARM64_REG_X13: return "x13";
	case ARM64_REG_X14: return "x14";
	case ARM64_REG_X15: return "x15";
	case ARM64_REG_X16: return "x16";
	case ARM64_REG_X17: return "x17";
	case ARM64_REG_X18: return "x18";
	case ARM64_REG_X19: return "x19";
	case ARM64_REG_X20: return "x20";
	case ARM64_REG_X21: return "x21";
	case ARM64_REG_X22: return "x22";
	case ARM64_REG_X23: return "x23";
	case ARM64_REG_X24: return "x24";
	case ARM64_REG_X25: return "x25";
	case ARM64_REG_X26: return "x26";
	case ARM64_REG_X27: return "x27";
	case ARM64_REG_X28: return "x28";
	case ARM64_REG_X29: return "x29";
	case ARM64_REG_X30: return "x30";
	case ARM64_REG_SP: return "sp";
	default: return NULL;
	}
}

/**
 * IL to read the given capstone reg
 */
static RzILOpBitVector *read_reg(/*ut64 pc, */arm64_reg reg) {
	// if (reg == ARM64_REG_PC) {
	// 	return U32(pc);
	// }
	const char *var = reg_var_name(reg);
	return var ? VARG(var) : NULL;
}

// #define PC(addr)      (addr)
#define REG_VAL(id)   read_reg(/*PC(insn->address), */id)
#define REG(n)        REG_VAL(REGID(n))
// #define MEMBASE(x)    REG_VAL(insn->detail->arm64.operands[x].mem.base)

/**
 * IL to write a value to the given capstone reg
 */
static RzILOpEffect *write_reg(arm64_reg reg, RZ_OWN RZ_NONNULL RzILOpBitVector *v) {
	rz_return_val_if_fail(v, NULL);
	const char *var = reg_var_name(reg);
	if (!var) {
		rz_il_op_pure_free(v);
		return NULL;
	}
	return SETG(var, v);
}

/**
 * IL to retrieve the value of the \p n -th arg of \p insn
 */
static RzILOpBitVector *arg(cs_insn *insn, int n) {
	cs_arm64_op *op = &insn->detail->arm64.operands[n];
	switch (op->type) {
	case ARM64_OP_REG: {
		return REG(n);
	}
	case ARM64_OP_IMM: {
		return U64(IMM(n));
	}
	case ARM64_OP_MEM: {
		return NULL;
	}
	default:
		break;
	}
	return NULL;
}

#define ARG(n)          arg(insn, n)

/**
 * Capstone: ARM64_INS_ADD
 * ARM: add
 */
static RzILOpEffect *add(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	RzILOpBitVector *a = ARG(1);
	RzILOpBitVector *b = ARG(2);
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	return write_reg(REGID(0), ADD(a, b));
}

RZ_IPI RzILOpEffect *rz_arm_cs_64_il(csh *handle, cs_insn *insn) {
	switch (insn->id) {
	case ARM64_INS_ADD:
		return add(insn);
		break;
	}
	return NULL;
}

#include <rz_il/rz_il_opbuilder_end.h>

RZ_IPI RzAnalysisILConfig *rz_arm_cs_64_il_config(bool big_endian) {
	RzAnalysisILConfig *r = rz_analysis_il_config_new(32, big_endian, 32);
	r->reg_bindings = regs_bound;
	return r;
}
