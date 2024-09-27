// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_util/rz_assert.h>
#include <capstone/capstone.h>

#include "arm_cs.h"
#include "arm_accessors32.h"

#include <rz_il/rz_il_opbuilder_begin.h>

#include "arm_il_common.inc"

/**
 * \brief Tests if the instruction is part of the given group.
 *
 * \param insn The instruction to test.
 * \param group The group to test for.
 * \return true The instruction is part of the group.
 * \return false The instruction is not part of the group.
 */
RZ_IPI bool rz_arm_cs_is_group_member(RZ_NONNULL const cs_insn *insn, arm_insn_group group) {
	rz_return_val_if_fail(insn && insn->detail, false);
	uint32_t i = 0;
	arm_insn_group group_it = insn->detail->groups[i];
	while (group_it) {
		if (group_it == group) {
			return true;
		}
		group_it = insn->detail->groups[++i];
	}
	return false;
}

/**
 * All regs available as global IL variables
 */
static const char *regs_bound_32[] = {
	"lr", "sp",
	"qf", "vf", "cf", "zf", "nf", "gef",
	"fpscr",
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12",
	"d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15",
	"d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23", "d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31",
	NULL
};

/**
 * Variable name for a register given by cs
 */
static const char *reg_var_name(arm_reg reg) {
	switch (reg) {
	case ARM_REG_LR: return "lr";
	case ARM_REG_SP: return "sp";
	case ARM_REG_D0: return "d0";
	case ARM_REG_D1: return "d1";
	case ARM_REG_D2: return "d2";
	case ARM_REG_D3: return "d3";
	case ARM_REG_D4: return "d4";
	case ARM_REG_D5: return "d5";
	case ARM_REG_D6: return "d6";
	case ARM_REG_D7: return "d7";
	case ARM_REG_D8: return "d8";
	case ARM_REG_D9: return "d9";
	case ARM_REG_D10: return "d10";
	case ARM_REG_D11: return "d11";
	case ARM_REG_D12: return "d12";
	case ARM_REG_D13: return "d13";
	case ARM_REG_D14: return "d14";
	case ARM_REG_D15: return "d15";
	case ARM_REG_D16: return "d16";
	case ARM_REG_D17: return "d17";
	case ARM_REG_D18: return "d18";
	case ARM_REG_D19: return "d19";
	case ARM_REG_D20: return "d20";
	case ARM_REG_D21: return "d21";
	case ARM_REG_D22: return "d22";
	case ARM_REG_D23: return "d23";
	case ARM_REG_D24: return "d24";
	case ARM_REG_D25: return "d25";
	case ARM_REG_D26: return "d26";
	case ARM_REG_D27: return "d27";
	case ARM_REG_D28: return "d28";
	case ARM_REG_D29: return "d29";
	case ARM_REG_D30: return "d30";
	case ARM_REG_D31: return "d31";
	case ARM_REG_R0: return "r0";
	case ARM_REG_R1: return "r1";
	case ARM_REG_R2: return "r2";
	case ARM_REG_R3: return "r3";
	case ARM_REG_R4: return "r4";
	case ARM_REG_R5: return "r5";
	case ARM_REG_R6: return "r6";
	case ARM_REG_R7: return "r7";
	case ARM_REG_R8: return "r8";
	case ARM_REG_R9: return "r9";
	case ARM_REG_R10: return "r10";
	case ARM_REG_R11: return "r11";
	case ARM_REG_R12: return "r12";
	default: return NULL;
	}
}

static ut32 reg_bits(arm_reg reg) {
	if (reg >= ARM_REG_D0 && reg <= ARM_REG_D31) {
		return 64;
	}
	if (reg >= ARM_REG_Q0 && reg <= ARM_REG_Q15) {
		return 128;
	}
	return 32;
}

static bool is_vec_signed(arm_vectordata_type vec_type) {
	switch (vec_type) {
	case ARM_VECTORDATA_S8:
	case ARM_VECTORDATA_S16:
	case ARM_VECTORDATA_S32:
	case ARM_VECTORDATA_S64:
	case ARM_VECTORDATA_I8:
	case ARM_VECTORDATA_I16:
	case ARM_VECTORDATA_I32:
	case ARM_VECTORDATA_I64:
		return true;
	case ARM_VECTORDATA_U8:
	case ARM_VECTORDATA_U16:
	case ARM_VECTORDATA_U32:
	case ARM_VECTORDATA_U64:
		return false;
	default:
		rz_warn_if_reached();
		return 0;
	}
}

static bool is_core_reg(arm_reg reg) {
	if (reg >= ARM_REG_S0 && reg <= ARM_REG_S31) {
		return false;
	}
	if (reg >= ARM_REG_D0 && reg <= ARM_REG_D31) {
		return false;
	}
	if (reg >= ARM_REG_Q0 && reg <= ARM_REG_Q15) {
		return false;
	}
	return true;
}

/**
 * IL to read the given capstone reg
 */
static RzILOpBitVector *read_reg(ut64 pc, arm_reg reg) {
	if (reg == ARM_REG_PC) {
		return U32(pc);
	}
	if (reg >= ARM_REG_S0 && reg <= ARM_REG_S31) {
		ut32 idx = reg - ARM_REG_S0;
		RzILOpBitVector *var = VARG(reg_var_name(ARM_REG_D0 + idx / 2));
		return UNSIGNED(32, idx % 2 ? SHIFTR0(var, UN(7, 32)) : var);
	}
	if (reg >= ARM_REG_Q0 && reg <= ARM_REG_Q15) {
		ut32 low_dr_idx = (reg - ARM_REG_Q0) << 1;
		ut32 high_dr_idx = low_dr_idx + 1;
		RzILOpBitVector *low_var = VARG(reg_var_name(ARM_REG_D0 + low_dr_idx));
		RzILOpBitVector *high_var = VARG(reg_var_name(ARM_REG_D0 + high_dr_idx));
		return APPEND(high_var, low_var);
	}

	const char *var = reg_var_name(reg);
	return var ? VARG(var) : NULL;
}

/**
 * Return IL of bitvector store in register lane
 * The length of such bitv is `data_size`
 */
static RzILOpBitVector *read_reg_lane(arm_reg reg, ut32 lane, ut32 data_size) {
	if (is_core_reg(reg)) {
		rz_warn_if_reached();
		return NULL;
	}

	ut32 shift_dist = lane * data_size;
	RzILOpBitVector *reg_val = read_reg(0, reg);
	return UNSIGNED(data_size, SHIFTR0(reg_val, UN(8, shift_dist)));
}

/**
 * Return the data width of given data type
 * note: Those data_type which contains 2 type (F16.F64, F32.F16)
 * is out of the scope of this function
 */
static inline ut32 arm_data_width(arm_vectordata_type vec_type) {
	switch (vec_type) {
	case ARM_VECTORDATA_I32:
	case ARM_VECTORDATA_U32:
	case ARM_VECTORDATA_S32:
	case ARM_VECTORDATA_F32:
		return 32;
	case ARM_VECTORDATA_I8:
	case ARM_VECTORDATA_U8:
	case ARM_VECTORDATA_S8:
		return 8;
	case ARM_VECTORDATA_I16:
	case ARM_VECTORDATA_S16:
	case ARM_VECTORDATA_U16:
		return 16;
	case ARM_VECTORDATA_I64:
	case ARM_VECTORDATA_F64:
	case ARM_VECTORDATA_U64:
	case ARM_VECTORDATA_S64:
		return 64;
	case ARM_VECTORDATA_INVALID:
	default:
		rz_warn_if_reached();
		return 0;
	}
}

static inline RzFloatFormat dt2fmt(arm_vectordata_type type) {
	switch (type) {
#if CS_API_MAJOR > 4
	case ARM_VECTORDATA_F16:
		return RZ_FLOAT_IEEE754_BIN_16;
#endif
	case ARM_VECTORDATA_F32:
		return RZ_FLOAT_IEEE754_BIN_32;
	case ARM_VECTORDATA_F64:
		return RZ_FLOAT_IEEE754_BIN_64;
	default:
		return RZ_FLOAT_UNK;
	}
}

static inline RzFloatFormat cvtdt2fmt(arm_vectordata_type type, bool choose_src) {
	switch (type) {
	case ARM_VECTORDATA_F16F64:
		return choose_src ? RZ_FLOAT_IEEE754_BIN_64 : RZ_FLOAT_IEEE754_BIN_16;
	case ARM_VECTORDATA_F64F16:
		return choose_src ? RZ_FLOAT_IEEE754_BIN_16 : RZ_FLOAT_IEEE754_BIN_64;
	case ARM_VECTORDATA_F32F16:
		return choose_src ? RZ_FLOAT_IEEE754_BIN_16 : RZ_FLOAT_IEEE754_BIN_32;
	case ARM_VECTORDATA_F16F32:
		return choose_src ? RZ_FLOAT_IEEE754_BIN_32 : RZ_FLOAT_IEEE754_BIN_16;
	case ARM_VECTORDATA_F64F32:
		return choose_src ? RZ_FLOAT_IEEE754_BIN_32 : RZ_FLOAT_IEEE754_BIN_64;
	case ARM_VECTORDATA_F32F64:
		return choose_src ? RZ_FLOAT_IEEE754_BIN_64 : RZ_FLOAT_IEEE754_BIN_32;
	default:
		return RZ_FLOAT_UNK;
	}
}

#define PC(addr, is_thumb)      (addr + (is_thumb ? 4 : 8))
#define PCALIGN(addr, is_thumb) (PC(addr, is_thumb) & ~3ul)
#define REG_VAL(id)             read_reg(PC(insn->address, is_thumb), id)
#define REG(n)                  REG_VAL(REGID(n))
#define MEMBASE(x)              REG_VAL(insn->detail->arm.operands[x].mem.base)
#define MEMINDEX(x)             REG_VAL(insn->detail->arm.operands[x].mem.index)
#define DT_WIDTH(insn)          arm_data_width(insn->detail->arm.vector_data)
#define REG_WIDTH(n)            reg_bits(REGID(n))
#define VVEC_SIZE(insn)         insn->detail->arm.vector_size
#define VVEC_DT(insn)           insn->detail->arm.vector_data
#define FROM_FMT(dt)            cvtdt2fmt(dt, true)
#define TO_FMT(dt)              cvtdt2fmt(dt, false)
#define NEON_LANE(n)            insn->detail->arm.operands[n].neon_lane

/**
 * IL to write the given capstone reg
 */
static RzILOpEffect *write_reg(arm_reg reg, RZ_OWN RZ_NONNULL RzILOpBitVector *v) {
	rz_return_val_if_fail(v, NULL);
	if (reg >= ARM_REG_S0 && reg <= ARM_REG_S31) {
		ut32 idx = reg - ARM_REG_S0;
		arm_reg dreg = ARM_REG_D0 + idx / 2;
		RzILOpBitVector *masked = LOGAND(read_reg(0, dreg), U64(idx % 2 ? 0xffffffffull : 0xffffffff00000000ull));
		v = UNSIGNED(64, v);
		if (idx % 2) {
			v = SHIFTL0(v, UN(6, 32));
		}
		return SETG(reg_var_name(dreg), LOGOR(masked, v));
	}
	if (reg >= ARM_REG_Q0 && reg <= ARM_REG_Q15) {
		arm_reg low_reg = ARM_REG_D0 + ((reg - ARM_REG_Q0) << 1);
		arm_reg high_reg = low_reg + 1;
		RzILOpBitVector *low_val = UNSIGNED(64, v);
		RzILOpBitVector *high_val = UNSIGNED(64, SHIFTR0(DUP(v), UN(8, 64)));
		return SEQ2(
			SETG(reg_var_name(low_reg), low_val),
			SETG(reg_var_name(high_reg), high_val));
	}
	const char *var = reg_var_name(reg);
	if (!var) {
		rz_il_op_pure_free(v);
		return NULL;
	}
	return SETG(var, v);
}

/**
 * IL for arm condition
 * unconditional is returned as NULL (rather than true), for simpler code
 */
#if CS_NEXT_VERSION >= 6
static RZ_NULLABLE RzILOpBool *cond(ARMCC_CondCodes c) {
#else
static RZ_NULLABLE RzILOpBool *cond(arm_cc c) {
#endif
	switch (c) {
	case CS_ARMCC(EQ):
		return VARG("zf");
	case CS_ARMCC(NE):
		return INV(VARG("zf"));
	case CS_ARMCC(HS):
		return VARG("cf");
	case CS_ARMCC(LO):
		return INV(VARG("cf"));
	case CS_ARMCC(MI):
		return VARG("nf");
	case CS_ARMCC(PL):
		return INV(VARG("nf"));
	case CS_ARMCC(VS):
		return VARG("vf");
	case CS_ARMCC(VC):
		return INV(VARG("vf"));
	case CS_ARMCC(HI):
		return AND(VARG("cf"), INV(VARG("zf")));
	case CS_ARMCC(LS):
		return OR(INV(VARG("cf")), VARG("zf"));
	case CS_ARMCC(GE):
		return INV(XOR(VARG("nf"), VARG("vf")));
	case CS_ARMCC(LT):
		return XOR(VARG("nf"), VARG("vf"));
	case CS_ARMCC(GT):
		return AND(INV(VARG("zf")), INV(XOR(VARG("nf"), VARG("vf"))));
	case CS_ARMCC(LE):
		return OR(VARG("zf"), XOR(VARG("nf"), VARG("vf")));
	case CS_ARMCC(AL):
	default:
		return NULL;
	}
}

static bool is_reg_shift(arm_shifter type) {
	switch (type) {
	case ARM_SFT_ASR_REG:
	case ARM_SFT_LSL_REG:
	case ARM_SFT_LSR_REG:
	case ARM_SFT_ROR_REG:
#if CS_NEXT_VERSION < 6
	case ARM_SFT_RRX_REG:
#endif
		return true;
	default:
		return false;
	}
}

static RZ_NULLABLE RzILOpBitVector *
shift(RzILOpBitVector *val, RZ_NULLABLE RzILOpBool **carry_out, arm_shifter type, RZ_OWN RzILOpBitVector *dist) {
	switch (type) {
	case ARM_SFT_ASR:
	case ARM_SFT_ASR_REG:
		if (!dist) {
			return val;
		}
		if (carry_out) {
			*carry_out = LSB(SHIFTRA(APPEND(DUP(val), ITE(VARG("cf"), UN(1, 1), UN(1, 0))), DUP(dist)));
		}
		return SHIFTRA(val, dist);
	case ARM_SFT_LSL:
	case ARM_SFT_LSL_REG:
		if (!dist) {
			return val;
		}
		if (carry_out) {
			*carry_out = MSB(SHIFTL0(APPEND(ITE(VARG("cf"), UN(1, 1), UN(1, 0)), DUP(val)), DUP(dist)));
		}
		return SHIFTL0(val, dist);
	case ARM_SFT_LSR:
	case ARM_SFT_LSR_REG:
		if (!dist) {
			return val;
		}
		if (carry_out) {
			*carry_out = LSB(SHIFTR0(APPEND(DUP(val), ITE(VARG("cf"), UN(1, 1), UN(1, 0))), DUP(dist)));
		}
		return SHIFTR0(val, dist);
	case ARM_SFT_ROR:
	case ARM_SFT_ROR_REG:
		if (!dist) {
			return val;
		}
		if (dist->code == RZ_IL_OP_CAST) {
			// this takes care of the mod 32 for register-based shifts which originally have 8 bits:
			dist->op.cast.length = 5;
		}
		if (carry_out) {
			*carry_out = ITE(IS_ZERO(DUP(dist)), VARG("cf"), MSB(SHIFTL0(DUP(val), NEG(DUP(dist)))));
		}
		return LOGOR(
			SHIFTR0(val, dist),
			SHIFTL0(DUP(val), NEG(DUP(dist))));
	case ARM_SFT_RRX:
#if CS_NEXT_VERSION < 6
	case ARM_SFT_RRX_REG:
#endif
		if (carry_out) {
			*carry_out = LSB(DUP(val));
		}
		rz_il_op_pure_free(dist);
		return SHIFTR(VARG("cf"), val, UN(5, 1));
	default:
		rz_il_op_pure_free(dist);
		return val;
	}
}

static RzILOpBitVector *arg_mem(RzILOpBitVector *base_plus_disp, cs_arm_op *op, RZ_NULLABLE RzILOpBool **carry_out) {
	if (op->mem.index != ARM_REG_INVALID && op->mem.index != ARM_REG_PC) {
		RzILOpBitVector *index = read_reg(0, op->mem.index);
		return ADD(base_plus_disp, shift(index, carry_out, op->shift.type, UN(5, op->shift.value)));
	}
	return base_plus_disp;
}

/**
 * Replicate given value to `dreg_width` length
 * Note the ownership of `val` will be transfered
 */
static RzILOpBitVector *replicated_val(ut32 val_width, ut32 dreg_width, RZ_OWN RzILOpBitVector *val) {
	ut32 repeat_times = dreg_width / val_width;
	if (dreg_width % val_width != 0) {
		rz_warn_if_reached();
		return NULL;
	}

	RzILOpBitVector *ext_val = UNSIGNED(dreg_width, val);
	RzILOpBitVector *rep_val = ext_val;
	for (int i = 0; i < repeat_times - 1; ++i) {
		rep_val = LOGOR(rep_val, SHIFTL0(DUP(ext_val), UN(8, val_width * i)));
	}

	return rep_val;
}

/**
 * For VFP/NEON instruction immediate value
 * <imm> in Arm ref manual: "A constant of the type specified by <dt>.
 * This constant is replicated enough times to fill the destination register.
 */
static RzILOpBitVector *repeated_imm(ut32 imm_width, ut32 dreg_width, ut32 imm) {
	ut64 final_imm = 0;
	ut32 repeat_times = dreg_width / imm_width;
	ut64 tmp = imm;

	if (dreg_width == 128) {
		// for <Qd> registers
		ut64 imm_low = tmp;
		ut64 imm_high = tmp;

		for (int i = 0; i < repeat_times / 2 - 1; ++i) {
			imm_low += tmp;
			imm_high += tmp;
			tmp <<= imm_width;
		}

		return (APPEND(UN(64, imm_high), UN(64, imm_low)));
	}

	// for <Dd> and <Sd>
	final_imm = tmp;
	for (int i = 0; i < repeat_times - 1; ++i) {
		final_imm += tmp;
		tmp <<= imm_width;
	}

	return UN(dreg_width, final_imm);
}

/**
 * Get immediate value operand
 * \param insn instruction
 * \param n operand number
 * \param carry_out carryout value, NULL if ignore
 * \return return immediate value as ut32
 */
static ut32 get_imm(cs_insn *insn, int n, RZ_NULLABLE RzILOpBool **carry_out) {
	if (carry_out) {
		*carry_out = NULL;
	}
	if (ISFPIMM(n)) {
		float fpimm = FPIMM(n);
		RzFloat *f = rz_float_new_from_f32(fpimm);
		ut32 hex_imm = rz_bv_to_ut32(f->s);
		rz_float_free(f);
		return hex_imm;
	}
	cs_arm_op *op = &insn->detail->arm.operands[n];
	ut32 imm = IMM(n);
	if (op->shift.type == ARM_SFT_INVALID && ISIMM(n + 1)) {
		// sometimes capstone encoded the shift like this, see also comment below
		ut32 ror = IMM(n + 1);
		imm = (imm >> ror) | (imm << (32 - ror));
	}

	if (carry_out) {
		// Some "movs"s leave c alone, some set it to the highest bit of the result.
		// Determining which one it is from capstone's info is tricky:
		// Arm defines that it is set when the imm12's rotate value is not 0.
		// This is the case when:
		// * capstone disassembles to something like "movs r0, 0, 2", giving us an explicit third operand
		// * capstone disassembles to something like "movs r0, 0x4000000" without the third operand,
		//   but we can see that the value is larger than 8 bits, so there must be a shift.
		if (ISIMM(n + 1) || imm > 0xff) {
			*carry_out = (imm & (1ul << 31)) ? IL_TRUE : IL_FALSE;
		}
	}

	return imm;
}

/**
 * IL to retrieve the value of the \p n -th arg of \p insn
 * \p carry_out filled with the carry value of NULL if it does not change
 */
static RzILOpBitVector *arg(cs_insn *insn, bool is_thumb, int n, RZ_NULLABLE RzILOpBool **carry_out) {
	if (carry_out) {
		*carry_out = NULL;
	}
	cs_arm_op *op = &insn->detail->arm.operands[n];
	switch (op->type) {
	case ARM_OP_REG: {
		RzILOpBitVector *r = REG(n);
		if (!r) {
			return NULL;
		}
		RzILOpBitVector *dist = NULL;
		if (is_reg_shift(op->shift.type)) {
			dist = read_reg(PC(insn->address, is_thumb), op->shift.value);
			if (dist) {
				dist = UNSIGNED(8, dist);
			}
		} else if (op->shift.type != ARM_SFT_INVALID) {
			dist = UN(5, op->shift.value);
		}
		return r ? shift(r, carry_out, op->shift.type, dist) : NULL;
	}
	case ARM_OP_IMM: {
		ut32 imm = get_imm(insn, n, carry_out);
		return U32(imm);
	}
	case ARM_OP_MEM: {
		RzILOpBitVector *addr = MEMBASE(n);
		int disp = MEMDISP(n);
		if (disp > 0) {
			addr = ADD(addr, U32(disp));
		} else if (disp < 0) {
			addr = SUB(addr, U32(-disp));
		}
		return arg_mem(addr, &insn->detail->arm.operands[n], carry_out);
	}
	default:
		break;
	}
	return NULL;
}

#define ARG_C(n, carry) arg(insn, is_thumb, n, carry)
#define ARG(n)          ARG_C(n, NULL)

/**
 * zf := v == 0
 * nf := msb v
 */
static RzILOpEffect *update_flags_zn(RzILOpBitVector *v) {
	return SEQ2(
		SETG("zf", IS_ZERO(v)),
		SETG("nf", MSB(DUP(v))));
}

/**
 * \p f set bits [24, 31] (nzcvq)
 * \p s set bits [16: 23] (ge)
 */
static RzILOpEffect *update_flags_from_cpsr(RzILOpBitVector *val, bool f, bool s) {
	RzILOpEffect *setf = f ? SEQ5(
					 SETG("nf", INV(IS_ZERO(LOGAND(val, U32(1ul << 31))))),
					 SETG("zf", INV(IS_ZERO(LOGAND(DUP(val), U32(1ul << 30))))),
					 SETG("cf", INV(IS_ZERO(LOGAND(DUP(val), U32(1ul << 29))))),
					 SETG("vf", INV(IS_ZERO(LOGAND(DUP(val), U32(1ul << 28))))),
					 SETG("qf", INV(IS_ZERO(LOGAND(DUP(val), U32(1ul << 27))))))
			       : NULL;
	RzILOpEffect *sets = s ? SETG("gef", UNSIGNED(4, SHIFTR0(setf ? DUP(val) : val, UN(5, 16)))) : NULL;
	return setf && sets ? SEQ2(sets, setf) : (setf ? setf : sets);
}

/**
 * Capstone: ARM_INS_MOV, ARM_INS_MOVW, ARM_INS_LSL, ARM_INS_LSR, ARM_INS_ASR, ARM_INS_RRX, ARM_INS_ROR, ARM_INS_MVN
 * ARM: mov, movs, movw, lsl, lsls, lsr, lsrs, asr, asrs, rrx, rrxs, ror, rors, mvn, mvns
 */
static RzILOpEffect *mov(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0) || (!ISIMM(1) && !ISREG(1)) || OPCOUNT() < 2) {
		return NULL;
	}
	size_t base_op = 1;
	// All of lsl, lsr, etc. are really just mov/movs, but capstone encodes them differently,
	// with the shift distance as extra (third) operand. But it doesn't do that always, sometimes the shift is also still
	// embedded in the second operand.
	arm_shifter shift_alias = ARM_SFT_INVALID;
	if (insn->detail->arm.operands[base_op].shift.type == ARM_SFT_INVALID) {
		base_op = OPCOUNT() < 3 ? 0 : 1;
		switch (insn->id) {
		case ARM_INS_LSL:
			shift_alias = ARM_SFT_LSL;
			break;
		case ARM_INS_LSR:
			shift_alias = ARM_SFT_LSR;
			break;
		case ARM_INS_ASR:
			shift_alias = ARM_SFT_ASR;
			break;
		case ARM_INS_RRX:
			shift_alias = ARM_SFT_RRX;
			base_op = 1;
			break;
		case ARM_INS_ROR:
			shift_alias = ARM_SFT_ROR;
			break;
		default:
			base_op = 1;
			break;
		}
	}
	bool update_flags = insn->detail->arm.update_flags;
	RzILOpBool *carry = NULL;
	RzILOpPure *val = ARG_C(base_op, update_flags && shift_alias == ARM_SFT_INVALID ? &carry : NULL);
	if (!val) {
		return NULL;
	}
	if (shift_alias != ARM_SFT_INVALID) {
		RzILOpPure *dist = NULL;
		if (shift_alias != ARM_SFT_RRX) {
			dist = ARG(base_op + 1);
			if (!dist) {
				rz_il_op_pure_free(val);
				return NULL;
			}
		}
		val = shift(val, update_flags ? &carry : NULL, shift_alias, dist ? UNSIGNED(8, dist) : NULL);
	}
	if (insn->id == ARM_INS_MVN) {
		val = LOGNOT(val);
	}
	if (REGID(0) == ARM_REG_PC) {
		if (update_flags) {
			// ALUExceptionReturn()
			goto err;
		} else {
			return JMP(val);
		}
	}
	RzILOpEffect *eff = write_reg(REGID(0), val);
	if (!eff) {
		goto err;
	}
	if (update_flags) {
		RzILOpEffect *zn = update_flags_zn(REG(0));
		return carry
			? SEQ4(SETL("cf_tmp", carry), eff, SETG("cf", VARL("cf_tmp")), zn) // rrxs still needs the old carry
			: SEQ2(eff, zn);
	}
	return eff;
err:
	rz_il_op_pure_free(carry);
	rz_il_op_pure_free(val);
	return NULL;
}

/**
 * Capstone: ARM_INS_MOVT
 * ARM: movt
 */
static RzILOpEffect *movt(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0) || !ISIMM(1)) {
		return NULL;
	}
	RzILOpPure *regval = REG(0);
	if (!regval) {
		return NULL;
	}
	return write_reg(REGID(0), APPEND(U16(IMM(1)), UNSIGNED(16, regval)));
}

/**
 * Capstone: ARM_INS_ADR,
 *           if base is pc: ARM_INS_ADD, ARM_INS_ADDW, ARM_INS_SUB, ARM_INS_SUBW
 * ARM: adr, add pc, addw pc, sub pc, subw pc
 */
static RzILOpEffect *adr(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0)) {
		return NULL;
	}
	st32 offset;
	switch (insn->id) {
	case ARM_INS_ADR:
		offset = IMM(1);
		break;
	case ARM_INS_ADD:
	case ARM_INS_ADDW:
		offset = IMM(2);
		break;
	case ARM_INS_SUB:
	case ARM_INS_SUBW:
		offset = -IMM(2);
		break;
	default:
		return NULL;
	}
	return write_reg(REGID(0), U32(PCALIGN(insn->address, is_thumb) + offset));
}

/**
 * Capstone: ARM_INS_ADD, ARM_INS_ADDW, ARM_INS_ADC, ARM_INS_SUB, ARM_INS_SUBW, ARM_INS_RSB, ARM_INS_RSC, ARM_INS_SBC
 * ARM: add, adds, adc, adcs, sub, subs, rsb, rsbs, rsc, rscs, sbc
 */
static RzILOpEffect *add_sub(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0)) {
		return NULL;
	}
	if ((insn->id == ARM_INS_ADD || insn->id == ARM_INS_ADDW || insn->id == ARM_INS_SUB || insn->id == ARM_INS_SUBW) &&
		!insn->detail->arm.update_flags && OPCOUNT() == 3 && REGID(1) == ARM_REG_PC && ISIMM(2)) {
		// alias for adr
		return adr(insn, is_thumb);
	}
	bool is_sub =
		insn->id == ARM_INS_SUB || insn->id == ARM_INS_SUBW || insn->id == ARM_INS_RSB || insn->id == ARM_INS_RSC ||
		insn->id == ARM_INS_SBC;
	RzILOpBitVector *a = ARG(OPCOUNT() > 2 ? 1 : 0);
	RzILOpBitVector *b = ARG(OPCOUNT() > 2 ? 2 : 1);
	if (insn->id == ARM_INS_RSB || insn->id == ARM_INS_RSC) {
		RzILOpBitVector *tmp = b;
		b = a;
		a = tmp;
	}
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	RzILOpBitVector *res = is_sub ? SUB(a, b) : ADD(a, b);
	bool with_carry = false;
	if (insn->id == ARM_INS_ADC) {
		res = ADD(res, ITE(VARG("cf"), U32(1), U32(0)));
		with_carry = true;
	} else if (insn->id == ARM_INS_RSC || insn->id == ARM_INS_SBC) {
		res = SUB(res, ITE(VARG("cf"), U32(0), U32(1)));
		with_carry = true;
	}
	if (REGID(0) == ARM_REG_PC) {
		if (insn->detail->arm.update_flags) {
			// ALUExceptionReturn()
			rz_il_op_pure_free(res);
			return NULL;
		} else {
			return JMP(res);
		}
	}
	RzILOpEffect *set = write_reg(REGID(0), res);
	bool update_flags = insn->detail->arm.update_flags;
	if (!strcmp(insn->mnemonic, "adc") || !strcmp(insn->mnemonic, "rsc") || !strcmp(insn->mnemonic, "sbc") ||
		!strcmp(insn->mnemonic, "adc.w") || !strcmp(insn->mnemonic, "sbc.w")) {
		// capstone is wrong about this, only the <...>s variants set flags
		update_flags = false;
	}
	if (update_flags) {
		return SEQ6(
			SETL("a", DUP(a)),
			SETL("b", DUP(b)),
			set,
			SETG("cf", (is_sub ? sub_carry : add_carry)(VARL("a"), VARL("b"), with_carry, 32)),
			SETG("vf", (is_sub ? sub_overflow : add_overflow)(VARL("a"), VARL("b"), REG(0))),
			update_flags_zn(REG(0)));
	}
	return set;
}

/**
 * Capstone: ARM_INS_MUL
 * ARM: mul, muls
 */
static RzILOpEffect *mul(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0)) {
		return NULL;
	}
	RzILOpBitVector *a = ARG(OPCOUNT() > 2 ? 1 : 0);
	RzILOpBitVector *b = ARG(OPCOUNT() > 2 ? 2 : 1);
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	RzILOpEffect *eff = write_reg(REGID(0), MUL(a, b));
	if (!eff) {
		return NULL;
	}
	return insn->detail->arm.update_flags ? SEQ2(eff, update_flags_zn(REG(0))) : eff;
}

/**
 * Capstone: ARM_INS_LDR, ARM_INS_LDRB, ARM_INS_LDRH, ARM_INS_LDRT, ARM_INS_LDRBT, ARM_INS_LDRHT,
 *           ARM_INS_LDA, ARM_INS_LDAB, ARM_INS_LDAH, ARM_INS_LDAEX, ARM_INS_LDAEXB, ARM_INS_LDAEXH,
 *           ARM_INS_LDRD, ARM_INS_LDREX, ARM_INS_LDREXD,
 *           ARM_INS_LDRSB, ARM_INS_LDRSBT, ARM_INS_LDRSH, ARM_INS_LDRSHT
 * ARM: ldr, ldrb, ldrh, ldrt, ldrbt, ldrht, lda, ldab, ldah, ldaex, ldaexb, ldaexh, ldrd, ldrexd
 */
static RzILOpEffect *ldr(cs_insn *insn, bool is_thumb) {
	bool is_double = insn->id == ARM_INS_LDRD || insn->id == ARM_INS_LDREXD;
	size_t mem_idx = is_double ? 2 : 1;
	if (!ISREG(0) || !ISMEM(mem_idx) ||
		(is_double && (!ISREG(1) || REGID(0) == ARM_REG_PC || REGID(1) == ARM_REG_PC))) {
		return NULL;
	}
	RzILOpBitVector *addr;
	cs_arm_op *memop = &insn->detail->arm.operands[mem_idx];
	if (memop->mem.base == ARM_REG_PC) {
		// LDR (literal) is different in the sense that it aligns the pc value:
		addr = arg_mem(U32(PCALIGN(insn->address, is_thumb) + MEMDISP(mem_idx)), memop, NULL);
	} else {
		addr = ARG(mem_idx);
	}
	if (!addr) {
		return NULL;
	}
	bool writeback = ISWRITEBACK32();

	RzILOpEffect *writeback_eff = NULL;
	bool writeback_post = ISPOSTINDEX32();
	if (writeback) {
		arm_reg base = insn->detail->arm.operands[mem_idx].mem.base;
		writeback_eff = write_reg(base, addr);
		if (!writeback_eff) {
			// 'ldrb r0, [pc, 0x104]!' (0401ffe5) for example is unpredictable. write_reg will return NULL for pc.
			return NULL;
		}
		addr = MEMBASE(mem_idx);
	}
	RzILOpEffect *eff;
	if (is_double) {
		eff = SEQ2(
			write_reg(REGID(0), LOADW(32, addr)),
			write_reg(REGID(1), LOADW(32, ADD(DUP(addr), U32(4)))));
	} else {
		RzILOpBitVector *data;
		switch (insn->id) {
		case ARM_INS_LDRB:
		case ARM_INS_LDRBT:
		case ARM_INS_LDAB:
		case ARM_INS_LDAEXB:
			data = UNSIGNED(32, LOAD(addr));
			break;
		case ARM_INS_LDRH:
		case ARM_INS_LDRHT:
		case ARM_INS_LDAH:
		case ARM_INS_LDAEXH:
			data = UNSIGNED(32, LOADW(16, addr));
			break;
		case ARM_INS_LDRSB:
		case ARM_INS_LDRSBT:
			data = SIGNED(32, LOAD(addr));
			break;
		case ARM_INS_LDRSH:
		case ARM_INS_LDRSHT:
			data = SIGNED(32, LOADW(16, addr));
			break;
		default: // ARM_INS_LDR, ARM_INS_LDRT, ARM_INS_LDA, ARM_INS_LDAEX
			data = LOADW(32, addr);
			break;
		}
		if (REGID(0) == ARM_REG_PC) {
			if (writeback_post) {
				// can't have writeback after the jmp, so need to handle this special case with a local var
				return SEQ3(
					SETL("tgt", data),
					writeback_eff,
					JMP(VARL("tgt")));
			} else {
				eff = JMP(data);
			}
		} else {
			eff = write_reg(REGID(0), data);
		}
	}
	if (writeback_eff) {
		return writeback_post ? SEQ2(eff, writeback_eff) : SEQ2(writeback_eff, eff);
	}
	return eff;
}

/**
 * Capstone: ARM_INS_STR, ARM_INS_STRB, ARM_INS_STRH, ARM_INS_STRT, ARM_INS_STRBT, ARM_INS_STRHT,
 *           ARM_INS_STL, ARM_INS_STLB, ARM_INS_STLH, ARM_INS_STRD
 * ARM: str, strb, strh, strt, strbt, strht, stl, stlb, stlh, strd
 */
static RzILOpEffect *str(cs_insn *insn, bool is_thumb) {
	size_t mem_idx = insn->id == ARM_INS_STRD ? 2 : 1;
	if (!ISREG(0) || !ISMEM(mem_idx)) {
		return NULL;
	}
	RzILOpBitVector *addr = ARG(mem_idx);
	if (!addr) {
		return NULL;
	}
	bool writeback = ISWRITEBACK32();
	RzILOpEffect *writeback_eff = NULL;
	bool writeback_post = ISPOSTINDEX32();
	if (writeback) {
		arm_reg base = insn->detail->arm.operands[mem_idx].mem.base;
		writeback_eff = write_reg(base, addr);
		if (!writeback_eff) {
			return NULL;
		}
		addr = MEMBASE(mem_idx);
	}
	RzILOpBitVector *val = ARG(0);
	if (!val) {
		rz_il_op_pure_free(addr);
		return NULL;
	}
	RzILOpEffect *eff;
	switch (insn->id) {
	case ARM_INS_STRB:
	case ARM_INS_STRBT:
	case ARM_INS_STLB:
		eff = STORE(addr, UNSIGNED(8, val));
		break;
	case ARM_INS_STRH:
	case ARM_INS_STRHT:
	case ARM_INS_STLH:
		eff = STOREW(addr, UNSIGNED(16, val));
		break;
	case ARM_INS_STRD: {
		RzILOpBitVector *val2 = ARG(1);
		if (!val2) {
			rz_il_op_pure_free(val);
			rz_il_op_pure_free(addr);
			return NULL;
		}
		eff = SEQ2(
			STOREW(addr, val),
			STOREW(ADD(DUP(addr), U32(4)), val2));
		break;
	}
	default: // ARM_INS_STR, ARM_INS_STRT, ARM_INS_STL
		eff = STOREW(addr, val);
		break;
	}
	if (writeback_eff) {
		return writeback_post ? SEQ2(eff, writeback_eff) : SEQ2(writeback_eff, eff);
	}
	return eff;
}

/**
 * Capstone: ARM_INS_STREX, ARM_INS_STREXB, ARM_INS_STREXD, ARM_INS_STREXH,
 *           ARM_INS_STLEX, ARM_INS_STLEXB, ARM_INS_STLEXD, ARM_INS_STLEXH
 * ARM: strex, strexb, strexd, strexh, stlex, stlexb, stlexd, stlexh
 */
static RzILOpEffect *strex(cs_insn *insn, bool is_thumb) {
	size_t mem_idx = insn->id == ARM_INS_STREXD || insn->id == ARM_INS_STLEXD ? 3 : 2;
	if (!ISREG(0) || !ISMEM(mem_idx)) {
		return NULL;
	}
	RzILOpBitVector *addr = ARG(mem_idx);
	RzILOpBitVector *val = ARG(1);
	// always return success of exclusive access while it's not represented in IL:
	RzILOpEffect *ret_eff = write_reg(REGID(0), U32(0));
	if (!addr || !val || !ret_eff) {
	err:
		rz_il_op_pure_free(addr);
		rz_il_op_pure_free(val);
		rz_il_op_effect_free(ret_eff);
		return NULL;
	}
	RzILOpEffect *eff;
	switch (insn->id) {
	case ARM_INS_STREXB:
	case ARM_INS_STLEXB:
		eff = STORE(addr, UNSIGNED(8, val));
		break;
	case ARM_INS_STREXH:
	case ARM_INS_STLEXH:
		eff = STOREW(addr, UNSIGNED(16, val));
		break;
	case ARM_INS_STREXD:
	case ARM_INS_STLEXD: {
		RzILOpBitVector *val2 = ARG(2);
		if (!val2) {
			goto err;
		}
		eff = SEQ2(
			STOREW(addr, val),
			STOREW(ADD(DUP(addr), U32(4)), val2));
		break;
	}
	default: // ARM_INS_STREX, ARM_INS_STLEX
		eff = STOREW(addr, val);
		break;
	}
	return SEQ2(eff, ret_eff);
}

/**
 * Capstone: ARM_INS_AND, ARM_INS_ORR, ARM_INS_EOR, ARM_INS_BIC
 * ARM: and, ands, orr, orrs, orn, orns, eor, eors, bic, bics
 */
static RzILOpEffect *bitwise(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0) || OPCOUNT() < 2) {
		return NULL;
	}
	bool update_flags = insn->detail->arm.update_flags;
	RzILOpBitVector *a = ARG(OPCOUNT() - 2);
	RzILOpBool *carry = NULL;
	RzILOpBitVector *b = ARG_C(OPCOUNT() - 1, update_flags ? &carry : NULL);
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		rz_il_op_pure_free(carry);
		return NULL;
	}
	RzILOpBitVector *res;
	switch (insn->id) {
	case ARM_INS_AND:
		res = LOGAND(a, b);
		break;
	case ARM_INS_ORR:
		res = LOGOR(a, b);
		break;
	case ARM_INS_ORN:
		res = LOGOR(a, LOGNOT(b));
		break;
	case ARM_INS_EOR:
		res = LOGXOR(a, b);
		break;
	case ARM_INS_BIC:
		res = LOGAND(a, LOGNOT(b));
		break;
	default:
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		rz_il_op_pure_free(carry);
		return NULL;
	}
	if (REGID(0) == ARM_REG_PC) {
		if (insn->detail->arm.update_flags) {
			// ALUExceptionReturn()
			rz_il_op_pure_free(res);
			rz_il_op_pure_free(carry);
			return NULL;
		} else {
			return JMP(res);
		}
	}
	RzILOpEffect *eff = write_reg(REGID(0), res);
	if (update_flags) {
		if (carry) {
			return SEQ3(
				eff,
				SETG("cf", carry),
				update_flags_zn(REG(0)));
		} else {
			return SEQ2(eff, update_flags_zn(REG(0)));
		}
	}
	return eff;
}

/**
 * Capstone: ARM_INS_TST, ARM_INS_TEQ
 * ARM: tst, teq
 */
static RzILOpEffect *tst(cs_insn *insn, bool is_thumb) {
	RzILOpBitVector *a = ARG(0);
	RzILOpBool *carry = NULL;
	RzILOpBitVector *b = ARG_C(1, &carry);
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		rz_il_op_pure_free(carry);
		return NULL;
	}
	RzILOpBitVector *res = insn->id == ARM_INS_TST ? LOGAND(a, b) : LOGOR(a, b);
	if (carry) {
		return SEQ2(
			SETG("cf", carry),
			update_flags_zn(res));
	} else {
		return update_flags_zn(res);
	}
}

/**
 * Capstone: ARM_INS_UXTB, ARM_INS_UXTH, ARM_INS_UXTAB, ARM_INS_UXTAH
 *           ARM_INS_SXTB, ARM_INS_SXTH, ARM_INS_SXTAB, ARM_INS_SXTAH
 * ARM: uxtb, uxth, uxtab, uxtah, sxtb, sxth, sxtab, sxtah
 */
static RzILOpEffect *uxt(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0)) {
		return NULL;
	}
	bool is_add = insn->id == ARM_INS_UXTAB || insn->id == ARM_INS_UXTAH || insn->id == ARM_INS_SXTAB ||
		insn->id == ARM_INS_SXTAH;
	RzILOpBitVector *src = ARG(is_add ? 2 : 1);
	if (!src) {
		return NULL;
	}
	ut32 src_bits =
		insn->id == ARM_INS_UXTH || insn->id == ARM_INS_UXTAH || insn->id == ARM_INS_SXTH ||
			insn->id == ARM_INS_SXTAH
		? 16
		: 8;
	RzILOpBitVector *val = UNSIGNED(src_bits, src);
	val = insn->id == ARM_INS_SXTB || insn->id == ARM_INS_SXTH || insn->id == ARM_INS_SXTAB || insn->id == ARM_INS_SXTAH
		? SIGNED(32, val)
		: UNSIGNED(32, val);
	if (is_add) {
		RzILOpBitVector *b = ARG(1);
		if (!b) {
			rz_il_op_pure_free(val);
			return NULL;
		}
		val = ADD(b, val);
	}
	return write_reg(REGID(0), val);
}

/**
 * Capstone: ARM_INS_UXTB16, ARM_INS_UXTAB16, ARM_INS_SXTB16, ARM_INS_SXTAB16
 * ARM: uxtb16, uxtab16, stxb16, sxtab16
 */
static RzILOpEffect *uxt16(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0)) {
		return NULL;
	}
	bool is_add = insn->id == ARM_INS_UXTAB16 || insn->id == ARM_INS_SXTAB16;
	RzILOpBitVector *src = ARG(is_add ? 2 : 1);
	if (!src) {
		return NULL;
	}
	RzILOpBitVector *l = UNSIGNED(8, VARLP("x"));
	RzILOpBitVector *h = UNSIGNED(8, SHIFTR0(VARLP("x"), UN(5, 16)));
	if (insn->id == ARM_INS_SXTB16 || insn->id == ARM_INS_SXTAB16) {
		l = SIGNED(16, l);
		h = SIGNED(16, h);
	} else {
		l = UNSIGNED(16, l);
		h = UNSIGNED(16, h);
	}
	if (is_add) {
		RzILOpBitVector *b = ARG(1);
		if (!b) {
			rz_il_op_pure_free(src);
			rz_il_op_pure_free(l);
			rz_il_op_pure_free(h);
			return NULL;
		}
		l = ADD(UNSIGNED(16, b), l);
		h = ADD(UNSIGNED(16, SHIFTR0(DUP(b), UN(5, 16))), h);
	}
	return write_reg(REGID(0), LET("x", src, APPEND(h, l)));
}

/**
 * Capstone: ARM_INS_CMP, ARM_INS_CMN
 * ARM: cmp, cmn
 */
static RzILOpEffect *cmp(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0)) {
		return NULL;
	}
	bool is_sub = insn->id == ARM_INS_CMP;
	RzILOpBitVector *a = ARG(0);
	RzILOpBitVector *b = ARG(1);
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	return SEQ6(
		SETL("a", a),
		SETL("b", b),
		SETL("res", is_sub ? SUB(VARL("a"), VARL("b")) : ADD(VARL("a"), VARL("b"))),
		SETG("cf", (is_sub ? sub_carry : add_carry)(VARL("a"), VARL("b"), false, 32)),
		SETG("vf", (is_sub ? sub_overflow : add_overflow)(VARL("a"), VARL("b"), VARL("res"))),
		update_flags_zn(VARL("res")));
}

/**
 * Capstone: ARM_INS_STM, ARM_INS_STMDA, ARM_INS_STMDB, ARM_INS_PUSH, ARM_INS_STMIB,
 *           ARM_INS_VSTMIA, ARM_INS_VSTMDB, ARM_INS_VPUSH
 * ARM: stm (stmia, stmea), stmdb (stmfb), push
 */
static RzILOpEffect *stm(cs_insn *insn, bool is_thumb) {
	size_t op_first;
	arm_reg ptr_reg;
	bool writeback;
#if CS_NEXT_VERSION < 6
	if (insn->id == ARM_INS_PUSH || insn->id == ARM_INS_VPUSH) {
		op_first = 0;
		ptr_reg = ARM_REG_SP;
		writeback = true;
#else
	if (insn->alias_id == ARM_INS_ALIAS_PUSH || insn->alias_id == ARM_INS_ALIAS_VPUSH) {
		op_first = 1;
		ptr_reg = ARM_REG_SP;
		writeback = true;
	} else if (insn->id == ARM_INS_PUSH) {
		// Thumb1 PUSH instructions. Have no alias defined in the ISA.
		op_first = 0;
		ptr_reg = ARM_REG_SP;
		writeback = true;
#endif
	} else { // ARM_INS_STMDB.*
		if (!ISREG(0)) {
			return NULL;
		}
		op_first = 1;
		ptr_reg = REGID(0);
		writeback = ISWRITEBACK32();
	}
	size_t op_count = OPCOUNT() - op_first;
	if (!op_count) {
		return NOP();
	}
	RzILOpBitVector *ptr = REG_VAL(ptr_reg);
	if (!ptr) {
		return NULL;
	}
	bool decrement = insn->id == ARM_INS_PUSH || insn->id == ARM_INS_STMDA || insn->id == ARM_INS_STMDB || insn->id == ARM_INS_VSTMDB;
#if CS_NEXT_VERSION < 6
	decrement |= insn->id == ARM_INS_VPUSH;
#endif
	bool before = insn->id == ARM_INS_PUSH || insn->id == ARM_INS_STMDB || insn->id == ARM_INS_VSTMDB || insn->id == ARM_INS_STMIB;
#if CS_NEXT_VERSION < 6
	before |= insn->id == ARM_INS_VPUSH;
#endif
	ut32 regsize = reg_bits(REGID(op_first)) / 8;
	RzILOpEffect *eff = NULL;
	// build up in reverse order so the result recurses in the second arg of seq (for tail-call optimization)
	if (writeback) {
		eff = write_reg(ptr_reg,
			decrement
				? SUB(DUP(ptr), U32(op_count * regsize))
				: ADD(DUP(ptr), U32(op_count * regsize)));
	}
	for (size_t i = 0; i < op_count; i++) {
		size_t idx = op_first + (op_count - 1 - i);
		RzILOpPure *val;
		if (!ISREG(idx) || !(val = REG(idx))) {
			rz_il_op_pure_free(ptr);
			rz_il_op_effect_free(eff);
			return NULL;
		}
		RzILOpEffect *store = STOREW(
			decrement
				? SUB(DUP(ptr), U32((i + (before ? 1 : 0)) * regsize))
				: ADD(DUP(ptr), U32((op_count - i - (before ? 0 : 1)) * regsize)),
			val);
		eff = eff ? SEQ2(store, eff) : store;
	}
	rz_il_op_pure_free(ptr);
	return eff;
}

/**
 * Capstone: ARM_INS_LDM, ARM_INS_POP, ARM_INS_LDMDA, ARM_INS_LDMDB, ARM_INS_LDMIB,
 *           ARM_INS_VLDMIA, ARM_INS_VLDMDB, ARM_INS_VPOP
 * ARM: ldm (ldmia, ldmfd), pop, ldmda (ldmfa), ldmdb (ldmea), ldmib (ldmed)
 */
static RzILOpEffect *ldm(cs_insn *insn, bool is_thumb) {
	size_t op_first;
	arm_reg ptr_reg;
	bool writeback;
#if CS_NEXT_VERSION < 6
	if (insn->id == ARM_INS_POP || insn->id == ARM_INS_VPOP) {
		op_first = 0;
		ptr_reg = ARM_REG_SP;
		writeback = true;
#else
	if (insn->alias_id == ARM_INS_ALIAS_POP || insn->alias_id == ARM_INS_ALIAS_VPOP) {
		op_first = 1;
		ptr_reg = ARM_REG_SP;
		writeback = true;
	} else if (insn->id == ARM_INS_POP) {
		// Thumb1 POP instructions. Have no alias defined in the ISA.
		op_first = 0;
		ptr_reg = ARM_REG_SP;
		writeback = true;
#endif
	} else { // ARM_INS_LDM.*
		if (!ISREG(0)) {
			return NULL;
		}
		op_first = 1;
		ptr_reg = REGID(0);
		writeback = ISWRITEBACK32();
	}
	size_t op_count = OPCOUNT() - op_first;
	if (!op_count) {
		return NOP();
	}
	RzILOpBitVector *ptr_initial = REG_VAL(ptr_reg);
	if (!ptr_initial) {
		return NULL;
	}
	RzILOpEffect *eff = NULL;
	// build up in reverse order so the result recurses in the second arg of seq (for tail-call optimization)
	for (size_t i = 0; i < op_count; i++) {
		size_t idx = op_first + (op_count - 1 - i);
		if (ISREG(idx) && REGID(idx) == ARM_REG_PC) {
			// jmp goes last
			eff = JMP(VARL("tgt"));
		}
	}
	bool decrement = insn->id == ARM_INS_LDMDA || insn->id == ARM_INS_LDMDB || insn->id == ARM_INS_VLDMDB;
	bool before = insn->id == ARM_INS_LDMDB || insn->id == ARM_INS_LDMIB || insn->id == ARM_INS_VLDMIA;
#if CS_NEXT_VERSION >= 6
	before &= !(insn->alias_id == ARM_INS_ALIAS_POP || insn->alias_id == ARM_INS_ALIAS_VPOP);
#endif
	ut32 regsize = reg_bits(REGID(op_first)) / 8;
	if (writeback) {
		RzILOpEffect *wb = write_reg(ptr_reg,
			decrement
				? SUB(VARL("base"), U32(op_count * regsize))
				: ADD(VARL("base"), U32(op_count * regsize)));
		eff = eff ? SEQ2(wb, eff) : wb;
	}
	for (size_t i = 0; i < op_count; i++) {
		size_t idx = op_first + (op_count - 1 - i);
		if (!ISREG(idx)) {
			rz_il_op_pure_free(ptr_initial);
			rz_il_op_effect_free(eff);
			return NULL;
		}
		RzILOpPure *val = LOADW(regsize * 8,
			decrement
				? SUB(VARL("base"), U32((i + (before ? 1 : 0)) * regsize))
				: ADD(VARL("base"), U32((op_count - i - (before ? 0 : 1)) * regsize)));
		RzILOpEffect *load;
		if (REGID(idx) == ARM_REG_PC) {
			load = SETL("tgt", val);
		} else {
			load = write_reg(REGID(idx), val);
		}
		eff = eff ? SEQ2(load, eff) : load;
	}
	return SEQ2(SETL("base", ptr_initial), eff);
}

/**
 * Capstone: ARM_INS_BL, ARM_INS_BLX
 * ARM: bl, blx
 */
static RzILOpEffect *bl(cs_insn *insn, bool is_thumb) {
	RzILOpBitVector *tgt = ARG(0);
	if (!tgt) {
		return NULL;
	}
	return SEQ2(
		SETG("lr", U32(((insn->address + insn->size) & ~1ul) | (is_thumb ? 1 : 0))),
		JMP(tgt));
}

/**
 * Capstone: ARM_INS_CLZ
 * ARM: clz
 */
static RzILOpEffect *clz(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0)) {
		return NULL;
	}
	RzILOpBitVector *v = ARG(1);
	if (!v) {
		return NULL;
	}
	return SEQ4(
		SETL("v", v),
		SETL("i", U32(0x20)),
		REPEAT(INV(IS_ZERO(VARL("v"))),
			SEQ2(
				SETL("v", SHIFTR0(VARL("v"), UN(5, 1))),
				SETL("i", SUB(VARL("i"), U32(1))))),
		write_reg(REGID(0), VARL("i")));
}

/**
 * Capstone: ARM_INS_SVC
 * ARM: svc
 */
static RzILOpEffect *svc(cs_insn *insn, bool is_thumb) {
	return GOTO("svc");
}

static void label_svc(RzILVM *vm, RzILOpEffect *op) {
	// stub, nothing to do here
}

/**
 * Capstone: ARM_INS_HVC
 * ARM: hvc
 */
static RzILOpEffect *hvc(cs_insn *insn, bool is_thumb) {
	return GOTO("hvc");
}

static void label_hvc(RzILVM *vm, RzILOpEffect *op) {
	// stub, nothing to do here
}

/**
 * Capstone: ARM_INS_BFC
 * ARM: bfc
 */
static RzILOpEffect *bfc(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0) || !ISIMM(1) || !ISIMM(2)) {
		return NULL;
	}
	RzILOpBitVector *val = REG(0);
	if (!val) {
		return NULL;
	}
	return write_reg(REGID(0), LOGAND(val, U32(~(rz_num_bitmask(IMM(2)) << IMM(1)))));
}

/**
 * Capstone: ARM_INS_BFI
 * ARM: bfi
 */
static RzILOpEffect *bfi(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0) || !ISIMM(2) || !ISIMM(3)) {
		return NULL;
	}
	RzILOpBitVector *dval = REG(0);
	RzILOpBitVector *nval = ARG(1);
	if (!dval || !nval) {
		rz_il_op_pure_free(dval);
		rz_il_op_pure_free(nval);
		return NULL;
	}
	ut32 lsb = IMM(2);
	ut32 mask = rz_num_bitmask(IMM(3));
	return write_reg(REGID(0),
		LOGOR(
			LOGAND(dval, U32(~(mask << lsb))),
			SHIFTL0(LOGAND(nval, U32(mask)), UN(5, lsb))));
}

/**
 * Capstone: ARM_INS_CBZ, ARM_INS_CBNZ
 * ARM: cbz, cbnz
 */
static RzILOpEffect *cbz(cs_insn *insn, bool is_thumb) {
	RzILOpBitVector *val = ARG(0);
	RzILOpBitVector *dst = ARG(1);
	if (!val || !dst) {
		rz_il_op_pure_free(val);
		rz_il_op_pure_free(dst);
		return NULL;
	}
	RzILOpBool *cond = IS_ZERO(val);
	if (insn->id == ARM_INS_CBNZ) {
		cond = INV(cond);
	}
	return BRANCH(cond, JMP(dst), NULL);
}

/**
 * Capstone: ARM_INS_MLA, ARM_INS_MLS
 * ARM: mla, mlas, mls
 */
static RzILOpEffect *mla(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0)) {
		return NULL;
	}
	RzILOpBitVector *op0 = ARG(1);
	RzILOpBitVector *op1 = ARG(2);
	RzILOpBitVector *addend = ARG(3);
	if (!op0 || !op1 || !addend) {
		rz_il_op_pure_free(op0);
		rz_il_op_pure_free(op1);
		rz_il_op_pure_free(addend);
		return NULL;
	}
	RzILOpBitVector *val = insn->id == ARM_INS_MLS
		? SUB(addend, MUL(op0, op1))
		: ADD(MUL(op0, op1), addend);
	RzILOpEffect *eff = write_reg(REGID(0), val);
	if (!eff) {
		return NULL;
	}
	return insn->detail->arm.update_flags
		? SEQ2(eff, update_flags_zn(REG(0)))
		: eff;
}

/**
 * Capstone: ARM_INS_MRS
 * ARM: mrs
 */
static RzILOpEffect *mrs(cs_insn *insn, bool is_thumb) {
#if CS_NEXT_VERSION >= 6
	if (!ISREG(0) || !(ISREG(1) || ISPSRFLAGS(1))) {
		return NULL;
	}
	if (REGID(1) != ARM_REG_CPSR && REGID(1) != ARM_REG_SPSR && REGID(1) != ARM_REG_APSR && !ISPSRFLAGS(1)) {
		// only these regs supported
		return NULL;
	}
#else
	if (!ISREG(0) || !(ISREG(1))) {
		return NULL;
	}
	if (REGID(1) != ARM_REG_CPSR && REGID(1) != ARM_REG_SPSR && REGID(1) != ARM_REG_APSR) {
		// only these regs supported
		return NULL;
	}
#endif
	// There are more bits in ARM, but this is all we have:
	return write_reg(REGID(0),
		LOGOR(ITE(VARG("nf"), U32(1ul << 31), U32(0)),
			LOGOR(ITE(VARG("zf"), U32(1ul << 30), U32(0)),
				LOGOR(ITE(VARG("cf"), U32(1ul << 29), U32(0)),
					LOGOR(ITE(VARG("vf"), U32(1ul << 28), U32(0)),
						LOGOR(ITE(VARG("qf"), U32(1ul << 27), U32(0)),
							SHIFTL0(UNSIGNED(32, VARG("gef")), UN(5, 16))))))));
}

/**
 * Capstone: ARM_INS_MSR
 * ARM: msr
 */
static RzILOpEffect *msr(cs_insn *insn, bool is_thumb) {
	cs_arm_op *dst = &insn->detail->arm.operands[0];
#if CS_NEXT_VERSION >= 6
	if ((dst->type != ARM_OP_SYSREG) && (dst->type != ARM_OP_CPSR) && (dst->type != ARM_OP_SPSR)) {
		return NULL;
	}
	// check if the reg+mask contains any of the flags we have:
	bool update_f = false;
	bool update_s = false;
	switch (dst->reg) {
	case ARM_MCLASSSYSREG_APSR_NZCVQ:
		update_f = true;
		break;
	case ARM_MCLASSSYSREG_APSR_G:
		update_s = true;
		break;
	case ARM_MCLASSSYSREG_APSR_NZCVQG:
		update_f = true;
		update_s = true;
		break;
	default:
		update_f = (dst->sysop.psr_bits & ARM_FIELD_CPSR_F) || (dst->sysop.psr_bits & ARM_FIELD_SPSR_F);
		update_s = (dst->sysop.psr_bits & ARM_FIELD_CPSR_S) || (dst->sysop.psr_bits & ARM_FIELD_SPSR_S);
		break;
	}
#else
	if (dst->type != ARM_OP_SYSREG) {
		return NULL;
	}
	// check if the reg+mask contains any of the flags we have:
	bool update_f = false;
	bool update_s = false;
	switch (dst->reg) {
	case ARM_SYSREG_APSR_NZCVQ:
		update_f = true;
		break;
	case ARM_SYSREG_APSR_G:
		update_s = true;
		break;
	case ARM_SYSREG_APSR_NZCVQG:
		update_f = true;
		update_s = true;
		break;
	default:
		update_f = (dst->reg & ARM_SYSREG_CPSR_F) || (dst->reg & ARM_SYSREG_SPSR_F);
		update_s = (dst->reg & ARM_SYSREG_CPSR_S) || (dst->reg & ARM_SYSREG_SPSR_S);
		break;
	}
#endif
	if (!update_f && !update_s) {
		// no flags we know
		return NULL;
	}
	RzILOpBitVector *val = ARG(1);
	if (!val) {
		return NULL;
	}
	return update_flags_from_cpsr(val, update_f, update_s);
}

/**
 * Capstone: ARM_INS_PKHBT, ARM_INS_PKHTB
 * ARM: pkhbt, pkhtb
 */
static RzILOpEffect *pkhbt(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0)) {
		return NULL;
	}
	RzILOpBitVector *hv = ARG(1);
	RzILOpBitVector *lv = ARG(2);
	if (!hv || !lv) {
		rz_il_op_pure_free(hv);
		rz_il_op_pure_free(lv);
		return NULL;
	}
	hv = UNSIGNED(16, SHIFTR0(hv, UN(5, 16)));
	lv = UNSIGNED(16, lv);
	bool tbform = insn->id == ARM_INS_PKHTB;
	return write_reg(REGID(0), tbform ? APPEND(hv, lv) : APPEND(lv, hv));
}

/**
 * Saturate the signed value \p val into the local variable \p dst
 * \p bits how many bits the result should have
 * \p val value to saturate, of \p ext_bits bits
 * \p set_q whether to set the q flag on saturation
 * \p min minimal value of the range to saturate into
 * \p min maximal value of the range to saturate into
 */
static RzILOpEffect *
saturate_signed_to_range(const char *dst, ut32 bits, RzILOpBitVector *val, ut32 ext_bits, bool set_q, st64 min,
	st64 max) {
	return SEQ2(
		SETL("er", val),
		BRANCH(SGT(VARL("er"), SN(ext_bits, max)),
			set_q ? SEQ2(SETL(dst, SN(bits, max)), SETG("qf", IL_TRUE)) : SETL(dst, SN(bits, max)),
			BRANCH(SLT(VARL("er"), SN(ext_bits, min)),
				set_q ? SEQ2(SETL(dst, SN(bits, min)), SETG("qf", IL_TRUE)) : SETL(dst, SN(bits, min)),
				SETL(dst, UNSIGNED(bits, VARL("er"))))));
}

static RzILOpEffect *
saturate_signed(bool to_signed, const char *dst, ut32 bits, RzILOpBitVector *val, ut32 ext_bits, bool set_q) {
	st64 max = to_signed ? (1ull << (bits - 1)) - 1 : (1ull << bits) - 1;
	st64 min = to_signed ? -max - 1 : 0;
	return saturate_signed_to_range(dst, bits, val, ext_bits, set_q, min, max);
}

/**
 * Saturate the unsigned value \p val into the local variable \p dst
 * \p is_sub whether the value came from addition or subtraction, to differenciate between underflow and overflow
 * \p bits how many bits the result should have
 * \p val value to saturate, of \p ext_bits bits
 * \p set_q whether to set the q flag on saturation
 */
static RzILOpEffect *
saturate_unsigned(bool is_sub, const char *dst, ut32 bits, RzILOpBitVector *val, ut32 ext_bits, bool set_q) {
	ut64 max = (1ull << bits) - 1;
	ut64 min = 0;
	return SEQ2(
		SETL("er", val),
		BRANCH(UGT(VARL("er"), UN(ext_bits, max)),
			set_q ? SEQ2(SETL(dst, UN(bits, max)), SETG("qf", IL_TRUE)) : SETL(dst, UN(bits, is_sub ? min : max)),
			SETL(dst, UNSIGNED(bits, VARL("er")))));
}

static RzILOpEffect *
saturate(bool sign, bool is_sub, const char *dst, ut32 bits, RzILOpBitVector *val, ut32 ext_bits, bool set_q) {
	return sign
		? saturate_signed(true, dst, bits, val, ext_bits, set_q)
		: saturate_unsigned(is_sub, dst, bits, val, ext_bits, set_q);
}

/**
 * Capstone: ARM_INS_SSAT, ARM_INS_USAT
 * ARM: ssat
 */
static RzILOpEffect *ssat(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0) || !ISIMM(1)) {
		return NULL;
	}
	RzILOpPure *src = ARG(2);
	bool is_signed = insn->id == ARM_INS_SSAT;
	RzILOpEffect *eff = write_reg(REGID(0), is_signed ? SIGNED(32, VARL("r")) : UNSIGNED(32, VARL("r")));
	if (!src || !eff) {
		rz_il_op_pure_free(src);
		rz_il_op_effect_free(eff);
		return NULL;
	}
	return SEQ2(
		saturate_signed(is_signed, "r", IMM(1), src, 32, true),
		eff);
}

/**
 * Capstone: ARM_INS_SSAT16, ARM_INS_USAT16
 * ARM: ssat16
 */
static RzILOpEffect *ssat16(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0) || !ISIMM(1)) {
		return NULL;
	}
	RzILOpPure *src = ARG(2);
	bool is_signed = insn->id == ARM_INS_SSAT16;
	RzILOpEffect *eff = write_reg(REGID(0),
		APPEND(
			is_signed ? SIGNED(16, VARL("rh")) : UNSIGNED(16, VARL("rh")),
			is_signed ? SIGNED(16, VARL("rl")) : UNSIGNED(16, VARL("rl"))));
	if (!src || !eff) {
		rz_il_op_pure_free(src);
		rz_il_op_effect_free(eff);
		return NULL;
	}
	return SEQ3(
		saturate_signed(is_signed, "rl", IMM(1), UNSIGNED(16, src), 16, true),
		saturate_signed(is_signed, "rh", IMM(1), UNSIGNED(16, SHIFTR0(DUP(src), UN(5, 16))), 16, true),
		eff);
}

/**
 * Capstone: ARM_INS_QADD, ARM_INS_QSUB, ARM_INS_QDADD, ARM_INS_QDSUB
 * ARM: qadd, qsub, qdadd, qdsub
 */
static RzILOpEffect *qadd(cs_insn *insn, bool is_thumb) {
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
	RzILOpEffect *eff = write_reg(REGID(0), VARL("r"));
	if (!eff) {
		return NULL;
	}
	RzILOpEffect *dbl = NULL;
	if (insn->id == ARM_INS_QDADD || insn->id == ARM_INS_QDSUB) {
		b = SIGNED(33, b);
		dbl = saturate_signed(true, "dbl", 32, ADD(b, DUP(b)), 33, true);
		b = VARL("dbl");
	}
	eff = SEQ2(
		saturate_signed(true, "r", 32,
			(insn->id == ARM_INS_QSUB || insn->id == ARM_INS_QDSUB)
				? SUB(SIGNED(33, a), SIGNED(33, b))
				: ADD(SIGNED(33, a), SIGNED(33, b)),
			33, true),
		eff);
	return dbl ? SEQ2(dbl, eff) : eff;
}

/**
 * Capstone: ARM_INS_QADD16, ARM_INS_QSUB16, ARM_INS_QASX, ARM_INS_QSAX,
 *           ARM_INS_UQADD16, ARM_INS_UQSUB16, ARM_INS_UQASX, ARM_INS_UQSAX
 * ARM: qadd16, qsub16, qasx, qsax, uqadd16, uqasx, uqsax
 */
static RzILOpEffect *qadd16(cs_insn *insn, bool is_thumb) {
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
	RzILOpEffect *eff = write_reg(REGID(0), APPEND(VARL("rh"), VARL("rl")));
	if (!eff) {
		return NULL;
	}
	bool is_signed = insn->id == ARM_INS_QADD16 || insn->id == ARM_INS_QSUB16 || insn->id == ARM_INS_QASX ||
		insn->id == ARM_INS_QSAX;
	RzILOpBitVector *(*cast)(ut32 length, RzILOpBitVector *val) = is_signed ? rz_il_op_new_signed : rz_il_op_new_unsigned;
	RzILOpBitVector *al = cast(17, UNSIGNED(16, a));
	RzILOpBitVector *ah = cast(17, UNSIGNED(16, SHIFTR0(DUP(a), UN(5, 16))));
	RzILOpBitVector *bl = cast(17, UNSIGNED(16, b));
	RzILOpBitVector *bh = cast(17, UNSIGNED(16, SHIFTR0(DUP(b), UN(5, 16))));
	bool l_sub, h_sub;
	RzILOpBitVector *l, *h;
	switch (insn->id) {
	case ARM_INS_QSUB16:
	case ARM_INS_UQSUB16:
		l_sub = true;
		h_sub = true;
		l = SUB(al, bl);
		h = SUB(ah, bh);
		break;
	case ARM_INS_QASX:
	case ARM_INS_UQASX:
		l_sub = true;
		h_sub = false;
		l = SUB(al, bh);
		h = ADD(ah, bl);
		break;
	case ARM_INS_QSAX:
	case ARM_INS_UQSAX:
		l_sub = false;
		h_sub = true;
		l = ADD(al, bh);
		h = SUB(ah, bl);
		break;
	default: // ARM_INS_QADD16, ARM_INS_UQADD16
		l_sub = false;
		h_sub = false;
		l = ADD(al, bl);
		h = ADD(ah, bh);
		break;
	}
	return SEQ3(saturate(is_signed, l_sub, "rl", 16, l, 17, false), saturate(is_signed, h_sub, "rh", 16, h, 17, false),
		eff);
}

/**
 * Capstone: ARM_INS_QADD8, ARM_INS_QSUB8, ARM_INS_UQADD8, ARM_INS_UQSUB8
 * ARM: qadd8, qsub8, uqadd8, uqsub8
 */
static RzILOpEffect *qadd8(cs_insn *insn, bool is_thumb) {
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
	RzILOpEffect *eff = write_reg(REGID(0), APPEND(APPEND(VARL("rb3"), VARL("rb2")), APPEND(VARL("rb1"), VARL("rb0"))));
	if (!eff) {
		return NULL;
	}
	bool is_signed = insn->id == ARM_INS_QADD8 || insn->id == ARM_INS_QSUB8;
	bool is_sub = insn->id == ARM_INS_QSUB8 || insn->id == ARM_INS_UQSUB8;
	RzILOpBitVector *(*cast)(ut32 length, RzILOpBitVector *val) = is_signed ? rz_il_op_new_signed : rz_il_op_new_unsigned;
	return SEQ5(
		saturate(is_signed, is_sub, "rb0", 8,
			is_sub
				? SUB(cast(9, UNSIGNED(8, a)), cast(9, UNSIGNED(8, b)))
				: ADD(cast(9, UNSIGNED(8, a)), cast(9, UNSIGNED(8, b))),
			9, false),
		saturate(is_signed, is_sub, "rb1", 8,
			is_sub
				? SUB(cast(9, UNSIGNED(8, SHIFTR0(DUP(a), UN(5, 8)))),
					  cast(9, UNSIGNED(8, SHIFTR0(DUP(b), UN(5, 8)))))
				: ADD(cast(9, UNSIGNED(8, SHIFTR0(DUP(a), UN(5, 8)))),
					  cast(9, UNSIGNED(8, SHIFTR0(DUP(b), UN(5, 8))))),
			9, false),
		saturate(is_signed, is_sub, "rb2", 8,
			is_sub
				? SUB(cast(9, UNSIGNED(8, SHIFTR0(DUP(a), UN(5, 16)))),
					  cast(9, UNSIGNED(8, SHIFTR0(DUP(b), UN(5, 16)))))
				: ADD(cast(9, UNSIGNED(8, SHIFTR0(DUP(a), UN(5, 16)))),
					  cast(9, UNSIGNED(8, SHIFTR0(DUP(b), UN(5, 16))))),
			9, false),
		saturate(is_signed, is_sub, "rb3", 8,
			is_sub
				? SUB(cast(9, UNSIGNED(8, SHIFTR0(DUP(a), UN(5, 24)))),
					  cast(9, UNSIGNED(8, SHIFTR0(DUP(b), UN(5, 24)))))
				: ADD(cast(9, UNSIGNED(8, SHIFTR0(DUP(a), UN(5, 24)))),
					  cast(9, UNSIGNED(8, SHIFTR0(DUP(b), UN(5, 24))))),
			9, false),
		eff);
}

/**
 * Capstone: ARM_INS_RBIT
 * ARM: rbit
 */
static RzILOpEffect *rbit(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0)) {
		return NULL;
	}
	RzILOpBitVector *v = ARG(1);
	if (!v) {
		return NULL;
	}
	RzILOpEffect *eff = write_reg(REGID(0), VARL("r"));
	if (!eff) {
		return NULL;
	}
	return SEQ5(
		SETL("v", v),
		SETL("i", U32(0x20)),
		SETL("r", U32(0x0)),
		REPEAT(INV(IS_ZERO(VARL("v"))),
			SEQ3(
				SETL("i", SUB(VARL("i"), U32(1))),
				SETL("r", LOGOR(VARL("r"), ITE(LSB(VARL("v")), SHIFTL0(U32(1), VARL("i")), U32(0)))),
				SETL("v", SHIFTR0(VARL("v"), UN(5, 1))))),
		eff);
}

/**
 * Capstone: ARM_INS_REV, ARM_INS_REV16
 * ARM: rev, rev16
 */
static RzILOpEffect *rev(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0)) {
		return NULL;
	}
	RzILOpBitVector *v = ARG(1);
	if (!v) {
		return NULL;
	}
	RzILOpBitVector *l = APPEND(UNSIGNED(8, v), UNSIGNED(8, SHIFTR0(DUP(v), UN(5, 8))));
	RzILOpBitVector *h = APPEND(UNSIGNED(8, SHIFTR0(DUP(v), UN(5, 16))), UNSIGNED(8, SHIFTR0(DUP(v), UN(5, 24))));
	return write_reg(REGID(0),
		insn->id == ARM_INS_REV
			? APPEND(l, h)
			: APPEND(h, l));
}

/**
 * Capstone: ARM_INS_REVSH
 * ARM: revsh
 */
static RzILOpEffect *revsh(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0)) {
		return NULL;
	}
	RzILOpBitVector *v = ARG(1);
	if (!v) {
		return NULL;
	}
	return write_reg(REGID(0),
		LET("r", APPEND(UNSIGNED(8, v), UNSIGNED(8, SHIFTR0(DUP(v), UN(5, 8)))), SIGNED(32, VARLP("r"))));
}

/**
 * Capstone: ARM_INS_RFEDA, ARM_INS_RFEDB, ARM_INS_RFEIA, ARM_INS_RFEIB
 * ARM: rfeda, rfedb, rfaia, rfeib
 */
static RzILOpEffect *rfe(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0)) {
		return NULL;
	}
	RzILOpBitVector *base = REG(0);
	if (!base) {
		return NULL;
	}
	RzILOpEffect *wb = NULL;
	bool wordhigher = insn->id == ARM_INS_RFEDA || insn->id == ARM_INS_RFEIB;
	bool increment = insn->id == ARM_INS_RFEIA || insn->id == ARM_INS_RFEIB;
	if (ISWRITEBACK32()) {
		wb = write_reg(REGID(0),
			increment ? ADD(DUP(base), U32(8)) : SUB(DUP(base), U32(8)));
		if (!wb) {
			rz_il_op_pure_free(base);
			return NULL;
		}
	}
	RzILOpBitVector *addr = increment ? base : SUB(base, U32(8));
	if (wordhigher) {
		addr = ADD(addr, U32(4));
	}
	return SEQ5(
		SETL("addr", addr),
		SETL("tgt", LOADW(32, VARL("addr"))),
		SETL("spsr", LOADW(32, ADD(VARL("addr"), U32(4)))),
		update_flags_from_cpsr(VARL("spsr"), true, true),
		wb ? SEQ2(wb, JMP(VARL("tgt"))) : JMP(VARL("tgt")));
}

/**
 * Capstone: ARM_INS_SADD16, ARM_INS_SHADD16, ARM_INS_SASX, ARM_INS_SSAX, ARM_INS_SHASX, ARM_INS_SHSAX,
 *           ARM_INS_SSUB16, ARM_INS_SHSUB16
 *           ARM_INS_UADD16, ARM_INS_UHADD16, ARM_INS_UASX, ARM_INS_USAX, ARM_INS_UHASX, ARM_INS_UHSAX,
 *           ARM_INS_USUB16, ARM_INS_UHSUB16
 * ARM: sadd16, shadd16, sasx, ssax, shasx, shsax, ssub16, shsub16
 *      uadd16, uhadd16, uasx, usax, uhasx, uhsax, usub16, uhsub16
 */
static RzILOpEffect *sadd16(cs_insn *insn, bool is_thumb) {
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
	RzILOpBitVector *al = UNSIGNED(16, a);
	RzILOpBitVector *ah = UNSIGNED(16, SHIFTR0(DUP(a), UN(5, 16)));
	RzILOpBitVector *bl = UNSIGNED(16, b);
	RzILOpBitVector *bh = UNSIGNED(16, SHIFTR0(DUP(b), UN(5, 16)));
	bool is_signed = insn->id == ARM_INS_SADD16 || insn->id == ARM_INS_SHADD16 || insn->id == ARM_INS_SASX ||
		insn->id == ARM_INS_SSAX || insn->id == ARM_INS_SHASX || insn->id == ARM_INS_SHSAX ||
		insn->id == ARM_INS_SSUB16 || insn->id == ARM_INS_SHSUB16;
	RzILOpBitVector *(*cast)(ut32 length, RzILOpBitVector *val) = is_signed ? rz_il_op_new_signed : rz_il_op_new_unsigned;
	al = cast(17, al);
	ah = cast(17, ah);
	bl = cast(17, bl);
	bh = cast(17, bh);
	RzILOpBitVector *l, *h;
	bool halve = false;
	switch (insn->id) {
	case ARM_INS_SHSAX:
	case ARM_INS_UHSAX:
		halve = true;
		// fallthrough
	case ARM_INS_SASX:
	case ARM_INS_UASX:
		l = SUB(al, bh);
		h = ADD(ah, bl);
		break;

	case ARM_INS_SHASX:
	case ARM_INS_UHASX:
		halve = true;
		// fallthrough
	case ARM_INS_SSAX:
	case ARM_INS_USAX:
		l = ADD(al, bh);
		h = SUB(ah, bl);
		break;

	case ARM_INS_SHSUB16:
	case ARM_INS_UHSUB16:
		halve = true;
		// fallthrough
	case ARM_INS_SSUB16:
	case ARM_INS_USUB16:
		l = SUB(al, bl);
		h = SUB(ah, bh);
		break;

	case ARM_INS_SHADD16:
	case ARM_INS_UHADD16:
		halve = true;
		// fallthrough
	default: // ARM_INS_SADD16, ARM_INS_SHADD16, ARM_INS_UADD16, ARM_INS_UHADD16
		l = ADD(al, bl);
		h = ADD(ah, bh);
		break;
	}
	bool set_ge = !halve;
	RzILOpBitVector *res = halve
		? APPEND(UNSIGNED(16, SHIFTRA(VARL("res1"), UN(4, 1))),
			  UNSIGNED(16, SHIFTRA(VARL("res0"), UN(4, 1))))
		: APPEND(UNSIGNED(16, VARL("res1")), UNSIGNED(16, VARL("res0")));
	RzILOpEffect *eff = write_reg(REGID(0), res);
	if (!eff) {
		rz_il_op_pure_free(l);
		rz_il_op_pure_free(h);
		return NULL;
	}
	if (set_ge) {
		ut64 tval = is_signed ? 0 : 3;
		ut64 fval = 3 - tval;
		eff = SEQ2(
			SETL("gef",
				APPEND(
					ITE(MSB(VARL("res1")), UN(2, tval), UN(2, fval)),
					ITE(MSB(VARL("res0")), UN(2, tval), UN(2, fval)))),
			eff);
	}
	return SEQ3(SETL("res0", l), SETL("res1", h), eff);
}

/**
 * Capstone: ARM_INS_SADD8, ARM_INS_SHADD8, ARM_INS_SSUB8, ARM_INS_SHSUB8
 *           ARM_INS_UADD8, ARM_INS_UHADD8, ARM_INS_USUB8, ARM_INS_UHSUB8
 * ARM: sadd8, shadd8, ssub8, shsub8, uadd8, uhadd8, usub8, uhsub8
 */
static RzILOpEffect *sadd8(cs_insn *insn, bool is_thumb) {
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
	RzILOpBitVector *a0 = UNSIGNED(8, a);
	RzILOpBitVector *a1 = UNSIGNED(8, SHIFTR0(DUP(a), UN(5, 8)));
	RzILOpBitVector *a2 = UNSIGNED(8, SHIFTR0(DUP(a), UN(5, 16)));
	RzILOpBitVector *a3 = UNSIGNED(8, SHIFTR0(DUP(a), UN(5, 24)));
	RzILOpBitVector *b0 = UNSIGNED(8, b);
	RzILOpBitVector *b1 = UNSIGNED(8, SHIFTR0(DUP(b), UN(5, 8)));
	RzILOpBitVector *b2 = UNSIGNED(8, SHIFTR0(DUP(b), UN(5, 16)));
	RzILOpBitVector *b3 = UNSIGNED(8, SHIFTR0(DUP(b), UN(5, 24)));
	RzILOpBitVector *r0, *r1, *r2, *r3;
	bool halve = false;
	switch (insn->id) {
	case ARM_INS_SHSUB8:
	case ARM_INS_UHSUB8:
		halve = true;
		// fallthrough
	case ARM_INS_SSUB8:
	case ARM_INS_USUB8:
		r0 = SUB(a0, b0);
		r1 = SUB(a1, b1);
		r2 = SUB(a2, b2);
		r3 = SUB(a3, b3);
		break;

	case ARM_INS_SHADD8:
	case ARM_INS_UHADD8:
		halve = true;
		// fallthrough
	default: // ARM_INS_SADD8, ARM_INS_UADD8
		r0 = ADD(a0, b0);
		r1 = ADD(a1, b1);
		r2 = ADD(a2, b2);
		r3 = ADD(a3, b3);
		break;
	}
	bool set_ge = !halve;
	bool is_signed = insn->id == ARM_INS_SADD8 || insn->id == ARM_INS_SHADD8 || insn->id == ARM_INS_SSUB8 ||
		insn->id == ARM_INS_SHSUB8;
	if (set_ge) {
		// Retroactively patch the ops to extend to 8 before the calculation because this is needed for ge
		// Note: add/sub members here use the same structure, so using just `.add` is fine.
		RzILOpBitVector *(*cast)(ut32 length, RzILOpBitVector *val) = is_signed ? rz_il_op_new_signed : rz_il_op_new_unsigned;
		r0->op.add.x = cast(9, r0->op.add.x);
		r0->op.add.y = cast(9, r0->op.add.y);
		r1->op.add.x = cast(9, r1->op.add.x);
		r1->op.add.y = cast(9, r1->op.add.y);
		r2->op.add.x = cast(9, r2->op.add.x);
		r2->op.add.y = cast(9, r2->op.add.y);
		r3->op.add.x = cast(9, r3->op.add.x);
		r3->op.add.y = cast(9, r3->op.add.y);
	}
	RzILOpBitVector *res;
	if (halve) {
		res = APPEND(
			APPEND(
				SHIFTRA(VARL("res3"), UN(3, 1)),
				SHIFTRA(VARL("res2"), UN(3, 1))),
			APPEND(
				SHIFTRA(VARL("res1"), UN(3, 1)),
				SHIFTRA(VARL("res0"), UN(3, 1))));
	} else {
		res = APPEND(
			APPEND(
				UNSIGNED(8, VARL("res3")),
				UNSIGNED(8, VARL("res2"))),
			APPEND(
				UNSIGNED(8, VARL("res1")),
				UNSIGNED(8, VARL("res0"))));
	}
	RzILOpEffect *eff = write_reg(REGID(0), res);
	if (!eff) {
		rz_il_op_pure_free(r0);
		rz_il_op_pure_free(r1);
		rz_il_op_pure_free(r2);
		rz_il_op_pure_free(r3);
		return NULL;
	}
	if (set_ge) {
		ut64 tval = is_signed ? 0 : 1;
		ut64 fval = 1 - tval;
		eff = SEQ2(
			SETL("gef",
				APPEND(
					APPEND(
						ITE(MSB(VARL("res3")), UN(1, tval), UN(1, fval)),
						ITE(MSB(VARL("res2")), UN(1, tval), UN(1, fval))),
					APPEND(
						ITE(MSB(VARL("res1")), UN(1, tval), UN(1, fval)),
						ITE(MSB(VARL("res0")), UN(1, tval), UN(1, fval))))),
			eff);
	}
	return SEQ5(
		SETL("res0", r0),
		SETL("res1", r1),
		SETL("res2", r2),
		SETL("res3", r3),
		eff);
}

/**
 * Capstone: ARM_INS_SEL
 * ARM: sel
 */
static RzILOpEffect *sel(cs_insn *insn, bool is_thumb) {
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
	return write_reg(REGID(0),
		APPEND(
			APPEND(
				UNSIGNED(8, SHIFTR0(ITE(IS_ZERO(LOGAND(VARG("gef"), UN(4, 1 << 3))), b, a), UN(5, 24))),
				UNSIGNED(8,
					SHIFTR0(ITE(IS_ZERO(LOGAND(VARG("gef"), UN(4, 1 << 2))), DUP(b), DUP(a)),
						UN(5, 16)))),
			APPEND(
				UNSIGNED(8,
					SHIFTR0(ITE(IS_ZERO(LOGAND(VARG("gef"), UN(4, 1 << 1))), DUP(b), DUP(a)),
						UN(5, 8))),
				UNSIGNED(8, ITE(IS_ZERO(LOGAND(VARG("gef"), UN(4, 1))), DUP(b), DUP(a))))));
}

/**
 * Capstone: ARM_INS_SBFX, ARM_INS_UBFX
 * ARM: sbfx, ubfx
 */
static RzILOpEffect *sbfx(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0) || !ISIMM(2) || !ISIMM(3)) {
		return NULL;
	}
	RzILOpBitVector *val = REG(1);
	if (!val) {
		return NULL;
	}
	val = UNSIGNED(IMM(3), SHIFTR0(val, UN(5, IMM(2))));
	val = insn->id == ARM_INS_SBFX ? SIGNED(32, val) : UNSIGNED(32, val);
	return write_reg(REGID(0), val);
}

/**
 * Capstone: ARM_INS_SDIV
 * ARM: sdiv
 */
static RzILOpEffect *sdiv(cs_insn *insn, bool is_thumb) {
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
	return write_reg(REGID(0),
		ITE(EQ(b, U32(0)), U32(0),
			ITE(AND(EQ(a, U32(0x80000000)), EQ(DUP(b), U32(0xffffffff))),
				U32(0x80000000),
				SDIV(DUP(a), DUP(b)))));
}

/**
 * Capstone: ARM_INS_UDIV
 * ARM: udiv
 */
static RzILOpEffect *udiv(cs_insn *insn, bool is_thumb) {
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
	return write_reg(REGID(0),
		ITE(EQ(b, U32(0)), U32(0),
			DIV(a, DUP(b))));
}

/**
 * Capstone: ARM_INS_UMAAL
 * ARM: umaal
 */
static RzILOpEffect *umaal(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0) || !ISREG(1)) {
		return NULL;
	}
	RzILOpBitVector *dl = ARG(0);
	RzILOpBitVector *dh = ARG(1);
	RzILOpBitVector *a = ARG(2);
	RzILOpBitVector *b = ARG(3);
	RzILOpEffect *wl = write_reg(REGID(0), UNSIGNED(32, VARL("res")));
	RzILOpEffect *wh = write_reg(REGID(1), UNSIGNED(32, SHIFTR0(VARL("res"), UN(6, 32))));
	if (!dl || !dh || !a || !b || !wl || !wh) {
		rz_il_op_pure_free(dl);
		rz_il_op_pure_free(dh);
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		rz_il_op_effect_free(wl);
		rz_il_op_effect_free(wh);
		return NULL;
	}
	return SEQ3(
		SETL("res", ADD(ADD(MUL(UNSIGNED(64, a), UNSIGNED(64, b)), UNSIGNED(64, dl)), UNSIGNED(64, dh))),
		wl, wh);
}

/**
 * Capstone: ARM_INS_UMULL
 * ARM: umull
 */
static RzILOpEffect *umull(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0) || !ISREG(1)) {
		return NULL;
	}
	RzILOpBitVector *a = ARG(2);
	RzILOpBitVector *b = ARG(3);
	RzILOpEffect *wl = write_reg(REGID(0), UNSIGNED(32, VARL("res")));
	RzILOpEffect *wh = write_reg(REGID(1), UNSIGNED(32, SHIFTR0(VARL("res"), UN(6, 32))));
	if (!a || !b || !wl || !wh) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		rz_il_op_effect_free(wl);
		rz_il_op_effect_free(wh);
		return NULL;
	}
	if (insn->detail->arm.update_flags) {
		return SEQ4(
			SETL("res", MUL(UNSIGNED(64, a), UNSIGNED(64, b))),
			wl, wh, update_flags_zn(VARL("res")));
	} else {
		return SEQ3(SETL("res", MUL(UNSIGNED(64, a), UNSIGNED(64, b))), wl, wh);
	}
}

static RzILOpBitVector *absdiff(RzILOpBitVector *a, RzILOpBitVector *b) {
	return LET("a", a,
		LET("b", b, ITE(ULE(VARLP("a"), VARLP("b")), SUB(VARLP("b"), VARLP("a")), SUB(VARLP("a"), VARLP("b")))));
}

/**
 * Capstone: ARM_INS_USAD8, ARM_INS_USADA8
 * ARM: usad8, usada8
 */
static RzILOpEffect *usad8(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0)) {
		return NULL;
	}
	bool have_acc = insn->id == ARM_INS_USADA8;
	RzILOpBitVector *a = ARG(1);
	RzILOpBitVector *b = ARG(2);
	RzILOpBitVector *acc = have_acc ? ARG(3) : NULL;
	if (!a || !b || (have_acc && !acc)) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	RzILOpBitVector *a0 = UNSIGNED(32, UNSIGNED(8, a));
	RzILOpBitVector *a1 = UNSIGNED(32, UNSIGNED(8, SHIFTR0(DUP(a), UN(5, 8))));
	RzILOpBitVector *a2 = UNSIGNED(32, UNSIGNED(8, SHIFTR0(DUP(a), UN(5, 16))));
	RzILOpBitVector *a3 = UNSIGNED(32, UNSIGNED(8, SHIFTR0(DUP(a), UN(5, 24))));
	RzILOpBitVector *b0 = UNSIGNED(32, UNSIGNED(8, b));
	RzILOpBitVector *b1 = UNSIGNED(32, UNSIGNED(8, SHIFTR0(DUP(b), UN(5, 8))));
	RzILOpBitVector *b2 = UNSIGNED(32, UNSIGNED(8, SHIFTR0(DUP(b), UN(5, 16))));
	RzILOpBitVector *b3 = UNSIGNED(32, UNSIGNED(8, SHIFTR0(DUP(b), UN(5, 24))));
	RzILOpBitVector *sum = ADD(absdiff(a0, b0), ADD(absdiff(a1, b1), ADD(absdiff(a2, b2), absdiff(a3, b3))));
	if (have_acc) {
		sum = ADD(acc, sum);
	}
	return write_reg(REGID(0), sum);
}

/**
 * Capstone: ARM_INS_SMLABB, ARM_INS_SMLABT, ARM_INS_SMLATB, ARM_INS_SMLATT, ARM_INS_SMLAD, ARM_INS_SMLADX, ARM_INS_SMLSD, ARM_INS_SMLSDX
 * ARM: smlabb, smlabt, smlatb, smlatt, smlad, smladx, smlsd, smlsdx
 */
static RzILOpEffect *smlabb(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0)) {
		return NULL;
	}
	RzILOpBitVector *ra = ARG(1);
	RzILOpBitVector *rb = ARG(2);
	RzILOpBitVector *acc = ARG(3);
	if (!ra || !rb || !acc) {
		rz_il_op_pure_free(ra);
		rz_il_op_pure_free(rb);
		rz_il_op_pure_free(acc);
		return NULL;
	}
	RzILOpBitVector *a = ra;
	RzILOpBitVector *b = rb;
	bool exchange_b = insn->id == ARM_INS_SMLADX || insn->id == ARM_INS_SMLSDX;
	if (insn->id == ARM_INS_SMLATB || insn->id == ARM_INS_SMLATT) {
		a = SHIFTR0(ra, UN(5, 16));
	}
	if (insn->id == ARM_INS_SMLABT || insn->id == ARM_INS_SMLATT || exchange_b) {
		b = SHIFTR0(rb, UN(5, 16));
	}
	a = UNSIGNED(16, a);
	b = UNSIGNED(16, b);
	RzILOpBitVector *product;
	ut32 extend_bits;
	if (insn->id == ARM_INS_SMLAD || insn->id == ARM_INS_SMLADX || insn->id == ARM_INS_SMLSD ||
		insn->id == ARM_INS_SMLSDX) {
		extend_bits = 34; // need more bits for the larger range that can be reached here
		RzILOpBitVector *ah = SIGNED(extend_bits, UNSIGNED(16, SHIFTR0(DUP(ra), UN(5, 16))));
		RzILOpBitVector *bh = SIGNED(extend_bits, UNSIGNED(16, exchange_b ? DUP(rb) : SHIFTR0(DUP(rb), UN(5, 16))));
		RzILOpBitVector *proda = MUL(SIGNED(extend_bits, a), SIGNED(extend_bits, b));
		RzILOpBitVector *prodb = MUL(ah, bh);
		product = insn->id == ARM_INS_SMLSD || insn->id == ARM_INS_SMLSDX
			? SUB(proda, prodb)
			: ADD(proda, prodb);
	} else {
		extend_bits = 33;
		product = MUL(SIGNED(extend_bits, a), SIGNED(extend_bits, b));
	}
	RzILOpEffect *eff = write_reg(REGID(0), UNSIGNED(32, VARL("res")));
	if (!eff) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		rz_il_op_pure_free(acc);
		return NULL;
	}
	return SEQ3(
		SETL("res", ADD(product, SIGNED(extend_bits, acc))),
		eff,
		BRANCH(INV(EQ(VARL("res"), SIGNED(extend_bits, REG(0)))), SETG("qf", IL_TRUE), NULL));
}

/**
 * Capstone: ARM_INS_SMLAL, ARM_INS_SMLALBB, ARM_INS_SMLALBT, ARM_INS_SMLALTB, ARM_INS_SMLALTT, ARM_INS_SMLALD, ARM_INS_SMLALDX,
 *           ARM_INS_SMLSLD, ARM_INS_SMLSLDX, ARM_INS_UMLAL
 * ARM: smlal, smlals, smlalbb, smlalbt, smlaltb, smlaltt, smlald, smlaldx, smlsld, smlsldx, umlal, umlals
 */
static RzILOpEffect *smlal(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0) || !ISREG(1)) {
		return NULL;
	}
	RzILOpBitVector *dl = ARG(0);
	RzILOpBitVector *dh = ARG(1);
	RzILOpBitVector *ra = ARG(2);
	RzILOpBitVector *rb = ARG(3);
	RzILOpEffect *wl = write_reg(REGID(0), UNSIGNED(32, VARL("res")));
	RzILOpEffect *wh = write_reg(REGID(1), UNSIGNED(32, SHIFTR0(VARL("res"), UN(6, 32))));
	if (!dl || !dh || !ra || !rb || !wl || !wh) {
		rz_il_op_pure_free(dl);
		rz_il_op_pure_free(dh);
		rz_il_op_pure_free(ra);
		rz_il_op_pure_free(rb);
		rz_il_op_effect_free(wl);
		rz_il_op_effect_free(wh);
		return NULL;
	}
	RzILOpBitVector *a = ra;
	RzILOpBitVector *b = rb;
	bool exchange_b = insn->id == ARM_INS_SMLALDX || insn->id == ARM_INS_SMLSLDX;
	if (insn->id == ARM_INS_SMLALTB || insn->id == ARM_INS_SMLALTT) {
		a = SHIFTR0(ra, UN(5, 16));
	}
	if (insn->id == ARM_INS_SMLALBT || insn->id == ARM_INS_SMLALTT || exchange_b) {
		b = SHIFTR0(rb, UN(5, 16));
	}
	if (insn->id == ARM_INS_SMLALBB || insn->id == ARM_INS_SMLALBT || insn->id == ARM_INS_SMLALTB ||
		insn->id == ARM_INS_SMLALTT || insn->id == ARM_INS_SMLALD || insn->id == ARM_INS_SMLALDX ||
		insn->id == ARM_INS_SMLSLD || insn->id == ARM_INS_SMLSLDX) {
		a = UNSIGNED(16, a);
		b = UNSIGNED(16, b);
	}
	if (insn->id == ARM_INS_UMLAL) {
		a = UNSIGNED(64, a);
		b = UNSIGNED(64, b);
	} else {
		a = SIGNED(64, a);
		b = SIGNED(64, b);
	}
	RzILOpBitVector *product;
	if (insn->id == ARM_INS_SMLALD || insn->id == ARM_INS_SMLALDX || insn->id == ARM_INS_SMLSLD ||
		insn->id == ARM_INS_SMLSLDX) {
		RzILOpBitVector *ah = SIGNED(64, UNSIGNED(16, SHIFTR0(DUP(ra), UN(5, 16))));
		RzILOpBitVector *bh = SIGNED(64, UNSIGNED(16, exchange_b ? DUP(rb) : SHIFTR0(DUP(rb), UN(5, 16))));
		product = insn->id == ARM_INS_SMLSLD || insn->id == ARM_INS_SMLSLDX
			? SUB(MUL(a, b), MUL(ah, bh))
			: ADD(MUL(a, b), MUL(ah, bh));
	} else {
		product = MUL(a, b);
	}
	RzILOpBitVector *res = ADD(product, APPEND(dh, dl));
	return insn->detail->arm.update_flags
		? SEQ4(SETL("res", res), update_flags_zn(VARL("res")), wl, wh)
		: SEQ3(SETL("res", res), wl, wh);
}

/**
 * Capstone: ARM_INS_SMLAWB, ARM_INS_SMLAWT
 * ARM: smlawb, smlawt
 */
static RzILOpEffect *smlaw(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0)) {
		return NULL;
	}
	RzILOpBitVector *a = ARG(1);
	RzILOpBitVector *b = ARG(2);
	RzILOpBitVector *acc = ARG(3);
	RzILOpBitVector *rres = ARG(0);
	RzILOpEffect *eff = write_reg(REGID(0), UNSIGNED(32, VARL("res")));
	if (!a || !b || !acc || !rres || !eff) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		rz_il_op_pure_free(acc);
		rz_il_op_pure_free(rres);
		rz_il_op_effect_free(eff);
		return NULL;
	}
	a = SIGNED(64, a);
	b = SIGNED(64, insn->id == ARM_INS_SMLAWT ? SHIFTRA(b, UN(5, 16)) : UNSIGNED(16, b));
	acc = SIGNED(64, acc);
	return SEQ3(
		SETL("res", ADD(SHIFTR0(MUL(a, b), UN(6, 16)), acc)),
		eff,
		BRANCH(INV(EQ(UNSIGNED(48, VARL("res")), SIGNED(48, rres))), SETG("qf", IL_TRUE), NULL));
}

/**
 * Capstone: ARM_INS_SMMLA, ARM_INS_SMMLAR, ARM_INS_SMMLS, ARM_INS_SMMLSR
 * ARM: smmla, smmlar, smmls, smmlsr
 */
static RzILOpEffect *smmla(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0)) {
		return NULL;
	}
	RzILOpBitVector *a = ARG(1);
	RzILOpBitVector *b = ARG(2);
	RzILOpBitVector *acc = ARG(3);
	if (!a || !b || !acc) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		rz_il_op_pure_free(acc);
		return NULL;
	}
	RzILOpBitVector *res = insn->id == ARM_INS_SMMLS || insn->id == ARM_INS_SMMLSR
		? SUB(APPEND(acc, U32(0)), MUL(SIGNED(64, a), SIGNED(64, b)))
		: ADD(MUL(SIGNED(64, a), SIGNED(64, b)), APPEND(acc, U32(0)));
	if (insn->id == ARM_INS_SMMLAR || insn->id == ARM_INS_SMMLSR) {
		res = ADD(res, U64(0x80000000));
	}
	return write_reg(REGID(0), UNSIGNED(32, SHIFTR0(res, UN(6, 32))));
}

/**
 * Capstone: ARM_INS_SMMUL, ARM_INS_SMMULR
 * ARM: smmul, smmulr
 */
static RzILOpEffect *smmul(cs_insn *insn, bool is_thumb) {
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
	RzILOpBitVector *res = MUL(SIGNED(64, a), SIGNED(64, b));
	if (insn->id == ARM_INS_SMMULR) {
		res = ADD(res, U64(0x80000000));
	}
	return write_reg(REGID(0), UNSIGNED(32, SHIFTR0(res, UN(6, 32))));
}

/**
 * Capstone: ARM_INS_SMUAD, ARM_INS_SMUADX
 * ARM: smuad
 */
static RzILOpEffect *smuad(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0)) {
		return NULL;
	}
	RzILOpBitVector *ra = ARG(1);
	RzILOpBitVector *rb = ARG(2);
	RzILOpEffect *eff = write_reg(REGID(0), UNSIGNED(32, VARL("res")));
	if (!ra || !rb || !eff) {
		rz_il_op_pure_free(ra);
		rz_il_op_pure_free(rb);
		rz_il_op_effect_free(eff);
		return NULL;
	}
	RzILOpBitVector *al = SIGNED(33, UNSIGNED(16, ra));
	RzILOpBitVector *ah = SIGNED(33, UNSIGNED(16, SHIFTR0(DUP(ra), UN(5, 16))));
	RzILOpBitVector *bl = SIGNED(33, UNSIGNED(16, rb));
	RzILOpBitVector *bh = SIGNED(33, UNSIGNED(16, SHIFTR0(DUP(rb), UN(5, 16))));
	if (insn->id == ARM_INS_SMUADX) {
		RzILOpBitVector *tmp = bl;
		bl = bh;
		bh = tmp;
	}
	return SEQ3(
		SETL("res", ADD(MUL(al, bl), MUL(ah, bh))),
		eff,
		BRANCH(XOR(MSB(VARL("res")), MSB(REG(0))), SETG("qf", IL_TRUE), NULL));
}

/**
 * Capstone: ARM_INS_SMULBB, ARM_INS_SMULBT, ARM_INS_SMULTB, ARM_INS_SMULTT, ARM_INS_SMUSD, ARM_INS_SMUSDX
 * ARM: smulbb, smulbt, smultb, smultt, smusd, smusdx
 */
static RzILOpEffect *smulbb(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0)) {
		return NULL;
	}
	RzILOpBitVector *ra = ARG(1);
	RzILOpBitVector *rb = ARG(2);
	if (!ra || !rb) {
		rz_il_op_pure_free(ra);
		rz_il_op_pure_free(rb);
		return NULL;
	}
	RzILOpBitVector *a = ra;
	RzILOpBitVector *b = rb;
	if (insn->id == ARM_INS_SMULTB || insn->id == ARM_INS_SMULTT) {
		a = SHIFTR0(a, UN(5, 16));
	}
	if (insn->id == ARM_INS_SMULBT || insn->id == ARM_INS_SMULTT || insn->id == ARM_INS_SMUSDX) {
		b = SHIFTR0(b, UN(5, 16));
	}
	a = UNSIGNED(16, a);
	b = UNSIGNED(16, b);
	RzILOpBitVector *res = MUL(SIGNED(32, a), SIGNED(32, b));
	if (insn->id == ARM_INS_SMUSD || insn->id == ARM_INS_SMUSDX) {
		res = SUB(res,
			MUL(
				SIGNED(32, UNSIGNED(16, SHIFTR0(DUP(ra), UN(5, 16)))),
				SIGNED(32,
					UNSIGNED(16, insn->id == ARM_INS_SMUSDX ? DUP(rb) : SHIFTR0(DUP(rb), UN(5, 16))))));
	}
	return write_reg(REGID(0), res);
}

/**
 * Capstone: ARM_INS_TBB, ARM_INS_TBH
 * ARM: tbb, tbh
 */
static RzILOpEffect *tbb(cs_insn *insn, bool is_thumb) {
	RzILOpBitVector *addr = ARG(0);
	if (!addr) {
		return NULL;
	}
	RzILOpBitVector *off = insn->id == ARM_INS_TBB ? LOAD(addr) : LOADW(16, addr);
	return JMP(ADD(U32(PC(insn->address, is_thumb)), SHIFTL0(UNSIGNED(32, off), UN(5, 1))));
}

static RzILOpEffect *write_reg_lane(arm_reg reg, ut32 lane, ut32 vec_size, RzILOpBitVector *v) {
	ut32 reg_size = reg_bits(reg);
	ut32 offset = vec_size * lane;

	// up bound is reg_bits(<Qd>)
	if (offset + vec_size > 128) {
		return NULL;
	}

	RzILOpBitVector *sft_val = SHIFTL0(UNSIGNED(reg_size, v), UN(8, offset));
	return write_reg(reg, sft_val);
}

/**
 * For Extend Instruction Set
 * TODO: Split to a seperate file and include before arm lifter
 * VFP and NEON
 */

/**
 * Capstone: ARM_INS_VMOV
 * ARM: vmov
 */
static RzILOpEffect *vmov(cs_insn *insn, bool is_thumb) {
	if (OPCOUNT() < 2 || !ISREG(0) || (!ISIMM(1) && !ISREG(1))) {
		return NULL;
	}

	// vmov for immediate must be unconditional
	// vmov.<dt> <Qd>, or vmov.<dt> <Dd>
	// vmov.F32 <Sd>, or vmov.F64 <Qd>
	if (ISIMM(1)) {
		// possible : I8, I16, I32, I64, F32 for Q/D register
		// possible : F32 for S register
		// possible : F64 for D register
		ut32 imm_width = DT_WIDTH(insn);
		if (!imm_width) {
			return NULL;
		}
		ut32 reg_width = REG_WIDTH(0);
		if (reg_width < imm_width) {
			return NULL;
		}

		ut32 imm = get_imm(insn, 1, NULL);
		RzILOpBitVector *imm_bv = repeated_imm(imm_width, reg_width, imm);
		if (!imm_bv) {
			return NULL;
		}

		// vmvn Dd, imm
		if (insn->id == ARM_INS_VMVN) {
			imm_bv = LOGNOT(imm_bv);
		}

		return write_reg(REGID(0), imm_bv);
	}

	// 2 core registers and 1 double-word register
	if (OPCOUNT() == 3) {
		if (!is_core_reg(REGID(0))) {
			// vmov <Dm> <Rt1> <Rt2>, Dm[low] = Rt1, Dm[high] = Rt2
			RzILOpBitVector *rt1_val = REG(1);
			RzILOpBitVector *rt2_val = REG(2);
			if (!rt1_val || !rt2_val) {
				return NULL;
			}
			return write_reg(REGID(0), APPEND(rt2_val, rt1_val));
		}
		// vmov <Rt1> <Rt2> <Dm>, Rt1 = Dm[low], Rt2 = Dm[high]
		RzILOpBitVector *reg_val = REG(2);
		if (!reg_val) {
			return NULL;
		}
		RzILOpBitVector *rt1_val = UNSIGNED(32, DUP(reg_val));
		RzILOpBitVector *rt2_val = UNSIGNED(32, SHIFTR0(reg_val, UN(8, 32)));
		return SEQ2(write_reg(REGID(0), rt1_val),
			write_reg(REGID(1), rt2_val));
	}

	// 2 core registers and 2 single-word registers
	// vmov <Sm1> <Sm2> <Rt1> <Rt2>
	// vmov <Rt1> <Rt2> <Sm1> <Sm2>
	if (OPCOUNT() == 4) {
		RzILOpBitVector *rt1_val = REG(2);
		RzILOpBitVector *rt2_val = REG(3);
		if (!rt1_val || !rt2_val) {
			return NULL;
		}
		return SEQ2(write_reg(REGID(0), rt1_val),
			write_reg(REGID(1), rt2_val));
	}

	// core register to scalar
	if (NEON_LANE(0) != -1 && !is_core_reg(REGID(0)) && is_core_reg(REGID(1))) {
		// vmov.<vec_size> <Dd>[lane], <Rt>
		// <Dd>[lane] = <Rt>{vecsize - 1 : 0}
		if (!VVEC_SIZE(insn) || NEON_LANE(0) == -1) {
			return NULL;
		}
		RzILOpBitVector *rt_val = UNSIGNED(VVEC_SIZE(insn), REG(1));
		return write_reg_lane(REGID(0), NEON_LANE(0), VVEC_SIZE(insn), rt_val);
	}

	// scalar to core register
	if (NEON_LANE(1) != -1 && !is_core_reg(REGID(1)) && is_core_reg(REGID(0))) {
		// vmov.<dt> <Rt> <Dd>[lane]
		// <Rt> = extend_to_32(<Dd>[lane], lane has size of dt)
		// unsigned/signed extend is specified by <dt> in capstone
		if (VVEC_DT(insn) == ARM_VECTORDATA_INVALID) {
			return NULL;
		}
		bool use_zero_ext = true;
		if (VVEC_DT(insn) == ARM_VECTORDATA_S8 || VVEC_DT(insn) == ARM_VECTORDATA_S16) {
			use_zero_ext = false;
		}
		RzILOpBitVector *lane_val = read_reg_lane(REGID(1), NEON_LANE(1), DT_WIDTH(insn));
		RzILOpBitVector *ext_lane_val = use_zero_ext ? UNSIGNED(32, lane_val) : SIGNED(32, lane_val);
		return write_reg(REGID(0), ext_lane_val);
	}

	// 1. vmov rd, rn
	// 2. core register and single-word register
	RzILOpBitVector *val = ARG(1);
	if (!val) {
		return NULL;
	}

	// vmvn Qd, Qn
	if (insn->id == ARM_INS_VMVN) {
		val = LOGNOT(val);
	}

	return write_reg(REGID(0), val);
}

/**
 * Capstone: ARM_INS_VMRS
 * ARM: vmrs
 * read extension/NEON system register into core register
 */
static RzILOpEffect *vmrs(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0) || !ISREG(1)) {
		return NULL;
	}

	// VMRS <Rt>, FPSCR only
	if (REGID(1) != ARM_REG_FPSCR) {
		return NULL;
	}

	// if <Rt> is APSR, transfer to flags
	if (REGID(0) == ARM_REG_APSR_NZCV) {
		RzILOpBitVector *val = VARG("fpscr");
		return SEQ4(
			SETG("nf", INV(IS_ZERO(LOGAND(val, U32(1ul << 31))))),
			SETG("zf", INV(IS_ZERO(LOGAND(DUP(val), U32(1ul << 30))))),
			SETG("cf", INV(IS_ZERO(LOGAND(DUP(val), U32(1ul << 29))))),
			SETG("vf", INV(IS_ZERO(LOGAND(DUP(val), U32(1ul << 28))))));
	}

	if (is_core_reg(REGID(0)) && REGID(0) != ARM_REG_PC) {
		return write_reg(REGID(0), VARG("fpscr"));
	}

	return NULL;
}

/**
 * Capstone: ARM_INS_VMSR
 * ARM: vmsr
 * write core register value into extension/NEON system register
 */
static RzILOpEffect *vmsr(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0) || REGID(0) != ARM_REG_FPSCR) {
		return NULL;
	}

	RzILOpBitVector *val;
	if (REGID(1) == ARM_REG_CPSR || REGID(1) == ARM_REG_SPSR || REGID(1) == ARM_REG_APSR) {
		val = LOGOR(ITE(VARG("nf"), U32(1ul << 31), U32(0)),
			LOGOR(ITE(VARG("zf"), U32(1ul << 30), U32(0)),
				LOGOR(ITE(VARG("cf"), U32(1ul << 29), U32(0)),
					LOGOR(ITE(VARG("vf"), U32(1ul << 28), U32(0)),
						LOGOR(ITE(VARG("qf"), U32(1ul << 27), U32(0)),
							SHIFTL0(UNSIGNED(32, VARG("gef")), UN(5, 16)))))));
	} else if (REGID(1) == ARM_REG_APSR_NZCV) {
		val = LOGOR(ITE(VARG("nf"), U32(1ul << 31), U32(0)),
			LOGOR(ITE(VARG("zf"), U32(1ul << 30), U32(0)),
				LOGOR(ITE(VARG("cf"), U32(1ul << 29), U32(0)),
					LOGOR(ITE(VARG("vf"), U32(1ul << 28), U32(0)),
						U32(0)))));
	} else {
		val = ARG(1);
	}

	return SETG("fpscr", val);
}

/**
 * Capstone: ARM_INS_VAND, ARM_INS_VORR, ARM_INS_VORN, ARM_INS_VEOR, ARM_INS_VBIC,
 * vand, vorr, vorn, veor, vbic
 */
static RzILOpEffect *vbitwise(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0) || OPCOUNT() < 2) {
		return NULL;
	}

	// has following types:
	// 1. bitwise_op <dst>, #imm
	// 2. bitwise_op <dst>, <src1>, <src2>
	RzILOpBitVector *src_a = ARG(OPCOUNT() - 2);
	RzILOpBitVector *src_b;

	// pseudo-instruction VAND(imm) disassembly produces VBIC(imm)
	// pseudo-instruction VORN(imm) disassembly produces VORR(imm)
	if ((insn->id == ARM_INS_VBIC || insn->id == ARM_INS_VORR) && ISIMM(OPCOUNT() - 1)) {
		ut32 imm = get_imm(insn, OPCOUNT() - 1, NULL);
		src_b = repeated_imm(DT_WIDTH(insn), REG_WIDTH(0), imm);
	} else {
		src_b = REG(OPCOUNT() - 1);
	}

	if (!src_a || !src_b) {
		rz_il_op_pure_free(src_a);
		rz_il_op_pure_free(src_b);
		return NULL;
	}

	RzILOpBitVector *res;
	switch (insn->id) {
	case ARM_INS_VAND:
		res = LOGAND(src_a, src_b);
		break;
	case ARM_INS_VORR:
		res = LOGOR(src_a, src_b);
		break;
	case ARM_INS_VORN:
		res = LOGOR(src_a, LOGNOT(src_b));
		break;
	case ARM_INS_VEOR:
		res = LOGXOR(src_a, src_b);
		break;
	case ARM_INS_VBIC:
		res = LOGAND(src_a, LOGNOT(src_b));
		break;
	default:
		rz_il_op_pure_free(src_a);
		rz_il_op_pure_free(src_b);
		return NULL;
	}

	return write_reg(REGID(0), res);
}

/**
 * Capstone: ARM_INS_VBIT, ARM_INS_VBIF, ARM_INS_VBSL
 * ARM: vbit, vbif, vbsl
 */
static RzILOpEffect *vbit_insert(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0) || OPCOUNT() < 3) {
		return NULL;
	}

	// v<op> <Qd>, <Qn>, <Qm>
	// v<op> <Dd>, <Dn>, <Dm>
	RzILOpBitVector *d = REG(0);
	RzILOpBitVector *n = REG(1);
	RzILOpBitVector *m = REG(2);

	if (!d || !n || !m) {
		rz_il_op_pure_free(d);
		rz_il_op_pure_free(n);
		rz_il_op_pure_free(m);
		return NULL;
	}

	RzILOpBitVector *res;
	switch (insn->id) {
	case ARM_INS_VBIF:
		// Rd = (d and m) or (n and not(m))
		res = LOGOR(LOGAND(d, m), LOGAND(n, LOGNOT(DUP(m))));
		break;
	case ARM_INS_VBIT:
		// Rd = (n and m) or (d and not(m))
		res = LOGOR(LOGAND(n, m), LOGAND(d, LOGNOT(DUP(m))));
		break;
	case ARM_INS_VBSL:
		// Rd = (n and d) or (m and not(d))
		res = LOGOR(LOGAND(n, d), LOGAND(m, LOGNOT(DUP(d))));
		break;
	default:
		rz_il_op_pure_free(d);
		rz_il_op_pure_free(n);
		rz_il_op_pure_free(m);
		return NULL;
	}

	return write_reg(REGID(0), res);
}

/**
 * Capstone: ARM_INS_VCEQ, ARM_INS_VCGE, ARM_INS_VCGT, ARM_INS_VCLE, ARM_INS_VCLT
 * ARM_INS_VACGE, ARM_INS_VACGT
 * ARM: vceq, vcge, vcgt, vcle, vclt, vacge, vacgt, [pseudo: vacle, vaclt]
 */
static RzILOpEffect *vec_cmp(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0) && OPCOUNT() < 3) {
		return NULL;
	}

	if (VVEC_DT(insn) == ARM_VECTORDATA_F32) {
		ut32 vec_size = 32;
		RzILOpEffect *eff = EMPTY();
		for (int i = 0; i < REG_WIDTH(0) / vec_size; ++i) {
			RzILOpFloat *l_elem = BV2F(RZ_FLOAT_IEEE754_BIN_32,
				read_reg_lane(REGID(1), i, vec_size));
			RzILOpFloat *r_elem = ISIMM(2) ? F32(0.0f) : BV2F(RZ_FLOAT_IEEE754_BIN_32, read_reg_lane(REGID(2), i, vec_size));
			RzILOpBool *cond;
			switch (insn->id) {
			case ARM_INS_VCEQ:
				cond = FEQ(l_elem, r_elem);
				break;
			case ARM_INS_VCGE:
				cond = INV(FORDER(l_elem, r_elem));
				break;
			case ARM_INS_VCGT:
				cond = FORDER(r_elem, l_elem);
				break;
			case ARM_INS_VCLE:
				cond = INV(FORDER(r_elem, l_elem));
				break;
			case ARM_INS_VCLT:
				cond = FORDER(l_elem, r_elem);
				break;
			case ARM_INS_VACGE:
				cond = INV(FORDER(FABS(l_elem), FABS(r_elem)));
				break;
			case ARM_INS_VACGT:
				cond = FORDER(FABS(r_elem), FABS(l_elem));
				break;
			default:
				cond = NULL;
				rz_il_op_pure_free(l_elem);
				rz_il_op_pure_free(r_elem);
				rz_il_op_effect_free(eff);
				return NULL;
			}

			eff = SEQ2(eff,
				write_reg_lane(REGID(0), i, vec_size,
					ITE(cond, LOGNOT(UN(vec_size, 0)), UN(vec_size, 0))));
		}
		return eff;
	}

	// for integer number
	ut32 vec_size = DT_WIDTH(insn);
	RzILOpEffect *eff = EMPTY();
	for (int i = 0; i < REG_WIDTH(0) / vec_size; ++i) {
		RzILOpBitVector *l_elem = read_reg_lane(REGID(1), i, vec_size);
		RzILOpBitVector *r_elem = ISIMM(2) ? UN(vec_size, 0) : read_reg_lane(REGID(2), i, vec_size);

		RzILOpBool *cond;
		bool as_signed = is_vec_signed(VVEC_DT(insn));
		switch (insn->id) {
		case ARM_INS_VCEQ:
			cond = EQ(l_elem, r_elem);
			break;
		case ARM_INS_VCGE:
			cond = as_signed ? SGE(l_elem, r_elem) : UGE(l_elem, r_elem);
			break;
		case ARM_INS_VCGT:
			cond = as_signed ? SGT(l_elem, r_elem) : UGT(l_elem, r_elem);
			break;
		case ARM_INS_VCLE:
			cond = as_signed ? SLE(l_elem, r_elem) : ULE(l_elem, r_elem);
			break;
		case ARM_INS_VCLT:
			cond = as_signed ? SLT(l_elem, r_elem) : SLE(l_elem, r_elem);
			break;
		default:
			cond = NULL;
			rz_il_op_pure_free(l_elem);
			rz_il_op_pure_free(r_elem);
			rz_il_op_effect_free(eff);
			return NULL;
		}

		eff = SEQ2(eff,
			write_reg_lane(REGID(0), i, vec_size,
				ITE(cond, LOGNOT(UN(vec_size, 0)), UN(vec_size, 0))));
	}

	return eff;
}

static RzILOpEffect *vtst(cs_insn *insn, bool is_thumb) {
	if (OPCOUNT() < 3) {
		return NULL;
	}

	// vtst <Vd>, <Vn>, <Vm>
	// for each lane:
	// Vd = iszero((n and m)) ? zero : not(zero)
	ut32 vec_size = VVEC_SIZE(insn);
	RzILOpEffect *eff = EMPTY();
	for (int i = 0; i < REG_WIDTH(0) / vec_size; ++i) {
		RzILOpBitVector *n = read_reg_lane(REGID(1), i, vec_size);
		RzILOpBitVector *m = read_reg_lane(REGID(2), i, vec_size);
		RzILOpBitVector *d = ITE(IS_ZERO(LOGAND(n, m)),
			UN(vec_size, 0),
			LOGNOT(UN(vec_size, 0)));
		eff = SEQ2(eff,
			write_reg_lane(REGID(0), i, vec_size, d));
	}

	return eff;
}

static RzILOpEffect *vldn_multiple_elem(cs_insn *insn, bool is_thumb) {
	ut32 mem_idx;
	ut32 regs = 0;
	bool wback = ISWRITEBACK32();
	bool use_rm_as_wback_offset = false;
	ut32 group_sz = insn->id - ARM_INS_VLD1 + 1;

	// vldn {list}, [Rn], Rm
	if (ISPOSTINDEX32()) {
		use_rm_as_wback_offset = true;
	}
	regs = OPCOUNT() - 1;

	// mem_idx
	mem_idx = regs;

	// assert list_size % n == 0
	// assert they were all Dn
	ut32 n_groups = regs / group_sz;
	ut32 elem_bits = VVEC_SIZE(insn);
	ut32 elem_bytes = elem_bits / 8;
	ut32 lanes = 64 / elem_bits;
	ut32 addr_bits = REG_WIDTH(mem_idx);

	RzILOpEffect *wback_eff = NULL;
	RzILOpEffect *eff = EMPTY();
	RzILOpBitVector *addr = ISPOSTINDEX32() ? MEMBASE(mem_idx) : ARG(mem_idx);

	for (int i = 0; i < n_groups; ++i) {
		for (int j = 0; j < lanes; ++j) {
			RzILOpBitVector *data0, *data1, *data2, *data3;
			ut32 vreg_idx = i * group_sz;
			switch (group_sz) {
			case 1:
				data0 = LOADW(elem_bits, addr);
				eff = SEQ2(eff,
					write_reg_lane(REGID(vreg_idx), j, elem_bits, data0));
				break;
			case 2:
				data0 = LOADW(elem_bits, addr);
				addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
				data1 = LOADW(elem_bits, addr);
				eff = SEQ3(eff,
					write_reg_lane(REGID(vreg_idx), j, elem_bits, data0),
					write_reg_lane(REGID(vreg_idx + 1), j, elem_bits, data1));
				break;
			case 3:
				data0 = LOADW(elem_bits, addr);
				addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
				data1 = LOADW(elem_bits, addr);
				addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
				data2 = LOADW(elem_bits, addr);
				eff = SEQ4(eff,
					write_reg_lane(REGID(vreg_idx), j, elem_bits, data0),
					write_reg_lane(REGID(vreg_idx + 1), j, elem_bits, data1),
					write_reg_lane(REGID(vreg_idx + 2), j, elem_bits, data2));
				break;
			case 4:
				data0 = LOADW(elem_bits, addr);
				addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
				data1 = LOADW(elem_bits, addr);
				addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
				data2 = LOADW(elem_bits, addr);
				addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
				data3 = LOADW(elem_bits, addr);
				eff = SEQ5(eff,
					write_reg_lane(REGID(vreg_idx), j, elem_bits, data0),
					write_reg_lane(REGID(vreg_idx + 1), j, elem_bits, data1),
					write_reg_lane(REGID(vreg_idx + 2), j, elem_bits, data2),
					write_reg_lane(REGID(vreg_idx + 3), j, elem_bits, data3));
				break;
			default:
				rz_warn_if_reached();
				return NULL;
			}
			addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
		}
	}

	// free last address inc op
	rz_il_op_pure_free(addr);

	// update Rn
	// if write_back then Rn = Rn + (if use_rm then Rm else 8 * regs)
	if (wback) {
		RzILOpBitVector *new_offset = use_rm_as_wback_offset ? MEMINDEX(mem_idx) : UN(32, 8 * regs);
		wback_eff = write_reg(REGBASE(mem_idx), ADD(MEMBASE(mem_idx), new_offset));
	} else {
		wback_eff = EMPTY();
	}

	return SEQ2(eff, wback_eff);
}

static RzILOpEffect *vldn_single_lane(cs_insn *insn, bool is_thumb) {
	ut32 mem_idx;
	bool use_rm_as_wback_offset = false;
	ut32 regs; // number of regs in {list}

	if (ISPOSTINDEX32()) {
		use_rm_as_wback_offset = true;
	}
	regs = OPCOUNT() - 1;
	mem_idx = regs;

	ut32 group_sz = insn->id - ARM_INS_VLD1 + 1;
	if (group_sz != regs) {
		return NULL;
	}

	RzILOpBitVector *data0, *data1, *data2, *data3;
	RzILOpEffect *eff;
	RzILOpBitVector *addr = ISPOSTINDEX32() ? MEMBASE(mem_idx) : ARG(mem_idx);
	ut32 vreg_idx = 0;
	ut32 elem_bits = VVEC_SIZE(insn);
	ut32 elem_bytes = elem_bits / 8;
	ut32 addr_bits = REG_WIDTH(mem_idx);

	// vld1/vld2/vld3/vld4, max(lane_size) == 4 Bytes
	if (group_sz > 4 || elem_bytes > 4) {
		return NULL;
	}

	unsigned char lane = NEON_LANE(0);
	switch (group_sz) {
	case 1:
		data0 = LOADW(elem_bits, addr);
		eff = write_reg_lane(REGID(vreg_idx), lane, elem_bits, data0);
		break;
	case 2:
		data0 = LOADW(elem_bits, addr);
		addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
		data1 = LOADW(elem_bits, addr);
		eff = SEQ2(write_reg_lane(REGID(vreg_idx), lane, elem_bits, data0),
			write_reg_lane(REGID(vreg_idx + 1), lane, elem_bits, data1));
		break;
	case 3:
		data0 = LOADW(elem_bits, addr);
		addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
		data1 = LOADW(elem_bits, addr);
		addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
		data2 = LOADW(elem_bits, addr);
		eff = SEQ3(write_reg_lane(REGID(vreg_idx), lane, elem_bits, data0),
			write_reg_lane(REGID(vreg_idx + 1), lane, elem_bits, data1),
			write_reg_lane(REGID(vreg_idx + 2), lane, elem_bits, data2));
		break;
	case 4:
		data0 = LOADW(elem_bits, addr);
		addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
		data1 = LOADW(elem_bits, addr);
		addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
		data2 = LOADW(elem_bits, addr);
		addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
		data3 = LOADW(elem_bits, addr);
		eff = SEQ4(write_reg_lane(REGID(vreg_idx), lane, elem_bits, data0),
			write_reg_lane(REGID(vreg_idx + 1), lane, elem_bits, data1),
			write_reg_lane(REGID(vreg_idx + 2), lane, elem_bits, data2),
			write_reg_lane(REGID(vreg_idx + 3), lane, elem_bits, data3));
		break;
	default:
		rz_warn_if_reached();
		return NULL;
	}

	bool wback = ISWRITEBACK32();
	RzILOpEffect *wback_eff;
	if (wback) {
		RzILOpBitVector *new_offset = use_rm_as_wback_offset ? MEMINDEX(mem_idx) : UN(32, (ut64)elem_bytes * group_sz);
		wback_eff = write_reg(REGID(mem_idx), ADD(MEMBASE(mem_idx), new_offset));
	} else {
		wback_eff = EMPTY();
	}

	return SEQ2(eff, wback_eff);
}

static RzILOpEffect *vldn_all_lane(cs_insn *insn, bool is_thumb) {
	ut32 mem_idx;
	bool use_rm_as_wback_offset = false;
	ut32 regs; // number of regs in {list}

	if (ISPOSTINDEX32()) {
		use_rm_as_wback_offset = true;
	}
	regs = OPCOUNT() - 1;
	mem_idx = regs;

	ut32 group_sz = insn->id - ARM_INS_VLD1 + 1;
	if (group_sz != regs) {
		return NULL;
	}

	RzILOpBitVector *data0 = NULL, *data1 = NULL, *data2 = NULL, *data3 = NULL;
	RzILOpEffect *eff = NULL;
	RzILOpBitVector *addr = ISPOSTINDEX32() ? MEMBASE(mem_idx) : ARG(mem_idx);
	ut32 elem_bits = VVEC_SIZE(insn);
	ut32 elem_bytes = elem_bits / 8;
	ut32 addr_bits = REG_WIDTH(mem_idx);

	// vld1/vld2/vld3/vld4, max(lane_size) == 4 Bytes
	if (group_sz > 4 || elem_bytes > 4) {
		return NULL;
	}

	ut32 dreg_size = 64;
	switch (group_sz) {
	case 1:
		data0 = replicated_val(elem_bits, dreg_size, LOADW(elem_bits, addr));
		eff = write_reg(REGID(0), DUP(data0));
		if (regs == 2) {
			eff = write_reg(REGID(1), data0);
		}
		break;
	case 2:
		data0 = replicated_val(elem_bits, dreg_size, LOADW(elem_bits, addr));
		addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
		data1 = replicated_val(elem_bits, dreg_size, LOADW(elem_bits, addr));
		eff = SEQ2(write_reg(REGID(0), data0),
			write_reg(REGID(1), data1));
		break;
	case 3:
		data0 = replicated_val(elem_bits, dreg_size, LOADW(elem_bits, addr));
		addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
		data1 = replicated_val(elem_bits, dreg_size, LOADW(elem_bits, addr));
		addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
		data2 = replicated_val(elem_bits, dreg_size, LOADW(elem_bits, addr));
		eff = SEQ3(write_reg(REGID(0), data0),
			write_reg(REGID(1), data1),
			write_reg(REGID(2), data2));
		break;
	case 4:
		data0 = replicated_val(elem_bits, dreg_size, LOADW(elem_bits, addr));
		addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
		data1 = replicated_val(elem_bits, dreg_size, LOADW(elem_bits, addr));
		addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
		data2 = replicated_val(elem_bits, dreg_size, LOADW(elem_bits, addr));
		addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
		data3 = replicated_val(elem_bits, dreg_size, LOADW(elem_bits, addr));
		eff = SEQ4(write_reg(REGID(0), data0),
			write_reg(REGID(1), data1),
			write_reg(REGID(2), data2),
			write_reg(REGID(3), data3));
		break;
	default:
		rz_warn_if_reached();
		return NULL;
	}

	bool wback = ISWRITEBACK32();
	RzILOpEffect *wback_eff;
	if (wback) {
		RzILOpBitVector *new_offset = use_rm_as_wback_offset ? MEMINDEX(mem_idx) : UN(32, (ut64)elem_bytes * group_sz);
		wback_eff = write_reg(REGID(mem_idx), ADD(MEMBASE(mem_idx), new_offset));
	} else {
		wback_eff = EMPTY();
	}

	return SEQ2(eff, wback_eff);
}

static RzILOpEffect *vldn(cs_insn *insn, bool is_thumb) {
	if (OPCOUNT() < 2 || !ISREG(0)) {
		return NULL;
	}

	// to single lane
	if (NEON_LANE(0) != -1) {
		return vldn_single_lane(insn, is_thumb);
	}

	// TODO: capstone cannot distinguish details of the following instructions
	// vld3.8 {d0, d1, d2}, [r0] (f420040f)
	// vld3.8 {d0[], d1[], d2[]}, [r0] (f4a00e0f)
	bool all_lane = (insn->bytes[2] & 0x0C) == 0x0C;
	return all_lane ? vldn_all_lane(insn, is_thumb) : vldn_multiple_elem(insn, is_thumb);
}

static RzILOpEffect *vstn_multiple_elem(cs_insn *insn, bool is_thumb) {
	ut32 mem_idx;
	ut32 regs = 0;
	bool wback = ISWRITEBACK32();
	bool use_rm_as_wback_offset = false;
	ut32 group_sz = insn->id - ARM_INS_VST1 + 1;

	// vldn {list}, [Rn], Rm
	if (ISPOSTINDEX32()) {
		use_rm_as_wback_offset = true;
	}
	regs = OPCOUNT() - 1;

	// mem_idx
	mem_idx = regs;

	// assert list_size % n == 0
	// assert they were all Dn
	ut32 n_groups = regs / group_sz;
	ut32 elem_bits = VVEC_SIZE(insn);
	ut32 elem_bytes = elem_bits / 8;
	ut32 lanes = 64 / elem_bits;
	ut32 addr_bits = REG_WIDTH(mem_idx);

	RzILOpEffect *wback_eff = NULL;
	RzILOpEffect *eff = EMPTY(), *eff_ = NULL, *eff__ = NULL;
	RzILOpBitVector *addr = ISPOSTINDEX32() ? MEMBASE(mem_idx) : ARG(mem_idx);

	for (int i = 0; i < n_groups; ++i) {
		for (int j = 0; j < lanes; ++j) {
			RzILOpBitVector *data0, *data1, *data2, *data3;
			ut32 vreg_idx = i * group_sz;
			switch (group_sz) {
			case 1:
				data0 = read_reg_lane(REGID(vreg_idx), j, elem_bits);
				eff = SEQ2(eff, STOREW(addr, data0));
				break;
			case 2:
				data0 = read_reg_lane(REGID(vreg_idx), j, elem_bits);
				data1 = read_reg_lane(REGID(vreg_idx + 1), j, elem_bits);
				eff = SEQ2(eff, STOREW(addr, data0));
				addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
				eff = SEQ2(eff, STOREW(addr, data1));
				break;
			case 3:
				data0 = read_reg_lane(REGID(vreg_idx), j, elem_bits);
				data1 = read_reg_lane(REGID(vreg_idx + 1), j, elem_bits);
				data2 = read_reg_lane(REGID(vreg_idx + 2), j, elem_bits);
				eff = SEQ2(eff, STOREW(addr, data0));
				addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
				eff_ = STOREW(addr, data1);
				addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
				eff = SEQ3(eff, eff_, STOREW(addr, data2));
				break;
			case 4:
				data0 = read_reg_lane(REGID(vreg_idx), j, elem_bits);
				data1 = read_reg_lane(REGID(vreg_idx + 1), j, elem_bits);
				data2 = read_reg_lane(REGID(vreg_idx + 2), j, elem_bits);
				data3 = read_reg_lane(REGID(vreg_idx + 3), j, elem_bits);
				eff = SEQ2(eff, STOREW(addr, data0));
				addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
				eff_ = STOREW(addr, data1);
				addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
				eff__ = STOREW(addr, data2);
				addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
				eff = SEQ4(eff, eff_, eff__, STOREW(addr, data3));
				break;
			default:
				rz_warn_if_reached();
				return NULL;
			}
			addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
		}
	}

	// free last address inc op
	rz_il_op_pure_free(addr);

	// update Rn
	// if write_back then Rn = Rn + (if use_rm then Rm else 8 * regs)
	if (wback) {
		RzILOpBitVector *new_offset = use_rm_as_wback_offset ? MEMINDEX(mem_idx) : UN(32, 8 * regs);
		wback_eff = write_reg(REGID(mem_idx), ADD(MEMBASE(mem_idx), new_offset));
	} else {
		wback_eff = EMPTY();
	}

	return SEQ2(eff, wback_eff);
}

static RzILOpEffect *vstn_from_single_lane(cs_insn *insn, bool is_thumb) {
	ut32 mem_idx;
	bool use_rm_as_wback_offset = false;
	ut32 regs; // number of regs in {list}

	if (ISPOSTINDEX32()) {
		use_rm_as_wback_offset = true;
	}
	regs = OPCOUNT() - 1;
	mem_idx = regs;

	ut32 group_sz = insn->id - ARM_INS_VST1 + 1;
	if (group_sz != regs) {
		return NULL;
	}

	RzILOpBitVector *data0, *data1, *data2, *data3;
	RzILOpEffect *eff, *eff_, *eff__;
	RzILOpBitVector *addr = ISPOSTINDEX32() ? MEMBASE(mem_idx) : ARG(mem_idx);
	ut32 vreg_idx = 0;
	ut32 elem_bits = VVEC_SIZE(insn);
	ut32 elem_bytes = elem_bits / 8;
	ut32 addr_bits = REG_WIDTH(mem_idx);

	if (group_sz > 4 || elem_bytes > 4) {
		return NULL;
	}

	unsigned char lane = NEON_LANE(0);
	switch (group_sz) {
	case 1:
		data0 = read_reg_lane(REGID(vreg_idx), lane, elem_bits);
		eff = STOREW(addr, data0);
		break;
	case 2:
		data0 = read_reg_lane(REGID(vreg_idx), lane, elem_bits);
		data1 = read_reg_lane(REGID(vreg_idx + 1), lane, elem_bits);
		eff = STOREW(addr, data0);
		addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
		eff = SEQ2(eff, STOREW(addr, data1));
		break;
	case 3:
		data0 = read_reg_lane(REGID(vreg_idx), lane, elem_bits);
		data1 = read_reg_lane(REGID(vreg_idx + 1), lane, elem_bits);
		data2 = read_reg_lane(REGID(vreg_idx + 2), lane, elem_bits);
		eff = STOREW(addr, data0);
		addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
		eff_ = STOREW(addr, data1);
		addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
		eff = SEQ3(eff, eff_, STOREW(addr, data2));
		break;
	case 4:
		data0 = read_reg_lane(REGID(vreg_idx), lane, elem_bits);
		data1 = read_reg_lane(REGID(vreg_idx + 1), lane, elem_bits);
		data2 = read_reg_lane(REGID(vreg_idx + 2), lane, elem_bits);
		data3 = read_reg_lane(REGID(vreg_idx + 3), lane, elem_bits);
		eff = STOREW(addr, data0);
		addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
		eff_ = STOREW(addr, data1);
		addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
		eff__ = STOREW(addr, data2);
		addr = ADD(DUP(addr), UN(addr_bits, elem_bytes));
		eff = SEQ4(eff, eff_, eff__, STOREW(addr, data3));
		break;
	default:
		rz_warn_if_reached();
		return NULL;
	}

	bool wback = ISWRITEBACK32();
	RzILOpEffect *wback_eff;
	if (wback) {
		RzILOpBitVector *new_offset = use_rm_as_wback_offset ? MEMINDEX(mem_idx) : UN(32, (ut64)elem_bytes * group_sz);
		wback_eff = write_reg(REGID(mem_idx), ADD(MEMBASE(mem_idx), new_offset));
	} else {
		wback_eff = EMPTY();
	}

	return SEQ2(eff, wback_eff);
}

static RzILOpEffect *vstn(cs_insn *insn, bool is_thumb) {
	if (OPCOUNT() < 2 || !ISREG(0)) {
		return NULL;
	}

	if (NEON_LANE(0) != -1) {
		return vstn_from_single_lane(insn, is_thumb);
	}

	return vstn_multiple_elem(insn, is_thumb);
}

static RzILOpEffect *try_as_float_cvt(cs_insn *insn, bool is_thumb, bool *success) {
	RzFloatFormat from_fmt, to_fmt;
	from_fmt = FROM_FMT(VVEC_DT(insn));
	to_fmt = TO_FMT(VVEC_DT(insn));
	if (from_fmt == RZ_FLOAT_UNK || to_fmt == RZ_FLOAT_UNK) {
		*success = false;
		return NULL;
	}

	// note that the ARM manual didn't specify rounding mode
	// VFP operation for single and double
	if (from_fmt == RZ_FLOAT_IEEE754_BIN_64 || to_fmt == RZ_FLOAT_IEEE754_BIN_64) {
		*success = true;
		return write_reg(REGID(0), F2BV(FCONVERT(to_fmt, RZ_FLOAT_RMODE_RNE, BV2F(from_fmt, REG(1)))));
	}

	// NEON vcvt for f16 and f32
	// Qn have 4 f32, Dn have 4 f16
	ut32 elem_n = 4;
	ut32 from_elem_sz = rz_float_get_format_info(from_fmt, RZ_FLOAT_INFO_TOTAL_LEN);
	ut32 to_elem_sz = rz_float_get_format_info(to_fmt, RZ_FLOAT_INFO_TOTAL_LEN);

	RzILOpEffect *eff = EMPTY();
	for (int i = 0; i < elem_n; ++i) {
		RzILOpFloat *from_val = BV2F(from_fmt, read_reg_lane(REGID(1), i, from_elem_sz));
		eff = SEQ2(eff,
			write_reg_lane(REGID(0), i, to_elem_sz,
				F2BV(FCONVERT(to_fmt, RZ_FLOAT_RMODE_RNE, from_val))));
	}

	*success = true;
	return eff;
}

static inline ut32 cvt_isize(arm_vectordata_type type, bool *is_signed) {
	switch (type) {
	case ARM_VECTORDATA_F32S32:
	case ARM_VECTORDATA_F64S32:
	case ARM_VECTORDATA_S32F32:
	case ARM_VECTORDATA_S32F64:
		*is_signed = true;
		return 32;
#if CS_API_MAJOR > 4
	case ARM_VECTORDATA_F16U32:
#endif
	case ARM_VECTORDATA_F32U32:
	case ARM_VECTORDATA_F64U32:
#if CS_API_MAJOR > 4
	case ARM_VECTORDATA_U32F16:
#endif
	case ARM_VECTORDATA_U32F32:
	case ARM_VECTORDATA_U32F64:
		*is_signed = false;
		return 32;
	case ARM_VECTORDATA_F32S16:
	case ARM_VECTORDATA_F64S16:
	case ARM_VECTORDATA_S16F32:
	case ARM_VECTORDATA_S16F64:
		*is_signed = true;
		return 16;
#if CS_API_MAJOR > 4
	case ARM_VECTORDATA_F16U16:
#endif
	case ARM_VECTORDATA_F32U16:
	case ARM_VECTORDATA_F64U16:
#if CS_API_MAJOR > 4
	case ARM_VECTORDATA_U16F16:
#endif
	case ARM_VECTORDATA_U16F32:
	case ARM_VECTORDATA_U16F64:
		*is_signed = false;
		return 16;
	default:
		rz_warn_if_reached();
		return 0;
	}
}

#if CS_NEXT_VERSION >= 6
/**
 * \brief Tests if the instruction is part of a float supporting
 * group (NEON, VFP MVEFloat...).
 *
 * \param insn The instruction to test.
 * \return true The instruction is a float instruction.
 * \return false The instruction is not a float instruction.
 */
RZ_IPI bool rz_arm_cs_is_float_insn(const cs_insn *insn) {
	rz_return_val_if_fail(insn && insn->detail, false);
	uint32_t i = 0;
	arm_insn_group group_it = insn->detail->groups[i];
	while (group_it) {
		switch (group_it) {
		default:
			break;
		case ARM_FEATURE_HasNEON:
		case ARM_FEATURE_HasVFP2:
		case ARM_FEATURE_HasVFP3:
		case ARM_FEATURE_HasVFP4:
		case ARM_FEATURE_HasDPVFP:
		case ARM_FEATURE_HasMVEFloat:
			return true;
		}
		group_it = insn->detail->groups[++i];
	}
	return false;
}
#endif

static RzILOpEffect *try_as_int_cvt(cs_insn *insn, bool is_thumb, bool *success) {
	bool is_f2i = false;
	bool is_signed = false;

	RzFloatFormat from_fmt = FROM_FMT(VVEC_DT(insn));
	RzFloatFormat to_fmt = TO_FMT(VVEC_DT(insn));
	ut32 bv_sz;
	if (from_fmt == RZ_FLOAT_UNK && to_fmt == RZ_FLOAT_UNK) {
		return NULL;
	}

	is_f2i = from_fmt == RZ_FLOAT_UNK ? false : true;
	bv_sz = cvt_isize(VVEC_DT(insn), &is_signed);
	ut32 fl_sz = rz_float_get_format_info(is_f2i ? from_fmt : to_fmt, RZ_FLOAT_INFO_TOTAL_LEN);

#if CS_NEXT_VERSION >= 6
	if (!rz_arm_cs_is_group_member(insn, ARM_FEATURE_HasNEON)) {
#else
	if (!rz_arm_cs_is_group_member(insn, ARM_GRP_NEON)) {
#endif
		// vfp
		// VCVT.F64.S32/U32 <Dd>, <Sm>
		// VCVT.F32.S32/U32 <Sd>, <Sm>
		RzILOpBitVector *from_val;
		if (is_f2i) {
			from_val = is_signed ? F2SINT(bv_sz, RZ_FLOAT_RMODE_RTZ,
						       BV2F(from_fmt, REG(1)))
					     : F2INT(bv_sz, RZ_FLOAT_RMODE_RTZ,
						       BV2F(from_fmt, REG(1)));
		} else {
			from_val = is_signed ? F2BV(SINT2F(to_fmt, RZ_FLOAT_RMODE_RNE,
						       REG(1)))
					     : F2BV(INT2F(to_fmt, RZ_FLOAT_RMODE_RNE,
						       REG(1)));
		}

		return write_reg(REGID(0), from_val);
	}

	RzILOpEffect *eff = EMPTY();
	for (int i = 0; i < REG_WIDTH(0) / bv_sz; ++i) {
		RzILOpBitVector *from_val;
		if (is_f2i) {
			from_val = is_signed ? F2SINT(bv_sz, RZ_FLOAT_RMODE_RTZ,
						       BV2F(from_fmt,
							       read_reg_lane(REGID(1), i, fl_sz)))
					     : F2INT(bv_sz, RZ_FLOAT_RMODE_RTZ,
						       BV2F(from_fmt,
							       read_reg_lane(REGID(1), i, fl_sz)));
		} else {
			from_val = is_signed ? F2BV(SINT2F(to_fmt, RZ_FLOAT_RMODE_RNE,
						       read_reg_lane(REGID(1), i, bv_sz)))
					     : F2BV(INT2F(to_fmt, RZ_FLOAT_RMODE_RNE,
						       read_reg_lane(REGID(1), i, bv_sz)));
		}
		eff = SEQ2(eff, write_reg_lane(REGID(0), i, bv_sz, from_val));
	}

	return eff;
}

static RzILOpEffect *vcvt(cs_insn *insn, bool is_thumb) {
	if (VVEC_DT(insn) == ARM_VECTORDATA_INVALID || OPCOUNT() < 2) {
		return NULL;
	}

	bool success = false;
	RzILOpEffect *eff = NULL;
	// vcvt between floats (advanced SIMD and VFP)
	// F16 <-> F32 (NEON) , F32 <-> F64 (VFP)
	eff = try_as_float_cvt(insn, is_thumb, &success);
	if (success) {
		return eff;
	}

	// vcvt between integer and float
	eff = try_as_int_cvt(insn, is_thumb, &success);
	if (success) {
		return eff;
	}

	// vcvt between fix-point and float-point
	// currently could not find a way to process fixed point value
	return NULL;
}

static RzILOpEffect *vdup(cs_insn *insn, bool is_thumb) {
	if (OPCOUNT() < 2) {
		return NULL;
	}

	ut32 elem_bits = VVEC_SIZE(insn);
	RzILOpEffect *eff = EMPTY();

	// 1. vdup <Vd> <Vn>[x], duplicate scalar
	// 2. vdup <Vd> <Rn>, duplicate Rn bits to Vd
	bool is_dup_lane = NEON_LANE(1) != -1;

	for (int i = 0; i < reg_bits(REGID(0)) / elem_bits; ++i) {
		RzILOpBitVector *scalar = is_dup_lane ? read_reg_lane(REGID(1), NEON_LANE(1), elem_bits) : UNSIGNED(elem_bits, REG(1));
		eff = SEQ2(eff,
			write_reg_lane(REGID(0), i, elem_bits, scalar));
	}

	return eff;
}

static RzILOpEffect *vext(cs_insn *insn, bool is_thumb) {
	if (OPCOUNT() < 2) {
		rz_warn_if_reached();
		return NULL;
	}

	// vext.8 <Vm>, <Vn>, <Vd>, #imm
	// vext.16, vext.32 are pseudo instruction of vext.8
	// objdump disasm them to vext.8 <Vm>, <Vn>, <Vd>, #imm * x
	// but capstone parse it as .16 and .32
	ut32 vec_bits = VVEC_SIZE(insn);
	ut32 imm = get_imm(insn, OPCOUNT() - 1, NULL);

	// (vec_bits * imm < reg_bits(Vd)) === True, else invalid in capstone
	ut32 shift_dist = imm * vec_bits;
	if (shift_dist >= reg_bits(REGID(0))) {
		rz_warn_if_reached();
		return NULL;
	}

	// <Vm:Vn>(start_bits: start_bits+reg_bits(Vd))
	return write_reg(REGID(0),
		UNSIGNED(reg_bits(REGID(0)),
			SHIFTR0(APPEND(REG(2), REG(1)),
				UN(8, shift_dist))));
}

static RzILOpEffect *vzip(cs_insn *insn, bool is_thumb) {
	if (OPCOUNT() < 2) {
		rz_warn_if_reached();
		return NULL;
	}

	if (REGID(0) == REGID(1)) {
		// UNKNOWN behavior
		rz_warn_if_reached();
		return EMPTY();
	}

	ut32 reg_sz = REG_WIDTH(0);
	ut32 vec_bits = VVEC_SIZE(insn);
	ut32 tmp_bits = reg_sz * 2;
	ut32 lanes = reg_sz / vec_bits;
	if (reg_sz % vec_bits != 0) {
		rz_warn_if_reached();
		return NULL;
	}

	// Assume Vd: A7, A6, A5, A4, A3, A2, A1, A0
	// Assume Vm: B7, B6, B5, B4, B3, B2, B1, B0
	// After interleave:
	// Vd: B3, A3, ... B1, A0
	// Vm: B7, A7, ... B4, A4
	RzILOpBitVector *interleaved_val = UN(tmp_bits, 0);
	for (ut32 i = 0; i < lanes; ++i) {
		RzILOpBitVector *d = UNSIGNED(tmp_bits, read_reg_lane(REGID(0), i, vec_bits));
		RzILOpBitVector *m = UNSIGNED(tmp_bits, read_reg_lane(REGID(1), i, vec_bits));
		interleaved_val = LOGOR(interleaved_val,
			SHIFTL0(LOGOR(SHIFTL0(m, UN(8, vec_bits)), d),
				UN(32, vec_bits * 2)));
	}

	return SEQ2(write_reg(REGID(0), UNSIGNED(reg_sz, DUP(interleaved_val))),
		write_reg(REGID(1), UNSIGNED(reg_sz, SHIFTR0(interleaved_val, UN(8, vec_bits)))));
}

static RzILOpEffect *vunzip(cs_insn *insn, bool is_thumb) {
	if (OPCOUNT() < 2) {
		rz_warn_if_reached();
		return NULL;
	}

	if (REGID(0) == REGID(1)) {
		// UNKNOWN behavior
		rz_warn_if_reached();
		return EMPTY();
	}

	ut32 reg_sz = REG_WIDTH(0);
	ut32 vec_bits = VVEC_SIZE(insn);
	ut32 lanes = reg_sz / vec_bits;
	if (reg_sz % vec_bits != 0) {
		rz_warn_if_reached();
		return NULL;
	}

	// Assume Vd: A7, A6, A5, A4, A3, A2, A1, A0
	// Assume Vm: B7, B6, B5, B4, B3, B2, B1, B0
	// After interleave:
	// Vd: B6, B4, B2, B0, A6, A4, A2, A0 (even)
	// Vm: B7, B5, B3, B1, A7, A5, A3, A1 (odd)
	RzILOpBitVector *deinterleave_d = UN(reg_sz, 0);
	RzILOpBitVector *deinterleave_m = UN(reg_sz, 0);
	for (ut32 i = 0; i < lanes; ++i) {
		RzILOpBitVector *d_lane = UNSIGNED(reg_sz, read_reg_lane(REGID(0), i, vec_bits));
		RzILOpBitVector *m_lane = UNSIGNED(reg_sz, read_reg_lane(REGID(1), i, vec_bits));

		// construct (Bn, 0, 0, 0, An)
		ut32 lane_shift_dist = i / 2 * vec_bits;
		d_lane = SHIFTL0(d_lane, UN(8, lane_shift_dist));
		m_lane = SHIFTL0(SHIFTL0(m_lane, UN(8, lane_shift_dist)), UN(8, reg_sz / 2));

		if (i % 2 == 0) {
			// even
			deinterleave_d = LOGOR(deinterleave_d, LOGOR(d_lane, m_lane));
		} else {
			// odd
			deinterleave_m = LOGOR(deinterleave_m, LOGOR(d_lane, m_lane));
		}
	}

	return SEQ2(write_reg(REGID(0), deinterleave_d),
		write_reg(REGID(1), deinterleave_m));
}

static RzILOpEffect *vswp(cs_insn *insn, bool is_thumb) {
	if (OPCOUNT() < 2) {
		rz_warn_if_reached();
		return NULL;
	}

	if (REGID(0) == REGID(1)) {
		// UNKNOWN
		rz_warn_if_reached();
		return EMPTY();
	}

	RzILOpBitVector *d_val = REG(0);
	RzILOpBitVector *m_val = REG(1);
	return SEQ2(write_reg(REGID(0), m_val),
		write_reg(REGID(1), d_val));
}

static RzILOpEffect *vadd(cs_insn *insn, bool is_thumb) {
	if (OPCOUNT() < 3) {
		rz_warn_if_reached();
		return NULL;
	}

	// TODO: vaddhn, vaddl, vaddw
	// determine format of float to interpret
	arm_vectordata_type dt = VVEC_DT(insn);
	RzFloatFormat fmt = dt2fmt(dt);
	bool is_float_vec = fmt == RZ_FLOAT_UNK ? false : true;

#if CS_NEXT_VERSION >= 6
	if (!rz_arm_cs_is_group_member(insn, ARM_FEATURE_HasNEON)) {
#else
	if (!rz_arm_cs_is_group_member(insn, ARM_GRP_NEON)) {
#endif
		// VFP
		return write_reg(REGID(0),
			F2BV(FADD(RZ_FLOAT_RMODE_RNE,
				BV2F(fmt, REG(1)),
				BV2F(fmt, REG(2)))));
	}

	ut32 elem_bits = DT_WIDTH(insn);
	ut32 lanes = reg_bits(REGID(0)) / elem_bits;
	if (reg_bits(REGID(0)) % elem_bits != 0) {
		rz_warn_if_reached();
		return NULL;
	}

	RzILOpEffect *eff = EMPTY();
	for (int i = 0; i < lanes; ++i) {
		RzILOpBitVector *a = read_reg_lane(REGID(1), i, elem_bits);
		RzILOpBitVector *b = read_reg_lane(REGID(2), i, elem_bits);

		RzILOpBitVector *sum = NULL;
		if (is_float_vec) {
			sum = F2BV(FADD(RZ_FLOAT_RMODE_RNE,
				BV2F(fmt, a),
				BV2F(fmt, b)));
		} else {
			sum = ADD(a, b);
		}

		eff = SEQ2(eff, write_reg_lane(REGID(0), i, elem_bits, sum));
	}

	return eff;
}

static RzILOpEffect *vsub(cs_insn *insn, bool is_thumb) {
	if (OPCOUNT() < 3) {
		rz_warn_if_reached();
		return NULL;
	}

	// TODO: vsubl, vsubw, vsubhn
	// determine format of float to interpret
	arm_vectordata_type dt = VVEC_DT(insn);
	RzFloatFormat fmt = dt2fmt(dt);
	bool is_float_vec = fmt == RZ_FLOAT_UNK ? false : true;

#if CS_NEXT_VERSION >= 6
	if (!rz_arm_cs_is_group_member(insn, ARM_FEATURE_HasNEON)) {
#else
	if (!rz_arm_cs_is_group_member(insn, ARM_GRP_NEON)) {
#endif
		// VFP
		return write_reg(REGID(0),
			F2BV(FSUB(RZ_FLOAT_RMODE_RNE,
				BV2F(fmt, REG(1)),
				BV2F(fmt, REG(2)))));
	}

	ut32 elem_bits = DT_WIDTH(insn);
	ut32 lanes = reg_bits(REGID(0)) / elem_bits;
	if (reg_bits(REGID(0)) % elem_bits != 0) {
		rz_warn_if_reached();
		return NULL;
	}

	RzILOpEffect *eff = EMPTY();
	for (int i = 0; i < lanes; ++i) {
		RzILOpBitVector *a = read_reg_lane(REGID(1), i, elem_bits);
		RzILOpBitVector *b = read_reg_lane(REGID(2), i, elem_bits);

		RzILOpBitVector *sum = NULL;
		if (is_float_vec) {
			sum = F2BV(FSUB(RZ_FLOAT_RMODE_RNE,
				BV2F(fmt, a),
				BV2F(fmt, b)));
		} else {
			sum = SUB(a, b);
		}

		eff = SEQ2(eff, write_reg_lane(REGID(0), i, elem_bits, sum));
	}

	return eff;
}

static RzILOpEffect *vmul(cs_insn *insn, bool is_thumb) {
	if (OPCOUNT() < 3) {
		rz_warn_if_reached();
		return NULL;
	}

	// determine format of float to interpret
	arm_vectordata_type dt = VVEC_DT(insn);
	RzFloatFormat fmt = dt2fmt(dt);

#if CS_NEXT_VERSION >= 6
	if (!rz_arm_cs_is_group_member(insn, ARM_FEATURE_HasNEON)) {
#else
	if (!rz_arm_cs_is_group_member(insn, ARM_GRP_NEON)) {
#endif
		// VFP fmul
		return write_reg(REGID(0),
			F2BV(FMUL(RZ_FLOAT_RMODE_RNE,
				BV2F(fmt, REG(1)),
				BV2F(fmt, REG(2)))));
	}

	// not implemented
	return EMPTY();
}

static RzILOpEffect *vldr(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0) || !ISMEM(1)) {
		rz_warn_if_reached();
		return NULL;
	}

	RzILOpBitVector *addr;
	size_t mem_idx = 1;
	cs_arm_op *memop = &insn->detail->arm.operands[mem_idx];
	if (memop->mem.base == ARM_REG_PC) {
		// LDR (literal) is different in the sense that it aligns the pc value:
		addr = arg_mem(U32(PCALIGN(insn->address, is_thumb) + MEMDISP(mem_idx)), memop, NULL);
	} else {
		addr = ARG(mem_idx);
	}
	if (!addr) {
		return NULL;
	}

	RzILOpBitVector *data = LOADW(reg_bits(REGID(0)), addr);
	return write_reg(REGID(0), data);
}

static RzILOpEffect *vstr(cs_insn *insn, bool is_thumb) {
	if (!ISREG(0) || !ISMEM(1)) {
		rz_warn_if_reached();
		return NULL;
	}

	size_t mem_idx = 1;
	RzILOpBitVector *addr = ARG(mem_idx);
	if (!addr) {
		return NULL;
	}

	RzILOpBitVector *val = REG(0);
	if (!val) {
		rz_il_op_pure_free(addr);
		return NULL;
	}

	return STOREW(addr, val);
}

static RzILOpEffect *vcmp(cs_insn *insn, bool is_thumb) {
	// VFP only
	if (OPCOUNT() < 2) {
		rz_warn_if_reached();
		return NULL;
	}

	RzILOpFloat *l = NULL;
	RzILOpFloat *r = NULL;
	RzFloatFormat fmt = dt2fmt(VVEC_DT(insn));
	if (ISIMM(1)) {
		ut64 imm = get_imm(insn, 1, NULL);
		if (imm != 0) {
			// only #0 is allowed in vcmp
			rz_warn_if_reached();
			return NULL;
		}

		r = fmt == RZ_FLOAT_IEEE754_BIN_32 ? F32(0) : F64(0);
	} else {
		r = BV2F(fmt, REG(1));
	}
	l = BV2F(fmt, REG(0));

	// only NZCV flag will change, ignore carry and overflow for float
	RzILOpBool *is_neg = FORDER(DUP(l), DUP(r));
	RzILOpBool *is_zero = FEQ(l, r);
	RzILOpBitVector *res = LOGOR(
		SHIFTL0(BOOL_TO_BV(is_neg, 32), UN(8, 31)),
		SHIFTL0(BOOL_TO_BV(is_zero, 32), UN(8, 30)));

	return SETG("fpscr", res);
}

static RzILOpEffect *vabs(cs_insn *insn, bool is_thumb) {
	// implement vabs for VFP now.
	if (OPCOUNT() < 2) {
		rz_warn_if_reached();
		return NULL;
	}

#if CS_NEXT_VERSION >= 6
	if (!rz_arm_cs_is_float_insn(insn)) {
#else
	if (!rz_arm_cs_is_group_member(insn, ARM_GRP_NEON)) {
#endif
		// not implement
		return NULL;
	}

	RzFloatFormat fmt = dt2fmt(VVEC_DT(insn));
	RzILOpFloat *abs_val = FABS(BV2F(fmt, REG(1)));
	return write_reg(REGID(0), F2BV(abs_val));
}

/**
 * Lift an ARM instruction to RzIL, without considering its condition
 *
 * Currently unimplemented:
 * - BKPT: causes a breakpoint instruction exception
 * - CLREX: clears the local monitor
 * - CPS, CPSID, CPSIE: changes interrupt mask bits and optionally PSTATE.M
 * - CRC32, CRC32C: does crc32, new feature in armv8
 * - CSDB, DMB, DSB, ESB, ISB, PSSBB, SB, SSBB: synchronization, memory barriers
 * - DCPS1, DCPS2, DCPS3: for debuggers
 * - ERET: exception return
 * - HLT: software breakpoint
 * - LDC, MCR, MRC, MRRC, STC: coprocessor instructions
 * - SETEND: switches endianness, but it's out of control of the IL
 * - SETPAN: not supported by capstone
 * - SEV, SEVL: multiprocessor event
 * - SMC: secure monitor call
 * - SRS: depends on mode, unpredictable in user mode
 * - UDF: permanently undefined
 * - WFE, WFI: wait
 */
static RzILOpEffect *il_unconditional(csh *handle, cs_insn *insn, bool is_thumb) {
	switch (insn->id) {
	// --
	// Base Instruction Set
	case ARM_INS_DBG:
#if CS_NEXT_VERSION < 6
	case ARM_INS_NOP:
#else
	case ARM_INS_HINT:
#endif
	case ARM_INS_PLD:
	case ARM_INS_PLDW:
	case ARM_INS_PLI:
		// barriers/synchronization
	case ARM_INS_DMB:
	case ARM_INS_DSB:
	case ARM_INS_ISB:
		return NOP();
	case ARM_INS_B:
	case ARM_INS_BX:
	case ARM_INS_BXJ: {
		RzILOpBitVector *dst = ARG(0);
		return dst ? JMP(dst) : NULL;
	}
	case ARM_INS_BL:
	case ARM_INS_BLX:
		return bl(insn, is_thumb);
	case ARM_INS_MOV:
#if CS_API_MAJOR > 4
	case ARM_INS_MOVS:
#endif
	case ARM_INS_MOVW:
	case ARM_INS_LSL:
	case ARM_INS_LSR:
	case ARM_INS_ASR:
	case ARM_INS_RRX:
	case ARM_INS_ROR:
	case ARM_INS_MVN:
		return mov(insn, is_thumb);
	case ARM_INS_MOVT:
		return movt(insn, is_thumb);
	case ARM_INS_ADR:
		return adr(insn, is_thumb);
	case ARM_INS_ADD:
	case ARM_INS_ADDW:
	case ARM_INS_ADC:
	case ARM_INS_SUB:
	case ARM_INS_SUBW:
	case ARM_INS_RSB:
	case ARM_INS_RSC:
	case ARM_INS_SBC:
		return add_sub(insn, is_thumb);
	case ARM_INS_MUL:
		return mul(insn, is_thumb);
	case ARM_INS_LDR:
	case ARM_INS_LDREX:
	case ARM_INS_LDRB:
	case ARM_INS_LDRH:
	case ARM_INS_LDRT:
	case ARM_INS_LDRBT:
	case ARM_INS_LDRHT:
	case ARM_INS_LDA:
	case ARM_INS_LDAB:
	case ARM_INS_LDAH:
	case ARM_INS_LDAEX:
	case ARM_INS_LDAEXB:
	case ARM_INS_LDAEXH:
	case ARM_INS_LDRD:
	case ARM_INS_LDREXD:
	case ARM_INS_LDRSB:
	case ARM_INS_LDRSBT:
	case ARM_INS_LDRSH:
	case ARM_INS_LDRSHT:
		return ldr(insn, is_thumb);
	case ARM_INS_STR:
	case ARM_INS_STRB:
	case ARM_INS_STRH:
	case ARM_INS_STRT:
	case ARM_INS_STRBT:
	case ARM_INS_STRHT:
	case ARM_INS_STL:
	case ARM_INS_STLB:
	case ARM_INS_STLH:
	case ARM_INS_STRD:
		return str(insn, is_thumb);
	case ARM_INS_STREX:
	case ARM_INS_STREXB:
	case ARM_INS_STREXD:
	case ARM_INS_STREXH:
	case ARM_INS_STLEX:
	case ARM_INS_STLEXB:
	case ARM_INS_STLEXD:
	case ARM_INS_STLEXH:
		return strex(insn, is_thumb);
	case ARM_INS_AND:
	case ARM_INS_ORR:
	case ARM_INS_ORN:
	case ARM_INS_EOR:
	case ARM_INS_BIC:
		return bitwise(insn, is_thumb);
	case ARM_INS_TST:
	case ARM_INS_TEQ:
		return tst(insn, is_thumb);
	case ARM_INS_UXTB:
	case ARM_INS_UXTAB:
	case ARM_INS_UXTH:
	case ARM_INS_UXTAH:
	case ARM_INS_SXTB:
	case ARM_INS_SXTAB:
	case ARM_INS_SXTH:
	case ARM_INS_SXTAH:
		return uxt(insn, is_thumb);
	case ARM_INS_UXTB16:
	case ARM_INS_UXTAB16:
	case ARM_INS_SXTB16:
	case ARM_INS_SXTAB16:
		return uxt16(insn, is_thumb);
	case ARM_INS_CMP:
	case ARM_INS_CMN:
		return cmp(insn, is_thumb);
	case ARM_INS_STM:
	case ARM_INS_STMDA:
	case ARM_INS_STMDB:
	case ARM_INS_PUSH:
#if CS_NEXT_VERSION < 6
	case ARM_INS_VPUSH:
#endif
	case ARM_INS_STMIB:
		return stm(insn, is_thumb);
#if CS_NEXT_VERSION < 6
	case ARM_INS_VPOP:
#endif
	case ARM_INS_POP:
	case ARM_INS_LDM:
	case ARM_INS_LDMDA:
	case ARM_INS_LDMDB:
	case ARM_INS_LDMIB:
		return ldm(insn, is_thumb);
	case ARM_INS_CLZ:
		return clz(insn, is_thumb);
	case ARM_INS_SVC:
		return svc(insn, is_thumb);
	case ARM_INS_HVC:
		return hvc(insn, is_thumb);
	case ARM_INS_BFC:
		return bfc(insn, is_thumb);
	case ARM_INS_BFI:
		return bfi(insn, is_thumb);
	case ARM_INS_CBZ:
	case ARM_INS_CBNZ:
		return cbz(insn, is_thumb);
	case ARM_INS_MLA:
	case ARM_INS_MLS:
		return mla(insn, is_thumb);
	case ARM_INS_MRS:
		return mrs(insn, is_thumb);
	case ARM_INS_MSR:
		return msr(insn, is_thumb);
	case ARM_INS_PKHBT:
	case ARM_INS_PKHTB:
		return pkhbt(insn, is_thumb);
	case ARM_INS_SSAT:
	case ARM_INS_USAT:
		return ssat(insn, is_thumb);
	case ARM_INS_SSAT16:
	case ARM_INS_USAT16:
		return ssat16(insn, is_thumb);
	case ARM_INS_QADD:
	case ARM_INS_QSUB:
	case ARM_INS_QDADD:
	case ARM_INS_QDSUB:
		return qadd(insn, is_thumb);
	case ARM_INS_QADD16:
	case ARM_INS_QSUB16:
	case ARM_INS_QASX:
	case ARM_INS_QSAX:
	case ARM_INS_UQADD16:
	case ARM_INS_UQSUB16:
	case ARM_INS_UQASX:
	case ARM_INS_UQSAX:
		return qadd16(insn, is_thumb);
	case ARM_INS_QADD8:
	case ARM_INS_QSUB8:
	case ARM_INS_UQADD8:
	case ARM_INS_UQSUB8:
		return qadd8(insn, is_thumb);
	case ARM_INS_RBIT:
		return rbit(insn, is_thumb);
	case ARM_INS_REV:
	case ARM_INS_REV16:
		return rev(insn, is_thumb);
	case ARM_INS_REVSH:
		return revsh(insn, is_thumb);
	case ARM_INS_RFEDA:
	case ARM_INS_RFEDB:
	case ARM_INS_RFEIA:
	case ARM_INS_RFEIB:
		return rfe(insn, is_thumb);
	case ARM_INS_SADD16:
	case ARM_INS_SHADD16:
	case ARM_INS_SASX:
	case ARM_INS_SSAX:
	case ARM_INS_SHASX:
	case ARM_INS_SHSAX:
	case ARM_INS_SSUB16:
	case ARM_INS_SHSUB16:
	case ARM_INS_UADD16:
	case ARM_INS_UHADD16:
	case ARM_INS_UASX:
	case ARM_INS_USAX:
	case ARM_INS_UHASX:
	case ARM_INS_UHSAX:
	case ARM_INS_USUB16:
	case ARM_INS_UHSUB16:
		return sadd16(insn, is_thumb);
	case ARM_INS_SADD8:
	case ARM_INS_SHADD8:
	case ARM_INS_SSUB8:
	case ARM_INS_SHSUB8:
	case ARM_INS_UADD8:
	case ARM_INS_UHADD8:
	case ARM_INS_USUB8:
	case ARM_INS_UHSUB8:
		return sadd8(insn, is_thumb);
	case ARM_INS_SEL:
		return sel(insn, is_thumb);
	case ARM_INS_SBFX:
	case ARM_INS_UBFX:
		return sbfx(insn, is_thumb);
	case ARM_INS_SDIV:
		return sdiv(insn, is_thumb);
	case ARM_INS_UDIV:
		return udiv(insn, is_thumb);
	case ARM_INS_UMAAL:
		return umaal(insn, is_thumb);
	case ARM_INS_UMULL:
		return umull(insn, is_thumb);
	case ARM_INS_USAD8:
	case ARM_INS_USADA8:
		return usad8(insn, is_thumb);
	case ARM_INS_SMLABB:
	case ARM_INS_SMLABT:
	case ARM_INS_SMLATB:
	case ARM_INS_SMLATT:
	case ARM_INS_SMLAD:
	case ARM_INS_SMLADX:
	case ARM_INS_SMLSD:
	case ARM_INS_SMLSDX:
		return smlabb(insn, is_thumb);
	case ARM_INS_SMLAL:
	case ARM_INS_SMLALBB:
	case ARM_INS_SMLALBT:
	case ARM_INS_SMLALTB:
	case ARM_INS_SMLALTT:
	case ARM_INS_SMLALD:
	case ARM_INS_SMLALDX:
	case ARM_INS_SMLSLD:
	case ARM_INS_SMLSLDX:
	case ARM_INS_UMLAL:
		return smlal(insn, is_thumb);
	case ARM_INS_SMLAWB:
	case ARM_INS_SMLAWT:
		return smlaw(insn, is_thumb);
	case ARM_INS_SMMLA:
	case ARM_INS_SMMLAR:
	case ARM_INS_SMMLS:
	case ARM_INS_SMMLSR:
		return smmla(insn, is_thumb);
	case ARM_INS_SMMUL:
	case ARM_INS_SMMULR:
		return smmul(insn, is_thumb);
	case ARM_INS_SMUAD:
	case ARM_INS_SMUADX:
		return smuad(insn, is_thumb);
	case ARM_INS_SMULBB:
	case ARM_INS_SMULBT:
	case ARM_INS_SMULTB:
	case ARM_INS_SMULTT:
	case ARM_INS_SMUSD:
	case ARM_INS_SMUSDX:
		return smulbb(insn, is_thumb);
	case ARM_INS_TBB:
	case ARM_INS_TBH:
		return tbb(insn, is_thumb);

	// --
	// Advanced SIMD and Floating-point
	case ARM_INS_VSTMIA:
	case ARM_INS_VSTMDB:
		return stm(insn, is_thumb);
	case ARM_INS_VLDMIA:
	case ARM_INS_VLDMDB:
		return ldm(insn, is_thumb);
#if CS_API_MAJOR > 4
	case ARM_INS_VMOVL:
	case ARM_INS_VMOVN:
	case ARM_INS_VMOVX:
#endif
	case ARM_INS_VMOV:
	case ARM_INS_VMVN:
		return vmov(insn, is_thumb);
	case ARM_INS_VMSR:
		return vmsr(insn, is_thumb);
	case ARM_INS_VMRS:
		return vmrs(insn, is_thumb);
	// NEON (advanced SIMD)
	case ARM_INS_VAND:
	case ARM_INS_VBIC:
	case ARM_INS_VORR:
	case ARM_INS_VORN:
	case ARM_INS_VEOR:
		return vbitwise(insn, is_thumb);
	case ARM_INS_VBIT:
	case ARM_INS_VBIF:
	case ARM_INS_VBSL:
		return vbit_insert(insn, is_thumb);
	case ARM_INS_VACGT:
	case ARM_INS_VACGE:
	case ARM_INS_VCEQ:
	case ARM_INS_VCGE:
	case ARM_INS_VCGT:
	case ARM_INS_VCLE:
	case ARM_INS_VCLT:
		return vec_cmp(insn, is_thumb);
	case ARM_INS_VTST:
		return vtst(insn, is_thumb);
	case ARM_INS_VLD1:
	case ARM_INS_VLD2:
	case ARM_INS_VLD3:
	case ARM_INS_VLD4:
		return vldn(insn, is_thumb);
	case ARM_INS_VST1:
	case ARM_INS_VST2:
	case ARM_INS_VST3:
	case ARM_INS_VST4:
		return vstn(insn, is_thumb);
	case ARM_INS_VCVT:
#if CS_API_MAJOR > 4
	case ARM_INS_VCVTA:
	case ARM_INS_VCVTB:
	case ARM_INS_VCVTM:
	case ARM_INS_VCVTN:
	case ARM_INS_VCVTP:
	case ARM_INS_VCVTR:
	case ARM_INS_VCVTT:
#endif
		return vcvt(insn, is_thumb);
	case ARM_INS_VDUP:
		return vdup(insn, is_thumb);
	case ARM_INS_VEXT:
		return vext(insn, is_thumb);
	case ARM_INS_VZIP:
		return vzip(insn, is_thumb);
	case ARM_INS_VUZP:
		return vunzip(insn, is_thumb);
	case ARM_INS_VSWP:
		return vswp(insn, is_thumb);
	case ARM_INS_VADD:
		return vadd(insn, is_thumb);
	case ARM_INS_VSUB:
		return vsub(insn, is_thumb);
	case ARM_INS_VMUL:
		return vmul(insn, is_thumb);
	case ARM_INS_VLDR:
		return vldr(insn, is_thumb);
	case ARM_INS_VSTR:
		return vstr(insn, is_thumb);
	case ARM_INS_VABS:
		return vabs(insn, is_thumb);
	case ARM_INS_VCMP:
		return vcmp(insn, is_thumb);
	default:
		return NULL;
	}
}

RZ_IPI RzILOpEffect *rz_arm_cs_32_il(csh *handle, cs_insn *insn, bool thumb) {
	if (insn->id == ARM_INS_IT) {
		// Note: IT is **not** a conditional branch!
		// It's currently handled in analysis_arm_cs.c using ArmCSContext as a hack to turn the following instructions
		// into conditional ones. So in the IL, we don't do anything for IT.
		return NOP();
	}
	RzILOpEffect *eff = il_unconditional(handle, insn, thumb);
	if (!eff) {
		return NULL;
	}
	RzILOpBool *c = cond(insn->detail->arm.cc);
	if (c) {
		return BRANCH(c, eff, NOP());
	}
	return eff;
}

#include <rz_il/rz_il_opbuilder_end.h>

RZ_IPI RzAnalysisILConfig *rz_arm_cs_32_il_config(bool big_endian) {
	RzAnalysisILConfig *r = rz_analysis_il_config_new(32, big_endian, 32);
	r->reg_bindings = regs_bound_32;
	RzILEffectLabel *svc_label = rz_il_effect_label_new("svc", EFFECT_LABEL_SYSCALL);
	svc_label->hook = label_svc;
	rz_analysis_il_config_add_label(r, svc_label);
	RzILEffectLabel *hvc_label = rz_il_effect_label_new("hvc", EFFECT_LABEL_SYSCALL);
	hvc_label->hook = label_hvc;
	rz_analysis_il_config_add_label(r, hvc_label);
	return r;
}
