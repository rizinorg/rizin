// SPDX-FileCopyrightText: 2025 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "sparc_il.h"
#include <rz_il/rz_il_opcodes.h>

#include "capstone.h"
#include "rz_il/rz_il_opbuilder_begin.h"
#include "rz_util/rz_assert.h"

#if CS_API_MAJOR >= 6
/**
 * \brief All registers we bind to the RzIL VM.
 * They are the same as for the 64bit reg profile, but without npc and pc.
 */
static const char *il_regs64[] = {
	"y", "asr", "fsr", "csr", "asi", "g0", "g1", "g2",
	"g3", "g4", "g5", "g6", "g7", "o0", "o1", "o2", "o3",
	"o4", "o5", "sp", "o7", "l0", "l1", "l2", "l3", "l4",
	"l5", "l6", "l7", "i0", "i1", "i2", "i3", "i4", "i5",
	"fp", "i7", "ccr", "tpc", "tnpc", "tstate", "tt", "tick", "tba",
	"pstate", "tl", "pil", "cwp", "cansave", "canrestore", "cleanwin", "otherwin", "wstate",
	"fq", "ver", "f0", "f1", "f2", "f3", "f4", "f5", "f6",
	"f7", "f8", "f9", "f10", "f11", "f12", "f13", "f14", "f15",
	"f16", "f17", "f18", "f19", "f20", "f21", "f22", "f23", "f24",
	"f25", "f26", "f27", "f28", "f29", "f30", "f31", "f32", "f34",
	"f36", "f38", "f40", "f42", "f44", "f46", "f48", "f50", "f52",
	"f54", "f56", "f58", "f60", "f62", "gsr", "fprs", "asr0", "asr1",
	"asr2", "asr3", "asr4", "asr5", "asr6", "asr7", "asr8", "asr9", "asr10",
	"asr11", "asr12", "asr13", "asr14", "asr15", "asr16", "asr17", "asr18", "asr19",
	"asr20", "asr21", "asr22", "asr23", "asr24", "asr25", "asr26", "asr27", "asr28",
	"asr29", "asr30", "asr31", NULL
};

/**
 * \brief All registers we bind to the RzIL VM.
 * They are the same as for the 32bit reg profile, but without npc and pc.
 */
static const char *il_regs32[] = {
	"psr", "y", "tbr", "wim", "asr", "fsr",
	"csr", "asi", "g0", "g1", "g2", "g3", "g4", "g5", "g6",
	"g7", "o0", "o1", "o2", "o3", "o4", "o5", "sp", "o7",
	"l0", "l1", "l2", "l3", "l4", "l5", "l6", "l7", "i0",
	"i1", "i2", "i3", "i4", "i5", "fp", "i7", "ccr", "tpc",
	"tnpc", "tstate", "tt", "tick", "tba", "pstate", "tl", "pil", "cwp",
	"cansave", "canrestore", "cleanwin", "otherwin", "wstate", "fq", "ver", "f0", "f1",
	"f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "f10",
	"f11", "f12", "f13", "f14", "f15", "f16", "f17", "f18", "f19",
	"f20", "f21", "f22", "f23", "f24", "f25", "f26", "f27", "f28",
	"f29", "f30", "f31", "fprs", "asr0", "asr1", "asr2", "asr3", "asr4", "asr5",
	"asr6", "asr7", "asr8", "asr9", "asr10", "asr11", "asr12", "asr13", "asr14",
	"asr15", "asr16", "asr17", "asr18", "asr19", "asr20", "asr21", "asr22", "asr23",
	"asr24", "asr25", "asr26", "asr27", "asr28", "asr29", "asr30", "asr31", NULL
};

// clang-format off
static const char *float_regs[] = {
  "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",
  "f8", "f9", "f10", "f11", "f12", "f13", "f14", "f15",
  "f16", "f17", "f18", "f19", "f20", "f21", "f22", "f23",
  "f24", "f25", "f26", "f27", "f28", "f29", "f30", "f31",
  "f32", "<undef>", "f34", "<undef>", "f36", "<undef>", "f38", "<undef>",
  "f40", "<undef>", "f42", "<undef>", "f44", "<undef>", "f46", "<undef>",
  "f48", "<undef>", "f50", "<undef>", "f52", "<undef>", "f54", "<undef>",
  "f56", "<undef>", "f58", "<undef>", "f60", "<undef>", "f62", "<undef>",
};
// clang-format on

static void label_trap(RzILVM *vm, RzILOpEffect *op) {
	RZ_LOG_WARN("VM runtime trap: general handler (trap ignored).\n");
	// stub, nothing to do here
}

static void label_fp_exception(RzILVM *vm, RzILOpEffect *op) {
	RZ_LOG_WARN("VM runtime FP exception: general handler (exception ignored).\n");
	// stub, nothing to do here
}

static void sparc_il_init(RzAnalysisILVM *vm, RzReg *reg, size_t addr_width) {
	// Init the memory for backing up the register window.
	RzBuffer *buf = rz_buf_new_sparse(0);
	if (!buf) {
		return;
	}
	RzILMem *mem = rz_il_mem_new_owned(buf, addr_width);
	if (!mem) {
		rz_buf_free(buf);
		return;
	}
	rz_il_vm_add_mem(vm->vm, SPARC_ASI_INDEX_RW, mem);
}

static void sparc_il_init_64_cb(RzAnalysisILVM *vm, RzReg *reg) {
	sparc_il_init(vm, reg, 64);
}

static void sparc_il_init_32_cb(RzAnalysisILVM *vm, RzReg *reg) {
	sparc_il_init(vm, reg, 32);
}

RZ_IPI RzAnalysisILConfig *rz_sparc_cs_64_il_config(bool big_endian) {
	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(64, big_endian, 64);
	cfg->reg_bindings = il_regs64;
	RzILEffectLabel *trap_label = rz_il_effect_label_new("trap", EFFECT_LABEL_SYSCALL);
	trap_label->hook = label_trap;
	rz_analysis_il_config_add_label(cfg, trap_label);

	cfg->init_state = rz_analysis_il_init_state_new();
	if (!cfg->init_state) {
		rz_analysis_il_config_free(cfg);
		return NULL;
	}
	RzAnalysisILInitStateVar var = {
		.name = "cwp",
		// Most CPUs have 8 windows.
		.val = rz_il_value_new_bitv(rz_bv_new_from_ut64(64, SPARC_NWINDOWS))
	};
	rz_vector_push(&cfg->init_state->vars, &var);

	RzILEffectLabel *fp_exception_label = rz_il_effect_label_new("fp_exception", EFFECT_LABEL_SYSCALL);
	fp_exception_label->hook = label_fp_exception;
	rz_analysis_il_config_add_label(cfg, fp_exception_label);

	cfg->init_state->cb = sparc_il_init_64_cb;
	return cfg;
}

RZ_IPI RzAnalysisILConfig *rz_sparc_cs_32_il_config(bool big_endian) {
	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(32, big_endian, 32);
	cfg->reg_bindings = il_regs32;
	RzILEffectLabel *trap_label = rz_il_effect_label_new("trap", EFFECT_LABEL_SYSCALL);
	trap_label->hook = label_trap;
	rz_analysis_il_config_add_label(cfg, trap_label);

	cfg->init_state = rz_analysis_il_init_state_new();
	if (!cfg->init_state) {
		rz_analysis_il_config_free(cfg);
		return NULL;
	}
	RzAnalysisILInitStateVar var = {
		.name = "cwp",
		// Most CPUs have 8 windows.
		.val = rz_il_value_new_bitv(rz_bv_new_from_ut64(32, SPARC_NWINDOWS))
	};
	rz_vector_push(&cfg->init_state->vars, &var);

	RzILEffectLabel *fp_exception_label = rz_il_effect_label_new("fp_exception", EFFECT_LABEL_SYSCALL);
	fp_exception_label->hook = label_fp_exception;
	rz_analysis_il_config_add_label(cfg, fp_exception_label);

	cfg->init_state->cb = sparc_il_init_32_cb;
	return cfg;
}

/**
 * \brief Float registers (F0-F61) are not defined as such in Capstone.
 * From F32 onward only the ones with even index are defined.
 * Not in the RzIL VM of course. So we need this getter for register names.
 */
RZ_IPI const char *rz_sparc_get_next_reg_name(const csh handle, sparc_reg base_reg, size_t offset) {
	size_t reg_num = 0;
	if (!is_float_reg(base_reg)) {
		if (RZ_BETWEEN(SPARC_REG_G0_G1, base_reg, SPARC_REG_G6_G7)) {
			reg_num = SPARC_REG_G0 + ((base_reg - SPARC_REG_G0_G1) * 2) + offset;
		} else if (RZ_BETWEEN(SPARC_REG_O0_O1, base_reg, SPARC_REG_O6_O7)) {
			reg_num = SPARC_REG_O0 + ((base_reg - SPARC_REG_O0_O1) * 2) + offset;
		} else if (RZ_BETWEEN(SPARC_REG_L0_L1, base_reg, SPARC_REG_L6_L7)) {
			reg_num = SPARC_REG_L0 + ((base_reg - SPARC_REG_L0_L1) * 2) + offset;
		} else if (RZ_BETWEEN(SPARC_REG_I0_I1, base_reg, SPARC_REG_I6_I7)) {
			reg_num = SPARC_REG_I0 + ((base_reg - SPARC_REG_I0_I1) * 2) + offset;
		} else {
			reg_num = base_reg + offset;
		}
		const char *regname = cs_reg_name(handle, reg_num);
		if (!regname) {
			rz_warn_if_reached();
			return NULL;
		}
		return regname;
	}
	if (RZ_BETWEEN(SPARC_REG_F0, base_reg, SPARC_REG_F31)) {
		reg_num = base_reg - SPARC_REG_F0 + offset;
	} else if (RZ_BETWEEN(SPARC_REG_D0, base_reg, SPARC_REG_D31)) {
		reg_num = ((base_reg - SPARC_REG_D0) * 2) + offset;
	} else if (RZ_BETWEEN(SPARC_REG_Q0, base_reg, SPARC_REG_Q15)) {
		reg_num = ((base_reg - SPARC_REG_Q0) * 4) + offset;
	} else {
		rz_warn_if_reached();
		return NULL;
	}
	if (reg_num > RZ_ARRAY_SIZE(float_regs)) {
		rz_warn_if_reached();
		return NULL;
	}
	return float_regs[reg_num];
}

/**
 * \brief Moves \p bv into the consecutive registers starting at \p dst_reg.
 * This is mostly used by floating point instructions to copy one bit vector
 * into multiple consecutive registers.
 * If the destination registers are FPU registers it updates the FPRS flag accorgingly.
 *
 * Normal GPR registers (o, l, i) work as well.
 *
 * The least significant bytes of the bit vector are copied to the registers
 * with the smallest number.
 */
RZ_IPI RzILOpEffect *rz_sparc_bv_to_consec_regs(const csh handle, cs_mode mode, sparc_reg dst_reg, RzILOpBitVector *bv, size_t width) {
	RzILOpEffect *set_seq = NULL;

	if (width == SPARC_HALF_WORD) {
		const char *freg = rz_sparc_get_next_reg_name(handle, dst_reg, 0);
		if (!freg) {
			rz_warn_if_reached();
			return NULL;
		}
		set_seq = SSETG(freg, UNSIGNED(32, bv));
		return set_seq;
	}
	bool is_v8_freg_dst = is_v8_reg(dst_reg);
	size_t decrement = is_v8_freg_dst ? 1 : 2;
	// Low significant bits are in the high regs.
	for (int i = (width / SPARC_WORD) - decrement, j = 0; i >= 0; i -= decrement, j += decrement) {
		const char *freg = rz_sparc_get_next_reg_name(handle, dst_reg, i);
		if (!freg) {
			rz_warn_if_reached();
			return NULL;
		}
		size_t width = is_v8_freg_dst ? 32 : 64;
		if (!set_seq) {
			set_seq = SEQ2(SETL("bv", bv), SSETG(freg, UNSIGNED(width, VARL("bv"))));
		} else {
			set_seq = SEQ2(set_seq, SSETG(freg, UNSIGNED(width, SHIFTR0(VARL("bv"), U8(SPARC_WORD * j)))));
		}
	}
	if (!set_seq) {
		// This is the special case \p width < sizeof(dst_reg).
		// E.g. if a 32bit values should be assigned to an upper 64bit FP reg.
		rz_warn_if_fail(width <= SPARC_WORD && !is_v8_freg_dst);
		const char *freg = rz_sparc_get_next_reg_name(handle, dst_reg, 0);
		set_seq = SSETG(freg, UNSIGNED(64, bv));
	}
	rz_warn_if_fail(set_seq);
	return set_seq;
}

/**
 * \brief Casts a float to a bit vector and copies it into the consecutive registers
 * starting at \p dst_reg.
 */
RZ_IPI RzILOpEffect *rz_sparc_fpure_to_freg(const csh handle, cs_mode mode, sparc_reg dst_reg, RzILOpFloat *src, size_t width) {
	RzILOpBitVector *bv = F2BV(src);
	return rz_sparc_bv_to_consec_regs(handle, mode, dst_reg, bv, width);
}

RZ_IPI RzILOpPure *rz_sparc_freg_to_fpure(const csh handle, sparc_reg base_reg, size_t width) {
	if (width == SPARC_HALF_WORD) {
		const char *freg = rz_sparc_get_next_reg_name(handle, base_reg, 0);
		if (!freg) {
			return NULL;
		}
		return FLOATV16(VARG(freg));
	}
	bool is_lower_float = is_float_lower(base_reg);
	RzILOpBitVector *bv = NULL;
	for (size_t i = 0; i < width / SPARC_WORD; i += is_lower_float ? 1 : 2) {
		const char *freg = rz_sparc_get_next_reg_name(handle, base_reg, i);
		if (!freg) {
			return NULL;
		}
		bv = !bv ? VARG(freg) : APPEND(bv, VARG(freg));
	}
	switch (width) {
	default:
		break;
	case SPARC_WORD:
		return FLOATV32(bv);
	case SPARC_DOUBLE_WORD:
		return FLOATV64(bv);
	case SPARC_QUAD_WORD:
		return FLOATV128(bv);
	}
	rz_il_op_pure_free(bv);
	rz_warn_if_reached();
	return NULL;
}

static RzILOpPure *get_reg_as_varg(RZ_BORROW csh handle, sparc_reg reg) {
	const char *reg_name = cs_reg_name(handle, reg);
	if (!reg_name) {
		RZ_LOG_ERROR("Getting register name failed.\n");
		return NULL;
	}
	return VARG(reg_name);
}

/**
 * \brief Return the operand[i] as RzILOpPure or NULL in vase of failure.
 * Immediates will always be a s64 because this is the type Capstone defines it.
 * Memory addresses are always the architecture width (32 or 64bit), depending on \p mode.
 *
 * Float registers will be returned as floating point number. Not as bit vector.
 *
 * \param handle The Capstone handle.
 * \param insn The Capstone instruction.
 * \param mode The current Capstone mode.
 * \param i The index of the operand in \p insn.
 * \param freg_to_float If >0 it will convert float registers to float values of this width.
 * If it is 0 or the operand is not a float register, it will return them as bitvector.
 *
 * \return The pure representing the operand.
 */
RZ_IPI RzILOpPure *rz_sparc_cs_get_operand(RZ_BORROW csh handle, const cs_insn *insn, cs_mode mode, size_t i, size_t float_width) {
	rz_return_val_if_fail(insn, NULL);
	if (insn->detail->sparc.op_count <= i) {
		RZ_LOG_ERROR("Invalid read of not exisiting operand[%" PFMTSZd "].\n", i);
		return NULL;
	}
	const cs_sparc_op *op = &INSOP(i);
	switch (op->type) {
	default:
		RZ_LOG_ERROR("Unhandled Sparc oprand type.\n");
		return NULL;
	case SPARC_OP_REG:
		if (op->reg == SPARC_REG_ASR5) {
			// PC
			return UA(insn->address);
		} else if (!is_float_reg(op->reg) || float_width == 0) {
			return get_reg_as_varg(handle, op->reg);
		}
		return rz_sparc_freg_to_fpure(handle, op->reg, float_width);
	case SPARC_OP_IMM:
		return S64(op->imm);
	case SPARC_OP_MEM: {
		RzILOpPure *base = get_reg_as_varg(handle, op->mem.base);
		if (!base || (op->mem.disp == 0 && op->mem.index == SPARC_REG_INVALID)) {
			return base;
		} else if (op->mem.disp != 0) {
			return ADD(base, SA(op->mem.disp));
		} else if (op->mem.index != SPARC_REG_INVALID) {
			RzILOpPure *index = get_reg_as_varg(handle, op->mem.index);
			return ADD(base, index);
		}
		return base;
	}
	}
}

/**
 * \brief Sets the given bits in the CCR register to the Bool value.
 * Values can be NULL if they should stay unchanged.
 * At least one flag must be not NULL.
 *
 * \param icc_c The icc c bit = CCR[0].
 * \param icc_v The icc v bit = CCR[1].
 * \param icc_z The icc z bit = CCR[2].
 * \param icc_n The icc n bit = CCR[3].
 * \param xcc_c The xcc c bit = CCR[4].
 * \param xcc_v The xcc v bit = CCR[5].
 * \param xcc_z The xcc z bit = CCR[6].
 * \param xcc_n The xcc n bit = CCR[7].
 *
 * \return The effect sequence setting all given bits to the value of the Bool.
 * Or NULL in case of failure.
 */
RZ_IPI RzILOpEffect *rz_sparc_set_ccr_flags(RzILOpBool *icc_c, RzILOpBool *icc_v, RzILOpBool *icc_z, RzILOpBool *icc_n,
	RzILOpBool *xcc_c, RzILOpBool *xcc_v, RzILOpBool *xcc_z, RzILOpBool *xcc_n) {
	// At least one should be set.
	rz_return_val_if_fail((icc_c || icc_v || icc_z || icc_n || xcc_c || xcc_v || xcc_z || xcc_n), NULL);
	RzILOpEffect *seq = NULL;

	if (icc_c && icc_v && icc_z && icc_n && xcc_c && xcc_v && xcc_z && xcc_n) {
		// If all are set, we can deglutter the whole RzIL expression
		// a little bit.
		seq = SETG("ccr",
			LOGOR(ITE(icc_c, U8(1), U8(0)),
				LOGOR(SHIFTL0(ITE(icc_v, U8(1), U8(0)), U8(1)),
					LOGOR(SHIFTL0(ITE(icc_z, U8(1), U8(0)), U8(2)),
						LOGOR(SHIFTL0(ITE(icc_n, U8(1), U8(0)), U8(3)),
							LOGOR(SHIFTL0(ITE(xcc_c, U8(1), U8(0)), U8(4)),
								LOGOR(SHIFTL0(ITE(xcc_v, U8(1), U8(0)), U8(5)),
									LOGOR(SHIFTL0(ITE(xcc_z, U8(1), U8(0)), U8(6)),
										SHIFTL0(ITE(xcc_n, U8(1), U8(0)), U8(7))))))))));
		return seq;
	}

	if (icc_c) {
		seq = SETG("ccr", ITE(icc_c, LOGOR(VARG("ccr"), U8(1 << 0)), LOGAND(VARG("ccr"), LOGNOT(U8(1 << 0)))));
	}
	if (icc_v) {
		RzILOpEffect *w_icc_v = SETG("ccr", ITE(icc_v, LOGOR(VARG("ccr"), U8(1 << 1)), LOGAND(VARG("ccr"), LOGNOT(U8(1 << 1)))));
		seq = seq ? SEQ2(seq, w_icc_v) : w_icc_v;
	}
	if (icc_z) {
		RzILOpEffect *w_icc_z = SETG("ccr", ITE(icc_z, LOGOR(VARG("ccr"), U8(1 << 2)), LOGAND(VARG("ccr"), LOGNOT(U8(1 << 2)))));
		seq = seq ? SEQ2(seq, w_icc_z) : w_icc_z;
	}
	if (icc_n) {
		RzILOpEffect *w_icc_n = SETG("ccr", ITE(icc_n, LOGOR(VARG("ccr"), U8(1 << 3)), LOGAND(VARG("ccr"), LOGNOT(U8(1 << 3)))));
		seq = seq ? SEQ2(seq, w_icc_n) : w_icc_n;
	}
	if (xcc_c) {
		RzILOpEffect *w_xcc_c = SETG("ccr", ITE(xcc_c, LOGOR(VARG("ccr"), U8(1 << 4)), LOGAND(VARG("ccr"), LOGNOT(U8(1 << 4)))));
		seq = seq ? SEQ2(seq, w_xcc_c) : w_xcc_c;
	}
	if (xcc_v) {
		RzILOpEffect *w_xcc_v = SETG("ccr", ITE(xcc_v, LOGOR(VARG("ccr"), U8(1 << 5)), LOGAND(VARG("ccr"), LOGNOT(U8(1 << 5)))));
		seq = seq ? SEQ2(seq, w_xcc_v) : w_xcc_v;
	}
	if (xcc_z) {
		RzILOpEffect *w_xcc_z = SETG("ccr", ITE(xcc_z, LOGOR(VARG("ccr"), U8(1 << 6)), LOGAND(VARG("ccr"), LOGNOT(U8(1 << 6)))));
		seq = seq ? SEQ2(seq, w_xcc_z) : w_xcc_z;
	}
	if (xcc_n) {
		RzILOpEffect *w_xcc_n = SETG("ccr", ITE(xcc_n, LOGOR(VARG("ccr"), U8(1 << 7)), LOGAND(VARG("ccr"), LOGNOT(U8(1 << 7)))));
		seq = seq ? SEQ2(seq, w_xcc_n) : w_xcc_n;
	}
	return seq;
}

RZ_IPI RZ_OWN RzILOpBool *add_overflow(RZ_OWN RzILOpBitVector *a, RZ_OWN RzILOpBitVector *b, RZ_OWN RzILOpBitVector *res) {
	return AND(INV(XOR(MSB(a), MSB(b))), XOR(MSB(DUP(a)), MSB(res)));
}

RZ_IPI RZ_OWN RzILOpBool *sub_overflow(RZ_OWN RzILOpBitVector *a, RZ_OWN RzILOpBitVector *b, RZ_OWN RzILOpBitVector *res) {
	return AND(XOR(MSB(a), MSB(b)), XOR(MSB(DUP(a)), MSB(res)));
}

/**
 * \brief Builds a Pure operation which performs `il_op(arg0, arg1)` and sets the CCR flags
 * in %icc and $xcc.
 * It will write the result into the local variable `res128`.
 *
 * \param arg0 The first argument passed to \p il_op.
 * \param arg1 The second argument passed to \p il_op.
 * \param bits The bits to set/unset/ignore.
 *
 * \return The sequence to calculating the result and setting icc/xcc accordingly.
 * Or NULL in case of failure.
 */
RZ_IPI RzILOpEffect *rz_sparc_2args_ccr(RzSparcCCROp op, RzILOpPure *arg0, RzILOpPure *arg1, RZ_NULLABLE RzILOpBool *carry_bit, RzSparcCCRBits *bits) {
	rz_return_val_if_fail(arg0 && arg1, NULL);
	RzILOpEffect *set_args = NULL;
	if (op == RZ_SPARC_CCR_OP_SDIV || op == RZ_SPARC_CCR_OP_SMUL) {
		set_args = SEQ2(SETL("arg0", SIGNED(128, arg0)), SETL("arg1", SIGNED(128, arg1)));
	} else {
		set_args = SEQ2(SETL("arg0", UNSIGNED(128, arg0)), SETL("arg1", UNSIGNED(128, arg1)));
	}
	if (carry_bit) {
		set_args = SEQ2(set_args, SETL("carry_bit", BOOL_TO_BV(carry_bit, 128)));
	}
	rz_il_pure_2args_op *il_op;
	RzILOpEffect *ov32 = NULL;
	RzILOpEffect *ov64 = NULL;
	RzILOpEffect *carry32 = NULL;
	RzILOpEffect *carry64 = NULL;
	switch (op) {
	default:
		rz_warn_if_reached();
		return NULL;
	case RZ_SPARC_CCR_OP_AND:
		il_op = rz_il_op_new_log_and;
		ov32 = EMPTY();
		ov64 = EMPTY();
		break;
	case RZ_SPARC_CCR_OP_OR:
		il_op = rz_il_op_new_log_or;
		ov32 = EMPTY();
		ov64 = EMPTY();
		break;
	case RZ_SPARC_CCR_OP_XOR:
		il_op = rz_il_op_new_log_xor;
		ov32 = EMPTY();
		ov64 = EMPTY();
		break;
	case RZ_SPARC_CCR_OP_UMUL:
	case RZ_SPARC_CCR_OP_SMUL:
		il_op = rz_il_op_new_mul;
		ov32 = EMPTY();
		ov64 = EMPTY();
		break;
	case RZ_SPARC_CCR_OP_ADD:
		il_op = rz_il_op_new_add;
		carry32 = SETL("carry32", XOR(XOR(BIT(32, VARL("arg0")), BIT(32, VARL("arg1"))), BIT(32, VARL("res128"))));
		carry64 = SETL("carry64", BIT(64, VARL("res128"))),
		ov32 = SETL("overflow32", add_overflow(UNSIGNED(32, VARL("arg0")), UNSIGNED(32, VARL("arg1")), UNSIGNED(32, VARL("res128"))));
		ov64 = SETL("overflow64", add_overflow(UNSIGNED(64, VARL("arg0")), UNSIGNED(64, VARL("arg1")), UNSIGNED(64, VARL("res128"))));
		break;
	case RZ_SPARC_CCR_OP_SUB:
		il_op = rz_il_op_new_sub;
		carry32 = SETL("carry32", OR(ULT(UNSIGNED(32, VARL("arg0")), UNSIGNED(32, VARL("arg1"))), carry_bit ? ULT(UNSIGNED(32, VARL("res128_mid")), UNSIGNED(32, VARL("carry_bit"))) : IL_FALSE)),
		carry64 = SETL("carry64", OR(ULT(UNSIGNED(64, VARL("arg0")), UNSIGNED(64, VARL("arg1"))), carry_bit ? ULT(UNSIGNED(64, VARL("res128_mid")), UNSIGNED(64, VARL("carry_bit"))) : IL_FALSE)),
		ov32 = SETL("overflow32", sub_overflow(UNSIGNED(32, VARL("arg0")), UNSIGNED(32, VARL("arg1")), UNSIGNED(32, VARL("res128"))));
		ov64 = SETL("overflow64", sub_overflow(UNSIGNED(64, VARL("arg0")), UNSIGNED(64, VARL("arg1")), UNSIGNED(64, VARL("res128"))));
		break;
	case RZ_SPARC_CCR_OP_UDIV:
		il_op = rz_il_op_new_div;
		ov32 = SETL("overflow32", UGE(VARL("res128"), UN(128, 0x100000000ull)));
		ov64 = EMPTY();
		break;
	case RZ_SPARC_CCR_OP_SDIV:
		il_op = rz_il_op_new_sdiv;
		ov32 = SETL("overflow32", OR(SGE(VARL("res128"), SN(128, 0x80000000)), SLE(VARL("res128"), SN(128, -0x7fffffff))));
		ov64 = EMPTY();
		break;
	}
	RzILOpEffect *res128 = NULL;
	res128 = SETL("res128_mid", il_op(VARL("arg0"), VARL("arg1")));
	if (carry_bit) {
		res128 = SEQ2(res128, SETL("res128", il_op(VARL("res128_mid"), VARL("carry_bit"))));
	} else {
		res128 = SEQ2(res128, SETL("res128", VARL("res128_mid")));
	}
	RzILOpEffect *set_ccr = rz_sparc_set_ccr_flags(
		bits->icc_c == RZ_SPARC_CC_UPDATE ? VARL("carry32") : (bits->icc_c == RZ_SPARC_CC_UNSET ? IL_FALSE : NULL),
		bits->icc_v == RZ_SPARC_CC_UPDATE ? VARL("overflow32") : (bits->icc_v == RZ_SPARC_CC_UNSET ? IL_FALSE : NULL),
		bits->icc_z == RZ_SPARC_CC_UPDATE ? VARL("is_zero32") : (bits->icc_z == RZ_SPARC_CC_UNSET ? IL_FALSE : NULL),
		bits->icc_n == RZ_SPARC_CC_UPDATE ? VARL("is_neg32") : (bits->icc_n == RZ_SPARC_CC_UNSET ? IL_FALSE : NULL),
		bits->xcc_c == RZ_SPARC_CC_UPDATE ? VARL("carry64") : (bits->xcc_c == RZ_SPARC_CC_UNSET ? IL_FALSE : NULL),
		bits->xcc_v == RZ_SPARC_CC_UPDATE ? VARL("overflow64") : (bits->xcc_v == RZ_SPARC_CC_UNSET ? IL_FALSE : NULL),
		bits->xcc_z == RZ_SPARC_CC_UPDATE ? VARL("is_zero64") : (bits->xcc_z == RZ_SPARC_CC_UNSET ? IL_FALSE : NULL),
		bits->xcc_n == RZ_SPARC_CC_UPDATE ? VARL("is_neg64") : (bits->xcc_n == RZ_SPARC_CC_UNSET ? IL_FALSE : NULL));
	if (!set_ccr) {
		rz_warn_if_reached();
		return NULL;
	}
	RzILOpEffect *update_ccr = SEQ9(
		bits->icc_z == RZ_SPARC_CC_UPDATE ? SETL("is_zero32", IS_ZERO(UNSIGNED(32, VARL("res128")))) : EMPTY(),
		bits->xcc_z == RZ_SPARC_CC_UPDATE ? SETL("is_zero64", IS_ZERO(UNSIGNED(64, VARL("res128")))) : EMPTY(),
		bits->icc_n == RZ_SPARC_CC_UPDATE ? SETL("is_neg32", BIT(31, VARL("res128"))) : EMPTY(),
		bits->xcc_n == RZ_SPARC_CC_UPDATE ? SETL("is_neg64", BIT(63, VARL("res128"))) : EMPTY(),
		ov32,
		ov64,
		carry32 ? carry32 : EMPTY(),
		carry64 ? carry64 : EMPTY(),
		set_ccr);
	if (!res128 || !update_ccr || !set_args) {
		rz_warn_if_reached();
		return NULL;
	}

	return SEQ3(set_args, res128, update_ccr);
}

/**
 * \brief G0 is never anything else than 0. This sets the global variable
 * only if it is != g0.
 * Registers alias not existing in Capstone are translated.
 * E.g. register GSR is an alias for ASR19. Capstone only knows ASR19.
 * So if "asr19" is passed, it will write to global variable GSR instead.
 *
 * \param gname The global variable name.
 * \param gval The varable the global variable should be set to.
 *
 * \return EMPTY() if gname == "g0", otherwise SETG(gname, gval).
 */
RZ_IPI RzILOpEffect *rz_sparc_set_g(const char *gname, RzILOpPure *gval) {
	if (RZ_STR_EQ(gname, "g0")) {
		rz_il_op_pure_free(gval);
		return EMPTY();
	} else if (RZ_STR_EQ(gname, "asr19")) {
		return SETG("gsr", gval);
	}

	RzILOpEffect *set_seq = SETG(gname, gval);
	if (gname[0] == 'f' && IS_DIGIT(gname[1])) {
		// Float reg, check if FPRS bits need to be set.
		bool is_upper = atoi(gname + 1) >= 32;
		return SEQ2(set_seq, SET_BIT(is_upper ? 1 : 0, "fprs", 3));
	}

	return set_seq;
}
#endif

#include "rz_il/rz_il_opbuilder_end.h"
