// SPDX-FileCopyrightText: 2013-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_lib.h>
#include <ht_uu.h>
#include <arm.h>
#include <capstone.h>
#include <arm.h>
#include <rz_util/rz_assert.h>
#include "./analysis_arm_hacks.inc"

#include "../arch/arm/arm_cs.h"
#include "../arch/arm/arm_accessors32.h"
#include "../arch/arm/arm_accessors64.h"
#include "../../asm/arch/arm/arm_it.h"

typedef struct arm_cs_context_t {
	RzArmITContext it;
	csh handle;
	int omode;
	int obits;
} ArmCSContext;

static const char *shift_type_name(arm_shifter type) {
	switch (type) {
	case ARM_SFT_ASR:
		return "asr";
	case ARM_SFT_LSL:
		return "lsl";
	case ARM_SFT_LSR:
		return "lsr";
	case ARM_SFT_ROR:
		return "ror";
	case ARM_SFT_RRX:
		return "rrx";
	case ARM_SFT_ASR_REG:
		return "asr_reg";
	case ARM_SFT_LSL_REG:
		return "lsl_reg";
	case ARM_SFT_LSR_REG:
		return "lsr_reg";
	case ARM_SFT_ROR_REG:
		return "ror_reg";
	case ARM_SFT_RRX_REG:
		return "rrx_reg";
	default:
		return "";
	}
}

static const char *vector_data_type_name(arm_vectordata_type type) {
	switch (type) {
	case ARM_VECTORDATA_I8:
		return "i8";
	case ARM_VECTORDATA_I16:
		return "i16";
	case ARM_VECTORDATA_I32:
		return "i32";
	case ARM_VECTORDATA_I64:
		return "i64";
	case ARM_VECTORDATA_S8:
		return "s8";
	case ARM_VECTORDATA_S16:
		return "s16";
	case ARM_VECTORDATA_S32:
		return "s32";
	case ARM_VECTORDATA_S64:
		return "s64";
	case ARM_VECTORDATA_U8:
		return "u8";
	case ARM_VECTORDATA_U16:
		return "u16";
	case ARM_VECTORDATA_U32:
		return "u32";
	case ARM_VECTORDATA_U64:
		return "u64";
	case ARM_VECTORDATA_P8:
		return "p8";
	case ARM_VECTORDATA_F32:
		return "f32";
	case ARM_VECTORDATA_F64:
		return "f64";
	case ARM_VECTORDATA_F16F64:
		return "f16.f64";
	case ARM_VECTORDATA_F64F16:
		return "f64.f16";
	case ARM_VECTORDATA_F32F16:
		return "f32.f16";
	case ARM_VECTORDATA_F16F32:
		return "f16.f32";
	case ARM_VECTORDATA_F64F32:
		return "f64.f32";
	case ARM_VECTORDATA_F32F64:
		return "f32.f64";
	case ARM_VECTORDATA_S32F32:
		return "s32.f32";
	case ARM_VECTORDATA_U32F32:
		return "u32.f32";
	case ARM_VECTORDATA_F32S32:
		return "f32.s32";
	case ARM_VECTORDATA_F32U32:
		return "f32.u32";
	case ARM_VECTORDATA_F64S16:
		return "f64.s16";
	case ARM_VECTORDATA_F32S16:
		return "f32.s16";
	case ARM_VECTORDATA_F64S32:
		return "f64.s32";
	case ARM_VECTORDATA_S16F64:
		return "s16.f64";
	case ARM_VECTORDATA_S16F32:
		return "s16.f64";
	case ARM_VECTORDATA_S32F64:
		return "s32.f64";
	case ARM_VECTORDATA_U16F64:
		return "u16.f64";
	case ARM_VECTORDATA_U16F32:
		return "u16.f32";
	case ARM_VECTORDATA_U32F64:
		return "u32.f64";
	case ARM_VECTORDATA_F64U16:
		return "f64.u16";
	case ARM_VECTORDATA_F32U16:
		return "f32.u16";
	case ARM_VECTORDATA_F64U32:
		return "f64.u32";
	default:
		return "";
	}
}

static const char *cc_name(arm_cc cc) {
	switch (cc) {
	case ARM_CC_EQ: // Equal                      Equal
		return "eq";
	case ARM_CC_NE: // Not equal                  Not equal, or unordered
		return "ne";
	case ARM_CC_HS: // Carry set                  >, ==, or unordered
		return "hs";
	case ARM_CC_LO: // Carry clear                Less than
		return "lo";
	case ARM_CC_MI: // Minus, negative            Less than
		return "mi";
	case ARM_CC_PL: // Plus, positive or zero     >, ==, or unordered
		return "pl";
	case ARM_CC_VS: // Overflow                   Unordered
		return "vs";
	case ARM_CC_VC: // No overflow                Not unordered
		return "vc";
	case ARM_CC_HI: // Unsigned higher            Greater than, or unordered
		return "hi";
	case ARM_CC_LS: // Unsigned lower or same     Less than or equal
		return "ls";
	case ARM_CC_GE: // Greater than or equal      Greater than or equal
		return "ge";
	case ARM_CC_LT: // Less than                  Less than, or unordered
		return "lt";
	case ARM_CC_GT: // Greater than               Greater than
		return "gt";
	case ARM_CC_LE: // Less than or equal         <, ==, or unordered
		return "le";
	default:
		return "";
	}
}

static void opex(RzStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new();
	if (!pj) {
		return;
	}
	pj_o(pj);
	pj_ka(pj, "operands");
	cs_arm *x = &insn->detail->arm;
	for (i = 0; i < x->op_count; i++) {
		cs_arm_op *op = x->operands + i;
		pj_o(pj);
		switch (op->type) {
		case ARM_OP_REG:
			pj_ks(pj, "type", "reg");
			pj_ks(pj, "value", cs_reg_name(handle, op->reg));
			break;
		case ARM_OP_IMM:
			pj_ks(pj, "type", "imm");
			pj_ki(pj, "value", op->imm);
			break;
		case ARM_OP_MEM:
			pj_ks(pj, "type", "mem");
			if (op->mem.base != ARM_REG_INVALID) {
				pj_ks(pj, "base", cs_reg_name(handle, op->mem.base));
			}
			if (op->mem.index != ARM_REG_INVALID) {
				pj_ks(pj, "index", cs_reg_name(handle, op->mem.index));
			}
			pj_ki(pj, "scale", op->mem.scale);
			pj_ki(pj, "disp", op->mem.disp);
			break;
		case ARM_OP_FP:
			pj_ks(pj, "type", "fp");
			pj_kd(pj, "value", op->fp);
			break;
		case ARM_OP_CIMM:
			pj_ks(pj, "type", "cimm");
			pj_ki(pj, "value", op->imm);
			break;
		case ARM_OP_PIMM:
			pj_ks(pj, "type", "pimm");
			pj_ki(pj, "value", op->imm);
			break;
		case ARM_OP_SETEND:
			pj_ks(pj, "type", "setend");
			switch (op->setend) {
			case ARM_SETEND_BE:
				pj_ks(pj, "value", "be");
				break;
			case ARM_SETEND_LE:
				pj_ks(pj, "value", "le");
				break;
			default:
				pj_ks(pj, "value", "invalid");
				break;
			}
			break;
		case ARM_OP_SYSREG: {
			pj_ks(pj, "type", "sysreg");
			const char *reg = cs_reg_name(handle, op->reg);
			if (reg) {
				pj_ks(pj, "value", reg);
			}
			break;
		}
		default:
			pj_ks(pj, "type", "invalid");
			break;
		}
		if (op->shift.type != ARM_SFT_INVALID) {
			pj_ko(pj, "shift");
			switch (op->shift.type) {
			case ARM_SFT_ASR:
			case ARM_SFT_LSL:
			case ARM_SFT_LSR:
			case ARM_SFT_ROR:
			case ARM_SFT_RRX:
				pj_ks(pj, "type", shift_type_name(op->shift.type));
				pj_kn(pj, "value", (ut64)op->shift.value);
				break;
			case ARM_SFT_ASR_REG:
			case ARM_SFT_LSL_REG:
			case ARM_SFT_LSR_REG:
			case ARM_SFT_ROR_REG:
			case ARM_SFT_RRX_REG:
				pj_ks(pj, "type", shift_type_name(op->shift.type));
				pj_ks(pj, "value", cs_reg_name(handle, op->shift.value));
				break;
			default:
				break;
			}
			pj_end(pj); /* o shift */
		}
		if (op->vector_index != -1) {
			pj_ki(pj, "vector_index", op->vector_index);
		}
		if (op->subtracted) {
			pj_kb(pj, "subtracted", true);
		}
		pj_end(pj); /* o operand */
	}
	pj_end(pj); /* a operands */
	if (x->usermode) {
		pj_kb(pj, "usermode", true);
	}
	if (x->update_flags) {
		pj_kb(pj, "update_flags", true);
	}
	if (x->writeback) {
		pj_kb(pj, "writeback", true);
	}
	if (x->vector_size) {
		pj_ki(pj, "vector_size", x->vector_size);
	}
	if (x->vector_data != ARM_VECTORDATA_INVALID) {
		pj_ks(pj, "vector_data", vector_data_type_name(x->vector_data));
	}
	if (x->cps_mode != ARM_CPSMODE_INVALID) {
		pj_ki(pj, "cps_mode", x->cps_mode);
	}
	if (x->cps_flag != ARM_CPSFLAG_INVALID) {
		pj_ki(pj, "cps_flag", x->cps_flag);
	}
	if (x->cc != ARM_CC_INVALID && x->cc != ARM_CC_AL) {
		pj_ks(pj, "cc", cc_name(x->cc));
	}
	if (x->mem_barrier != ARM_MB_INVALID) {
		pj_ki(pj, "mem_barrier", x->mem_barrier - 1);
	}
	pj_end(pj);

	rz_strbuf_init(buf);
	rz_strbuf_append(buf, pj_string(pj));
	pj_free(pj);
}

static const char *cc_name64(arm64_cc cc) {
	switch (cc) {
	case ARM64_CC_EQ: // Equal
		return "eq";
	case ARM64_CC_NE: // Not equal:                 Not equal, or unordered
		return "ne";
	case ARM64_CC_HS: // Unsigned higher or same:   >, ==, or unordered
		return "hs";
	case ARM64_CC_LO: // Unsigned lower or same:    Less than
		return "lo";
	case ARM64_CC_MI: // Minus, negative:           Less than
		return "mi";
	case ARM64_CC_PL: // Plus, positive or zero:    >, ==, or unordered
		return "pl";
	case ARM64_CC_VS: // Overflow:                  Unordered
		return "vs";
	case ARM64_CC_VC: // No overflow:               Ordered
		return "vc";
	case ARM64_CC_HI: // Unsigned higher:           Greater than, or unordered
		return "hi";
	case ARM64_CC_LS: // Unsigned lower or same:    Less than or equal
		return "ls";
	case ARM64_CC_GE: // Greater than or equal:     Greater than or equal
		return "ge";
	case ARM64_CC_LT: // Less than:                 Less than, or unordered
		return "lt";
	case ARM64_CC_GT: // Signed greater than:       Greater than
		return "gt";
	case ARM64_CC_LE: // Signed less than or equal: <, ==, or unordered
		return "le";
	default:
		return "";
	}
}

static const char *extender_name(arm64_extender extender) {
	switch (extender) {
	case ARM64_EXT_UXTB:
		return "uxtb";
	case ARM64_EXT_UXTH:
		return "uxth";
	case ARM64_EXT_UXTW:
		return "uxtw";
	case ARM64_EXT_UXTX:
		return "uxtx";
	case ARM64_EXT_SXTB:
		return "sxtb";
	case ARM64_EXT_SXTH:
		return "sxth";
	case ARM64_EXT_SXTW:
		return "sxtw";
	case ARM64_EXT_SXTX:
		return "sxtx";
	default:
		return "";
	}
}

static const char *vas_name(arm64_vas vas) {
	switch (vas) {
	case ARM64_VAS_8B:
		return "8b";
	case ARM64_VAS_16B:
		return "16b";
	case ARM64_VAS_4H:
		return "4h";
	case ARM64_VAS_8H:
		return "8h";
	case ARM64_VAS_2S:
		return "2s";
	case ARM64_VAS_4S:
		return "4s";
	case ARM64_VAS_2D:
		return "2d";
	case ARM64_VAS_1D:
		return "1d";
	case ARM64_VAS_1Q:
		return "1q";
#if CS_API_MAJOR > 4
	case ARM64_VAS_1B:
		return "8b";
	case ARM64_VAS_4B:
		return "8b";
	case ARM64_VAS_2H:
		return "2h";
	case ARM64_VAS_1H:
		return "1h";
	case ARM64_VAS_1S:
		return "1s";
#endif
	default:
		return "";
	}
}

#if CS_API_MAJOR == 4
static const char *vess_name(arm64_vess vess) {
	switch (vess) {
	case ARM64_VESS_B:
		return "b";
	case ARM64_VESS_H:
		return "h";
	case ARM64_VESS_S:
		return "s";
	case ARM64_VESS_D:
		return "d";
	default:
		return "";
	}
}
#endif

static void opex64(RzStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new();
	if (!pj) {
		return;
	}
	pj_o(pj);
	pj_ka(pj, "operands");
	cs_arm64 *x = &insn->detail->arm64;
	for (i = 0; i < x->op_count; i++) {
		cs_arm64_op *op = x->operands + i;
		pj_o(pj);
		switch (op->type) {
		case ARM64_OP_REG:
			pj_ks(pj, "type", "reg");
			pj_ks(pj, "value", cs_reg_name(handle, op->reg));
			break;
		case ARM64_OP_REG_MRS:
			pj_ks(pj, "type", "reg_mrs");
			// TODO value
			break;
		case ARM64_OP_REG_MSR:
			pj_ks(pj, "type", "reg_msr");
			// TODO value
			break;
		case ARM64_OP_IMM:
			pj_ks(pj, "type", "imm");
			pj_kN(pj, "value", op->imm);
			break;
		case ARM64_OP_MEM:
			pj_ks(pj, "type", "mem");
			if (op->mem.base != ARM64_REG_INVALID) {
				pj_ks(pj, "base", cs_reg_name(handle, op->mem.base));
			}
			if (op->mem.index != ARM64_REG_INVALID) {
				pj_ks(pj, "index", cs_reg_name(handle, op->mem.index));
			}
			pj_ki(pj, "disp", op->mem.disp);
			break;
		case ARM64_OP_FP:
			pj_ks(pj, "type", "fp");
			pj_kd(pj, "value", op->fp);
			break;
		case ARM64_OP_CIMM:
			pj_ks(pj, "type", "cimm");
			pj_kN(pj, "value", op->imm);
			break;
		case ARM64_OP_PSTATE:
			pj_ks(pj, "type", "pstate");
			switch (op->pstate) {
			case ARM64_PSTATE_SPSEL:
				pj_ks(pj, "value", "spsel");
				break;
			case ARM64_PSTATE_DAIFSET:
				pj_ks(pj, "value", "daifset");
				break;
			case ARM64_PSTATE_DAIFCLR:
				pj_ks(pj, "value", "daifclr");
				break;
			default:
				pj_ki(pj, "value", op->pstate);
			}
			break;
		case ARM64_OP_SYS:
			pj_ks(pj, "type", "sys");
			pj_kn(pj, "value", (ut64)op->sys);
			break;
		case ARM64_OP_PREFETCH:
			pj_ks(pj, "type", "prefetch");
			pj_ki(pj, "value", op->prefetch - 1);
			break;
		case ARM64_OP_BARRIER:
			pj_ks(pj, "type", "prefetch");
			pj_ki(pj, "value", op->barrier - 1);
			break;
		default:
			pj_ks(pj, "type", "invalid");
			break;
		}
		if (op->shift.type != ARM64_SFT_INVALID) {
			pj_ko(pj, "shift");
			switch (op->shift.type) {
			case ARM64_SFT_LSL:
				pj_ks(pj, "type", "lsl");
				break;
			case ARM64_SFT_MSL:
				pj_ks(pj, "type", "msl");
				break;
			case ARM64_SFT_LSR:
				pj_ks(pj, "type", "lsr");
				break;
			case ARM64_SFT_ASR:
				pj_ks(pj, "type", "asr");
				break;
			case ARM64_SFT_ROR:
				pj_ks(pj, "type", "ror");
				break;
			default:
				break;
			}
			pj_kn(pj, "value", (ut64)op->shift.value);
			pj_end(pj);
		}
		if (op->ext != ARM64_EXT_INVALID) {
			pj_ks(pj, "ext", extender_name(op->ext));
		}
		if (op->vector_index != -1) {
			pj_ki(pj, "vector_index", op->vector_index);
		}
		if (op->vas != ARM64_VAS_INVALID) {
			pj_ks(pj, "vas", vas_name(op->vas));
		}
#if CS_API_MAJOR == 4
		if (op->vess != ARM64_VESS_INVALID) {
			pj_ks(pj, "vess", vess_name(op->vess));
		}
#endif
		pj_end(pj);
	}
	pj_end(pj);
	if (x->update_flags) {
		pj_kb(pj, "update_flags", true);
	}
	if (x->writeback) {
		pj_kb(pj, "writeback", true);
	}
	if (x->cc != ARM64_CC_INVALID && x->cc != ARM64_CC_AL && x->cc != ARM64_CC_NV) {
		pj_ks(pj, "cc", cc_name64(x->cc));
	}
	pj_end(pj);

	rz_strbuf_init(buf);
	rz_strbuf_append(buf, pj_string(pj));
	pj_free(pj);
}

static int cond_cs2r2(int cc) {
	if (cc == ARM_CC_AL || cc < 0) {
		cc = RZ_TYPE_COND_AL;
	} else {
		switch (cc) {
		case ARM_CC_EQ: cc = RZ_TYPE_COND_EQ; break;
		case ARM_CC_NE: cc = RZ_TYPE_COND_NE; break;
		case ARM_CC_HS: cc = RZ_TYPE_COND_HS; break;
		case ARM_CC_LO: cc = RZ_TYPE_COND_LO; break;
		case ARM_CC_MI: cc = RZ_TYPE_COND_MI; break;
		case ARM_CC_PL: cc = RZ_TYPE_COND_PL; break;
		case ARM_CC_VS: cc = RZ_TYPE_COND_VS; break;
		case ARM_CC_VC: cc = RZ_TYPE_COND_VC; break;
		case ARM_CC_HI: cc = RZ_TYPE_COND_HI; break;
		case ARM_CC_LS: cc = RZ_TYPE_COND_LS; break;
		case ARM_CC_GE: cc = RZ_TYPE_COND_GE; break;
		case ARM_CC_LT: cc = RZ_TYPE_COND_LT; break;
		case ARM_CC_GT: cc = RZ_TYPE_COND_GT; break;
		case ARM_CC_LE: cc = RZ_TYPE_COND_LE; break;
		}
	}
	return cc;
}

static void anop64(ArmCSContext *ctx, RzAnalysisOp *op, cs_insn *insn) {
	csh handle = ctx->handle;
	ut64 addr = op->addr;

	/* grab family */
	if (cs_insn_group(handle, insn, ARM64_GRP_CRYPTO)) {
		op->family = RZ_ANALYSIS_OP_FAMILY_CRYPTO;
	} else if (cs_insn_group(handle, insn, ARM64_GRP_CRC)) {
		op->family = RZ_ANALYSIS_OP_FAMILY_CRYPTO;
#if CS_API_MAJOR >= 4
	} else if (cs_insn_group(handle, insn, ARM64_GRP_PRIVILEGE)) {
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
#endif
	} else if (cs_insn_group(handle, insn, ARM64_GRP_NEON)) {
		op->family = RZ_ANALYSIS_OP_FAMILY_MMX;
	} else if (cs_insn_group(handle, insn, ARM64_GRP_FPARMV8)) {
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
	} else {
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	}

	op->cond = cond_cs2r2(insn->detail->arm64.cc);
	if (op->cond == RZ_TYPE_COND_NV) {
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		return;
	}

	switch (insn->detail->arm64.cc) {
	case ARM64_CC_GE:
	case ARM64_CC_GT:
	case ARM64_CC_LE:
	case ARM64_CC_LT:
		op->sign = true;
		break;
	default:
		break;
	}

	switch (insn->id) {
#if CS_API_MAJOR > 4
	case ARM64_INS_PACDA:
	case ARM64_INS_PACDB:
	case ARM64_INS_PACDZA:
	case ARM64_INS_PACDZB:
	case ARM64_INS_PACGA:
	case ARM64_INS_PACIA:
	case ARM64_INS_PACIA1716:
	case ARM64_INS_PACIASP:
	case ARM64_INS_PACIAZ:
	case ARM64_INS_PACIB:
	case ARM64_INS_PACIB1716:
	case ARM64_INS_PACIBSP:
	case ARM64_INS_PACIBZ:
	case ARM64_INS_PACIZA:
	case ARM64_INS_PACIZB:
	case ARM64_INS_AUTDA:
	case ARM64_INS_AUTDB:
	case ARM64_INS_AUTDZA:
	case ARM64_INS_AUTDZB:
	case ARM64_INS_AUTIA:
	case ARM64_INS_AUTIA1716:
	case ARM64_INS_AUTIASP:
	case ARM64_INS_AUTIAZ:
	case ARM64_INS_AUTIB:
	case ARM64_INS_AUTIB1716:
	case ARM64_INS_AUTIBSP:
	case ARM64_INS_AUTIBZ:
	case ARM64_INS_AUTIZA:
	case ARM64_INS_AUTIZB:
	case ARM64_INS_XPACD:
	case ARM64_INS_XPACI:
	case ARM64_INS_XPACLRI:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_SECURITY;
		break;
#endif
	case ARM64_INS_SVC:
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		op->val = IMM64(0);
		break;
	case ARM64_INS_ADRP:
	case ARM64_INS_ADR:
		op->type = RZ_ANALYSIS_OP_TYPE_LEA;
		op->ptr = IMM64(1);
		break;
	case ARM64_INS_NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->cycles = 1;
		break;
	case ARM64_INS_SUB:
		if (ISREG64(0) && REGID64(0) == ARM64_REG_SP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			if (ISIMM64(1)) {
				// sub sp, 0x54
				op->stackptr = IMM(1);
			} else if (ISIMM64(2) && ISREG64(1) && REGID64(1) == ARM64_REG_SP) {
				// sub sp, sp, 0x10
				op->stackptr = IMM64(2);
			}
			op->val = op->stackptr;
		} else {
			op->stackop = RZ_ANALYSIS_STACK_RESET;
			op->stackptr = 0;
		}
		op->cycles = 1;
		/* fallthru */
	case ARM64_INS_MSUB:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case ARM64_INS_FDIV:
	case ARM64_INS_SDIV:
	case ARM64_INS_UDIV:
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case ARM64_INS_MUL:
	case ARM64_INS_SMULL:
	case ARM64_INS_FMUL:
	case ARM64_INS_UMULL:
		/* TODO: if next instruction is also a MUL, cycles are /=2 */
		/* also known as Register Indexing Addressing */
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case ARM64_INS_ADD:
		if (ISREG64(0) && REGID64(0) == ARM64_REG_SP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			if (ISIMM64(1)) {
				// add sp, 0x54
				op->stackptr = -IMM(1);
			} else if (ISIMM64(2) && ISREG64(1) && REGID64(1) == ARM64_REG_SP) {
				// add sp, sp, 0x10
				op->stackptr = -IMM64(2);
			}
			op->val = op->stackptr;
		} else {
			op->stackop = RZ_ANALYSIS_STACK_RESET;
			op->stackptr = 0;
			if (ISIMM64(2)) {
				op->val = IMM64(2);
			}
		}
		op->cycles = 1;
		/* fallthru */
	case ARM64_INS_ADC:
	// case ARM64_INS_ADCS:
	case ARM64_INS_UMADDL:
	case ARM64_INS_SMADDL:
	case ARM64_INS_FMADD:
	case ARM64_INS_MADD:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case ARM64_INS_CSEL:
	case ARM64_INS_FCSEL:
	case ARM64_INS_CSET:
	case ARM64_INS_CINC:
		op->type = RZ_ANALYSIS_OP_TYPE_CMOV;
		break;
	case ARM64_INS_MOV:
		if (REGID64(0) == ARM64_REG_SP) {
			op->stackop = RZ_ANALYSIS_STACK_RESET;
			op->stackptr = 0;
		}
		if (ISIMM64(1)) {
			op->val = IMM64(1);
		}
		op->cycles = 1;
		/* fallthru */
	case ARM64_INS_MOVI:
	case ARM64_INS_MOVK:
	case ARM64_INS_MOVN:
	case ARM64_INS_SMOV:
	case ARM64_INS_UMOV:
	case ARM64_INS_FMOV:
	case ARM64_INS_SBFX:
	case ARM64_INS_UBFX:
	case ARM64_INS_UBFM:
	case ARM64_INS_SBFIZ:
	case ARM64_INS_UBFIZ:
	case ARM64_INS_BIC:
	case ARM64_INS_BFI:
	case ARM64_INS_BFXIL:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case ARM64_INS_MRS:
	case ARM64_INS_MSR:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		break;
	case ARM64_INS_MOVZ:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->ptr = 0LL;
		op->ptrsize = 8;
		op->val = IMM64(1);
		break;
	case ARM64_INS_UXTB:
	case ARM64_INS_SXTB:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		op->ptr = 0LL;
		op->ptrsize = 1;
		break;
	case ARM64_INS_UXTH:
	case ARM64_INS_SXTH:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->ptr = 0LL;
		op->ptrsize = 2;
		break;
	case ARM64_INS_UXTW:
	case ARM64_INS_SXTW:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->ptr = 0LL;
		op->ptrsize = 4;
		break;
	case ARM64_INS_BRK:
	case ARM64_INS_HLT:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		// hlt stops the process, not skips some cycles like in x86
		break;
	case ARM64_INS_DMB:
	case ARM64_INS_DSB:
	case ARM64_INS_ISB:
		op->family = RZ_ANALYSIS_OP_FAMILY_THREAD;
		// intentional fallthrough
	case ARM64_INS_IC: // instruction cache invalidate
	case ARM64_INS_DC: // data cache invalidate
		op->type = RZ_ANALYSIS_OP_TYPE_SYNC; // or cache
		break;
	//  XXX unimplemented instructions
	case ARM64_INS_DUP:
	case ARM64_INS_XTN:
	case ARM64_INS_XTN2:
	case ARM64_INS_REV64:
	case ARM64_INS_EXT:
	case ARM64_INS_INS:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case ARM64_INS_LSL:
		op->cycles = 1;
		/* fallthru */
	case ARM64_INS_SHL:
	case ARM64_INS_USHLL:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case ARM64_INS_LSR:
		op->cycles = 1;
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case ARM64_INS_ASR:
		op->cycles = 1;
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		break;
	case ARM64_INS_NEG:
#if CS_API_MAJOR > 3
	case ARM64_INS_NEGS:
#endif
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case ARM64_INS_FCMP:
	case ARM64_INS_CCMP:
	case ARM64_INS_CCMN:
	case ARM64_INS_CMP:
	case ARM64_INS_CMN:
	case ARM64_INS_TST:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case ARM64_INS_ROR:
		op->cycles = 1;
		op->type = RZ_ANALYSIS_OP_TYPE_ROR;
		break;
	case ARM64_INS_AND:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case ARM64_INS_ORR:
	case ARM64_INS_ORN:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		if (ISIMM64(2)) {
			op->val = IMM64(2);
		}
		break;
	case ARM64_INS_EOR:
	case ARM64_INS_EON:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case ARM64_INS_STRB:
	case ARM64_INS_STURB:
	case ARM64_INS_STUR:
	case ARM64_INS_STR:
	case ARM64_INS_STP:
	case ARM64_INS_STNP:
	case ARM64_INS_STXR:
	case ARM64_INS_STXRH:
	case ARM64_INS_STLXR:
	case ARM64_INS_STLXRH:
	case ARM64_INS_STXRB:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		if (ISPREINDEX64() && REGBASE64(2) == ARM64_REG_SP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = -MEMDISP64(2);
		} else if (ISPOSTINDEX64() && REGID64(2) == ARM64_REG_SP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = -IMM64(3);
		} else if (ISPREINDEX64() && REGBASE64(1) == ARM64_REG_SP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = -MEMDISP64(1);
		} else if (ISPOSTINDEX64() && REGID64(1) == ARM64_REG_SP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = -IMM64(2);
		}
		break;
	case ARM64_INS_LDUR:
	case ARM64_INS_LDURB:
	case ARM64_INS_LDRSW:
	case ARM64_INS_LDRSB:
	case ARM64_INS_LDRSH:
	case ARM64_INS_LDR:
	case ARM64_INS_LDURSW:
	case ARM64_INS_LDP:
	case ARM64_INS_LDNP:
	case ARM64_INS_LDPSW:
	case ARM64_INS_LDRH:
	case ARM64_INS_LDRB:
		if (ISPREINDEX64() && REGBASE64(2) == ARM64_REG_SP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = -MEMDISP64(2);
		} else if (ISPOSTINDEX64() && REGID64(2) == ARM64_REG_SP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = -IMM64(3);
		} else if (ISPREINDEX64() && REGBASE64(1) == ARM64_REG_SP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = -MEMDISP64(1);
		} else if (ISPOSTINDEX64() && REGID64(1) == ARM64_REG_SP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = -IMM64(2);
		}
		if (REGID(0) == ARM_REG_PC) {
			op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
			if (insn->detail->arm.cc != ARM_CC_AL) {
				// op->type = RZ_ANALYSIS_OP_TYPE_MCJMP;
				op->type = RZ_ANALYSIS_OP_TYPE_UCJMP;
			}
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		}
		switch (insn->id) {
		case ARM64_INS_LDPSW:
		case ARM64_INS_LDRSW:
		case ARM64_INS_LDRSH:
		case ARM64_INS_LDRSB:
			op->sign = true;
			break;
		}
		if (REGBASE64(1) == ARM64_REG_X29) {
			op->stackop = RZ_ANALYSIS_STACK_GET;
			op->stackptr = 0;
			op->ptr = MEMDISP64(1);
		} else {
			if (ISIMM64(1)) {
				op->type = RZ_ANALYSIS_OP_TYPE_LEA;
				op->ptr = IMM64(1);
				op->refptr = 8;
			} else {
				int d = (int)MEMDISP64(1);
				op->ptr = (d < 0) ? -d : d;
				op->refptr = 4;
			}
		}
		break;
#if CS_API_MAJOR > 4
	case ARM64_INS_BLRAA:
	case ARM64_INS_BLRAAZ:
	case ARM64_INS_BLRAB:
	case ARM64_INS_BLRABZ:
		op->family = RZ_ANALYSIS_OP_FAMILY_SECURITY;
		op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		break;
	case ARM64_INS_BRAA:
	case ARM64_INS_BRAAZ:
	case ARM64_INS_BRAB:
	case ARM64_INS_BRABZ:
		op->family = RZ_ANALYSIS_OP_FAMILY_SECURITY;
		op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
		break;
	case ARM64_INS_LDRAA:
	case ARM64_INS_LDRAB:
		op->family = RZ_ANALYSIS_OP_FAMILY_SECURITY;
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case ARM64_INS_RETAA:
	case ARM64_INS_RETAB:
	case ARM64_INS_ERETAA:
	case ARM64_INS_ERETAB:
		op->family = RZ_ANALYSIS_OP_FAMILY_SECURITY;
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
#endif
	case ARM64_INS_ERET:
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case ARM64_INS_RET:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case ARM64_INS_BL: // bl 0x89480
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = IMM64(0);
		op->fail = addr + 4;
		break;
	case ARM64_INS_BLR: // blr x0
		op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		op->reg = cs_reg_name(handle, REGID64(0));
		op->fail = addr + 4;
		// op->jump = IMM64(0);
		break;
	case ARM64_INS_CBZ:
	case ARM64_INS_CBNZ:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = IMM64(1);
		op->fail = addr + op->size;
		break;
	case ARM64_INS_TBZ:
	case ARM64_INS_TBNZ:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = IMM64(2);
		op->fail = addr + op->size;
		break;
	case ARM64_INS_BR:
		op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
		op->reg = cs_reg_name(handle, REGID64(0));
		op->eob = true;
		break;
	case ARM64_INS_B:
		// BX LR == RET
		if (insn->detail->arm64.operands[0].reg == ARM64_REG_LR) {
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
		} else if (insn->detail->arm64.cc) {
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = IMM64(0);
			op->fail = addr + op->size;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			op->jump = IMM64(0);
		}
		break;
	default:
		RZ_LOG_DEBUG("ARM64 analysis: Op type %d at 0x%" PFMT64x " not handled\n", insn->id, op->addr);
		break;
	}
}

static void anop32(RzAnalysis *a, csh handle, RzAnalysisOp *op, cs_insn *insn, bool thumb, const ut8 *buf, int len) {
	ArmCSContext *ctx = (ArmCSContext *)a->plugin_data;
	const ut64 addr = op->addr;
	const int pcdelta = thumb ? 4 : 8;
	int i;

	op->cond = cond_cs2r2(insn->detail->arm.cc);
	if (op->cond == RZ_TYPE_COND_NV) {
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		return;
	}
	op->cycles = 1;
	/* grab family */
	if (cs_insn_group(handle, insn, ARM_GRP_CRYPTO)) {
		op->family = RZ_ANALYSIS_OP_FAMILY_CRYPTO;
	} else if (cs_insn_group(handle, insn, ARM_GRP_CRC)) {
		op->family = RZ_ANALYSIS_OP_FAMILY_CRYPTO;
#if CS_API_MAJOR >= 4
	} else if (cs_insn_group(handle, insn, ARM_GRP_PRIVILEGE)) {
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
	} else if (cs_insn_group(handle, insn, ARM_GRP_VIRTUALIZATION)) {
		op->family = RZ_ANALYSIS_OP_FAMILY_VIRT;
#endif
	} else if (cs_insn_group(handle, insn, ARM_GRP_NEON)) {
		op->family = RZ_ANALYSIS_OP_FAMILY_MMX;
	} else if (cs_insn_group(handle, insn, ARM_GRP_FPARMV8)) {
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
	} else if (cs_insn_group(handle, insn, ARM_GRP_THUMB2DSP)) {
		op->family = RZ_ANALYSIS_OP_FAMILY_MMX;
	} else {
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	}

	if (insn->id != ARM_INS_IT) {
		rz_arm_it_update_nonblock(&ctx->it, insn);
	}

	switch (insn->id) {
#if 0

If PC is specified for Rn, the value used is the address of the instruction plus 4.

These instructions cause a PC-relative forward branch using a table of single byte offsets (TBB) or halfword offsets (TBH). Rn provides a pointer to the table, and Rm supplies an index into the table. The branch length is twice the value of the byte (TBB) or the halfword (TBH) returned from the table. The target of the branch table must be in the same execution state.

jmp $$ + 4 + ( [delta] * 2 )

#endif
	case ARM_INS_TBH: // half word table
		op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
		op->cycles = 2;
		op->ptrsize = 2;
		op->ireg = rz_str_get_null(cs_reg_name(handle, INSOP(0).mem.index));
		break;
	case ARM_INS_TBB: // byte jump table
		op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
		op->cycles = 2;
		op->ptrsize = 1;
		op->ireg = rz_str_get_null(cs_reg_name(handle, INSOP(0).mem.index));
		break;
	case ARM_INS_PLD:
		op->type = RZ_ANALYSIS_OP_TYPE_LEA; // not really a lea, just a prefetch
		if (ISMEM(0)) {
			int regBase = REGBASE(0);
			int delta = MEMDISP(0);
			if (regBase == ARM_REG_PC) {
				op->ptr = addr + 4 + delta;
			} else {
				// exotic pld
			}
		}
		break;
	case ARM_INS_IT:
		rz_arm_it_update_block(&ctx->it, insn);
		op->cycles = 2;
		break;
	case ARM_INS_BKPT:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		op->cycles = 4;
		break;
	case ARM_INS_NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->cycles = 1;
		break;
	case ARM_INS_POP:
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -4LL * insn->detail->arm.op_count;
		// fallthrough
	case ARM_INS_FLDMDBX:
	case ARM_INS_FLDMIAX:
	case ARM_INS_LDMDA:
	case ARM_INS_LDMDB:
	case ARM_INS_LDMIB:
	case ARM_INS_LDM:
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		op->cycles = 2;
		for (i = 0; i < insn->detail->arm.op_count; i++) {
			if (insn->detail->arm.operands[i].type == ARM_OP_REG &&
				insn->detail->arm.operands[i].reg == ARM_REG_PC) {
				if (insn->detail->arm.cc == ARM_CC_AL) {
					op->type = RZ_ANALYSIS_OP_TYPE_RET;
				} else {
					op->type = RZ_ANALYSIS_OP_TYPE_CRET;
				}
				break;
			}
		}
		break;
	case ARM_INS_SUB:
		if (ISREG(0) && REGID(0) == ARM_REG_SP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			if (ISIMM(1)) {
				// 0x0000bf4e      95b0           sub sp, 0x54
				op->stackptr = IMM(1);
			} else if (ISIMM(2) && ISREG(1) && REGID(1) == ARM_REG_SP) {
				// 0x00008254    10d04de2     sub sp, sp, 0x10
				op->stackptr = IMM(2);
			}
			op->val = op->stackptr;
		}
		op->cycles = 1;
		/* fall-thru */
	case ARM_INS_SUBW:
	case ARM_INS_SSUB8:
	case ARM_INS_SSUB16:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case ARM_INS_ADD:
		if (ISREG(0) && REGID(0) == ARM_REG_SP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			if (ISIMM(1)) {
				// add sp, 0x54
				op->stackptr = -IMM(1);
			} else if (ISIMM(2) && ISREG(1) && REGID(1) == ARM_REG_SP) {
				// add sp, sp, 0x10
				op->stackptr = -IMM(2);
			}
			op->val = op->stackptr;
		}
		// fallthrough
	case ARM_INS_ADC:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		if (REGID(0) == ARM_REG_PC) {
			op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
			if (REGID(1) == ARM_REG_PC && insn->detail->arm.cc != ARM_CC_AL) {
				// op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
				op->type = RZ_ANALYSIS_OP_TYPE_UCJMP;
				op->fail = addr + op->size;
				op->jump = ((addr & ~3LL) + (thumb ? 4 : 8) + MEMDISP(1)) & UT64_MAX;
				op->ptr = (addr & ~3LL) + (thumb ? 4 : 8) + MEMDISP(1);
				op->refptr = 4;
				op->reg = rz_str_get_null(cs_reg_name(handle, INSOP(2).reg));
				break;
			}
		}
		op->cycles = 1;
		break;
		/* fall-thru */
	case ARM_INS_ADDW:
	case ARM_INS_SADD8:
	case ARM_INS_SADD16:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case ARM_INS_SDIV:
	case ARM_INS_UDIV:
		op->cycles = 4;
		/* fall-thru */
	case ARM_INS_VDIV:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case ARM_INS_MUL:
	case ARM_INS_SMULL:
	case ARM_INS_UMULL:
		/* TODO: if next instruction is also a MUL, cycles are /=2 */
		/* also known as Register Indexing Addressing */
		op->cycles = 4;
		/* fall-thru */
	case ARM_INS_VMUL:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case ARM_INS_TRAP:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		op->cycles = 2;
		break;
	case ARM_INS_MOV:
		if (REGID(0) == ARM_REG_PC) {
			if (REGID(1) == ARM_REG_LR) {
				op->type = RZ_ANALYSIS_OP_TYPE_RET;
			} else {
				op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
			}
		}
		if (ISIMM(1)) {
			op->val = IMM(1);
		}
		/* fall-thru */
	case ARM_INS_MOVT:
	case ARM_INS_MOVW:
	case ARM_INS_VMOVL:
	case ARM_INS_VMOVN:
	case ARM_INS_VQMOVUN:
	case ARM_INS_VQMOVN:
	case ARM_INS_SBFX:
	case ARM_INS_UBFX:
	case ARM_INS_BIC:
	case ARM_INS_BFI:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case ARM_INS_VMOV:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		op->cycles = 2;
		break;
	case ARM_INS_UDF:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		op->cycles = 4;
		break;
	case ARM_INS_SVC:
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		op->val = IMM(0);
		break;
	case ARM_INS_ROR:
	case ARM_INS_RRX:
		op->cycles = 1;
		op->type = RZ_ANALYSIS_OP_TYPE_ROR;
		break;
	case ARM_INS_AND:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case ARM_INS_ORR:
	case ARM_INS_ORN:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case ARM_INS_EOR:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case ARM_INS_CMP:
	case ARM_INS_CMN:
	case ARM_INS_TST:
		if (ISIMM(1)) {
			op->ptr = IMM(1);
		}
		op->reg = rz_str_get_null(cs_reg_name(handle, INSOP(0).reg));
		/* fall-thru */
	case ARM_INS_VCMP:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case ARM_INS_LSL:
		op->cycles = 1;
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case ARM_INS_LSR:
		op->cycles = 1;
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case ARM_INS_ASR:
		op->cycles = 1;
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		break;
	case ARM_INS_PUSH:
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = 4LL * insn->detail->arm.op_count;
		// fallthrough
	case ARM_INS_STM:
	case ARM_INS_STMDA:
	case ARM_INS_STMDB:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		// 0x00008160    04202de5     str r2, [sp, -4]!
		// 0x000082a0    28000be5     str r0, [fp, -0x28]
		if (REGBASE(1) == ARM_REG_FP) {
			op->stackop = RZ_ANALYSIS_STACK_SET;
			op->stackptr = 0;
			op->ptr = MEMDISP(1);
		}
		break;
	case ARM_INS_STREX:
	case ARM_INS_STREXB:
	case ARM_INS_STREXD:
	case ARM_INS_STREXH:
		op->family = RZ_ANALYSIS_OP_FAMILY_THREAD;
		/* fall-thru */
	case ARM_INS_STR:
	case ARM_INS_STRB:
	case ARM_INS_STRD:
	case ARM_INS_STRBT:
	case ARM_INS_STRH:
	case ARM_INS_STRHT:
	case ARM_INS_STRT:
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		if (REGBASE(1) == ARM_REG_FP) {
			op->stackop = RZ_ANALYSIS_STACK_SET;
			op->stackptr = 0;
			op->ptr = -MEMDISP(1);
		}
		break;
	case ARM_INS_SXTB:
	case ARM_INS_SXTH:
		op->cycles = 1;
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case ARM_INS_LDREX:
	case ARM_INS_LDREXB:
	case ARM_INS_LDREXD:
	case ARM_INS_LDREXH:
		op->family = RZ_ANALYSIS_OP_FAMILY_THREAD;
		/* fall-thru */
	case ARM_INS_LDR:
	case ARM_INS_LDRD:
	case ARM_INS_LDRB:
	case ARM_INS_LDRBT:
	case ARM_INS_LDRH:
	case ARM_INS_LDRHT:
	case ARM_INS_LDRSB:
	case ARM_INS_LDRSBT:
	case ARM_INS_LDRSH:
	case ARM_INS_LDRSHT:
	case ARM_INS_LDRT:
		op->cycles = 4;
		// 0x000082a8    28301be5     ldr r3, [fp, -0x28]
		if (INSOP(1).mem.scale != -1) {
			op->scale = INSOP(1).mem.scale << LSHIFT(1);
		}
		op->ireg = cs_reg_name(handle, REGBASE(1));
		op->disp = MEMDISP(1);
		if (REGID(0) == ARM_REG_PC) {
			op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
			if (insn->detail->arm.cc != ARM_CC_AL) {
				// op->type = RZ_ANALYSIS_OP_TYPE_MCJMP;
				op->type = RZ_ANALYSIS_OP_TYPE_UCJMP;
			}
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		}
		switch (insn->id) {
		case ARM_INS_LDRB:
			op->ptrsize = 1;
			break;
		case ARM_INS_LDRH:
		case ARM_INS_LDRHT:
			op->ptrsize = 2;
			break;
		}
		if (REGBASE(1) == ARM_REG_FP) {
			op->stackop = RZ_ANALYSIS_STACK_GET;
			op->stackptr = 0;
			op->ptr = -MEMDISP(1);
		} else if (REGBASE(1) == ARM_REG_PC) {
			op->ptr = (addr & ~3LL) + (thumb ? 4 : 8) + MEMDISP(1);
			op->refptr = 4;
			if (REGID(0) == ARM_REG_PC && insn->detail->arm.cc != ARM_CC_AL) {
				// op->type = RZ_ANALYSIS_OP_TYPE_MCJMP;
				op->type = RZ_ANALYSIS_OP_TYPE_UCJMP;
				op->fail = addr + op->size;
				op->jump = ((addr & ~3LL) + (thumb ? 4 : 8) + MEMDISP(1)) & UT64_MAX;
				op->ireg = rz_str_get_null(cs_reg_name(handle, INSOP(1).mem.index));
				break;
			}
		}
		break;
	case ARM_INS_MRS:
	case ARM_INS_MSR:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		break;
	case ARM_INS_BLX:
		op->cycles = 4;
		if (ISREG(0)) {
			/* blx reg */
			op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
			op->reg = cs_reg_name(handle, REGID(0));
		} else {
			/* blx label */
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			op->jump = IMM(0) & UT32_MAX;
			op->fail = addr + op->size;
			op->hint.new_bits = (a->bits == 32) ? 16 : 32;
			// switch instruction set always with blx label
			//  rz_analysis_hint_set_bits (a, op->jump, a->bits == 32? 16 : 32);
		}
		break;
	case ARM_INS_BL:
		/* bl label */
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = IMM(0) & UT32_MAX;
		op->fail = addr + op->size;
		op->hint.new_bits = a->bits;
		break;
	case ARM_INS_CBZ:
	case ARM_INS_CBNZ:
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = IMM(1) & UT32_MAX;
		op->fail = addr + op->size;
		if (op->jump == op->fail) {
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			op->fail = UT64_MAX;
		}
		break;
	case ARM_INS_B:
		/* b.cc label */
		op->cycles = 4;
		if (insn->detail->arm.cc == ARM_CC_INVALID) {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
			op->fail = addr + op->size;
		} else if (insn->detail->arm.cc == ARM_CC_AL) {
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			op->fail = UT64_MAX;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->fail = addr + op->size;
		}
		op->jump = IMM(0) & UT32_MAX;
		// propagate bits to create correctly hints ranges
		op->hint.new_bits = a->bits;
		break;
	case ARM_INS_BX:
	case ARM_INS_BXJ:
		/* bx reg */
		op->cycles = 4;
		op->reg = cs_reg_name(handle, REGID(0));
		switch (REGID(0)) {
		case ARM_REG_LR:
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
			break;
		case ARM_REG_IP:
			op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
			break;
		case ARM_REG_PC:
			// bx pc is well known without ESIL
			op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
			op->jump = (addr & ~3LL) + pcdelta;
			op->hint.new_bits = 32;
			break;
		default:
			op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
			op->eob = true;
			break;
		}
		break;
	case ARM_INS_ADR:
		op->cycles = 2;
		op->type = RZ_ANALYSIS_OP_TYPE_LEA;
		// Set the pointer address and align it
		op->ptr = IMM(1) + addr + 4 - (addr % 4);
		op->refptr = 1;
		break;
	case ARM_INS_UXTAB:
	case ARM_INS_UXTAB16:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->ptr = 0LL;
		op->ptrsize = 1;
		break;
	case ARM_INS_UXTAH:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->ptr = 0LL;
		op->ptrsize = 2;
		break;
	case ARM_INS_UXTB:
	case ARM_INS_UXTB16:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		op->ptr = 0LL;
		op->ptrsize = 1;
		break;
	case ARM_INS_UXTH:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		op->ptr = 0LL;
		op->ptrsize = 2;
		break;
	default:
		RZ_LOG_DEBUG("ARM analysis: Op type %d at 0x%" PFMT64x " not handled\n", insn->id, op->addr);
		break;
	}
	if (thumb && rz_arm_it_apply_cond(&ctx->it, insn)) {
		op->mnemonic = rz_str_newf("%s%s%s%s",
			rz_analysis_optype_to_string(op->type),
			cc_name(insn->detail->arm.cc),
			insn->op_str[0] ? " " : "",
			insn->op_str);
		op->cond = (RzTypeCond)insn->detail->arm.cc;
	}
}

static bool is_valid(arm_reg reg) {
	return reg != ARM_REG_INVALID;
}

static int parse_reg_name(RzReg *reg, RzRegItem **reg_base, RzRegItem **reg_delta, csh handle, cs_insn *insn, int reg_num) {
	cs_arm_op armop = INSOP(reg_num);
	switch (armop.type) {
	case ARM_OP_REG:
		*reg_base = rz_reg_get(reg, cs_reg_name(handle, armop.reg), RZ_REG_TYPE_ANY);
		break;
	case ARM_OP_MEM:
		if (is_valid(armop.mem.base) && is_valid(armop.mem.index)) {
			*reg_base = rz_reg_get(reg, cs_reg_name(handle, armop.mem.base), RZ_REG_TYPE_ANY);
			*reg_delta = rz_reg_get(reg, cs_reg_name(handle, armop.mem.index), RZ_REG_TYPE_ANY);
		} else if (is_valid(armop.mem.base)) {
			*reg_base = rz_reg_get(reg, cs_reg_name(handle, armop.mem.base), RZ_REG_TYPE_ANY);
		} else if (is_valid(armop.mem.index)) {
			*reg_base = rz_reg_get(reg, cs_reg_name(handle, armop.mem.index), RZ_REG_TYPE_ANY);
		}
		break;
	default:
		break;
	}
	return 0;
}

static bool is_valid64(arm64_reg reg) {
	return reg != ARM64_REG_INVALID;
}

static char *reg_list[] = {
	"x0", "x1", "x2", "x3", "x4",
	"x5", "x6", "x7", "x8", "x9",
	"x10", "x11", "x12", "x13", "x14",
	"x15", "x16", "x17", "x18", "x19",
	"x20", "x21", "x22", "x23", "x24",
	"x25", "x26", "x27", "x28", "x29",
	"x30"
};

static int parse_reg64_name(RzReg *reg, RzRegItem **reg_base, RzRegItem **reg_delta, csh handle, cs_insn *insn, int reg_num) {
	cs_arm64_op armop = INSOP64(reg_num);
	switch (armop.type) {
	case ARM64_OP_REG:
		*reg_base = rz_reg_get(reg, cs_reg_name(handle, armop.reg), RZ_REG_TYPE_ANY);
		break;
	case ARM64_OP_MEM:
		if (is_valid64(armop.mem.base) && is_valid64(armop.mem.index)) {
			*reg_base = rz_reg_get(reg, cs_reg_name(handle, armop.mem.base), RZ_REG_TYPE_ANY);
			*reg_delta = rz_reg_get(reg, cs_reg_name(handle, armop.mem.index), RZ_REG_TYPE_ANY);
		} else if (is_valid64(armop.mem.base)) {
			*reg_base = rz_reg_get(reg, cs_reg_name(handle, armop.mem.base), RZ_REG_TYPE_ANY);
		} else if (is_valid64(armop.mem.index)) {
			*reg_base = rz_reg_get(reg, cs_reg_name(handle, armop.mem.index), RZ_REG_TYPE_ANY);
		}
		break;
	default:
		break;
	}
	if (*reg_base && *(*reg_base)->name == 'w') {
		*reg_base = rz_reg_get(reg, reg_list[atoi((*reg_base)->name + 1)], RZ_REG_TYPE_ANY);
	}
	return 0;
}

static void set_opdir(RzAnalysisOp *op) {
	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_LOAD:
		op->direction = RZ_ANALYSIS_OP_DIR_READ;
		break;
	case RZ_ANALYSIS_OP_TYPE_STORE:
		op->direction = RZ_ANALYSIS_OP_DIR_WRITE;
		break;
	case RZ_ANALYSIS_OP_TYPE_LEA:
		op->direction = RZ_ANALYSIS_OP_DIR_REF;
		break;
	case RZ_ANALYSIS_OP_TYPE_CALL:
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_UCALL:
		op->direction = RZ_ANALYSIS_OP_DIR_EXEC;
		break;
	default:
		break;
	}
}

static void set_src_dst(RzAnalysisValue *val, RzReg *reg, csh *handle, cs_insn *insn, int x, int bits) {
	cs_arm_op armop = INSOP(x);
	cs_arm64_op arm64op = INSOP64(x);
	if (bits == 64) {
		parse_reg64_name(reg, &val->reg, &val->regdelta, *handle, insn, x);
	} else {
		parse_reg_name(reg, &val->reg, &val->regdelta, *handle, insn, x);
	}
	if (bits == 64) {
		switch (arm64op.type) {
		case ARM64_OP_REG:
			val->type = RZ_ANALYSIS_VAL_REG;
			break;
		case ARM64_OP_MEM:
			val->type = RZ_ANALYSIS_VAL_MEM;
			val->delta = arm64op.mem.disp;
			break;
		case ARM64_OP_IMM:
			val->type = RZ_ANALYSIS_VAL_IMM;
			val->imm = arm64op.imm;
			break;
		default:
			break;
		}
	} else {
		switch (armop.type) {
		case ARM_OP_REG:
			val->type = RZ_ANALYSIS_VAL_REG;
			break;
		case ARM_OP_MEM:
			val->type = RZ_ANALYSIS_VAL_MEM;
#if CS_API_MAJOR > 3
			val->mul = armop.mem.scale << armop.mem.lshift;
#endif
			val->delta = armop.mem.disp;
			break;
		case ARM_OP_IMM:
			val->type = RZ_ANALYSIS_VAL_IMM;
			val->imm = armop.imm;
			break;
		default:
			break;
		}
	}
}

static void create_src_dst(RzAnalysisOp *op) {
	op->src[0] = rz_analysis_value_new();
	op->src[1] = rz_analysis_value_new();
	op->src[2] = rz_analysis_value_new();
	op->dst = rz_analysis_value_new();
}

static void op_fillval(RzAnalysis *analysis, RzAnalysisOp *op, csh handle, cs_insn *insn, int bits) {
	create_src_dst(op);
	int i, j;
	int count = bits == 64 ? insn->detail->arm64.op_count : insn->detail->arm.op_count;
	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_MOV:
	case RZ_ANALYSIS_OP_TYPE_CMP:
	case RZ_ANALYSIS_OP_TYPE_ADD:
	case RZ_ANALYSIS_OP_TYPE_SUB:
	case RZ_ANALYSIS_OP_TYPE_MUL:
	case RZ_ANALYSIS_OP_TYPE_DIV:
	case RZ_ANALYSIS_OP_TYPE_SHR:
	case RZ_ANALYSIS_OP_TYPE_SHL:
	case RZ_ANALYSIS_OP_TYPE_SAL:
	case RZ_ANALYSIS_OP_TYPE_SAR:
	case RZ_ANALYSIS_OP_TYPE_OR:
	case RZ_ANALYSIS_OP_TYPE_AND:
	case RZ_ANALYSIS_OP_TYPE_XOR:
	case RZ_ANALYSIS_OP_TYPE_NOR:
	case RZ_ANALYSIS_OP_TYPE_NOT:
	case RZ_ANALYSIS_OP_TYPE_LOAD:
	case RZ_ANALYSIS_OP_TYPE_LEA:
	case RZ_ANALYSIS_OP_TYPE_ROR:
	case RZ_ANALYSIS_OP_TYPE_ROL:
	case RZ_ANALYSIS_OP_TYPE_CAST:
		for (i = 1; i < count; i++) {
#if CS_API_MAJOR > 3
			if (bits == 64) {
				cs_arm64_op arm64op = INSOP64(i);
				if (arm64op.access == CS_AC_WRITE) {
					continue;
				}
			} else {
				cs_arm_op armop = INSOP(i);

				if (armop.access == CS_AC_WRITE) {
					continue;
				}
			}
#endif
			break;
		}
		for (j = 0; j < 3; j++, i++) {
			set_src_dst(op->src[j], analysis->reg, &handle, insn, i, bits);
		}
		set_src_dst(op->dst, analysis->reg, &handle, insn, 0, bits);
		break;
	case RZ_ANALYSIS_OP_TYPE_STORE:
		if (count > 2) {
			if (bits == 64) {
				cs_arm64_op arm64op = INSOP64(count - 1);
				if (arm64op.type == ARM64_OP_IMM) {
					count--;
				}
			} else {
				cs_arm_op armop = INSOP(count - 1);
				if (armop.type == ARM_OP_IMM) {
					count--;
				}
			}
		}
		set_src_dst(op->dst, analysis->reg, &handle, insn, --count, bits);
		for (j = 0; j < 3 && j < count; j++) {
			set_src_dst(op->src[j], analysis->reg, &handle, insn, j, bits);
		}
		break;
	default:
		break;
	}
}

static void patch_capstone_bugs(cs_insn *insn, int bits, bool big_endian) {
	if (!insn->detail) {
		return;
	}
	if (bits == 32) {
		cs_arm *detail = &insn->detail->arm;

		// b40071e0    ldrht r0, [r1], -4
		// has operand 2 as immediate 4 (positive) and subtracted as false from capstone.
		// This is wrong and makes it impossible to distinguish from b400f1e0 ldrht r0, [r1], 4.
		// We just read the respective bit from the encoding.
		if (insn->id == ARM_INS_LDRHT && ISREG(0) && ISMEM(1) && ISIMM(2)) {
			ut32 op = rz_read_ble32(insn->bytes, big_endian);
			if (!(op & (1 << 23))) {
				detail->operands[2].subtracted = true;
			}
		}
	}
}

static int analysis_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	ArmCSContext *ctx = (ArmCSContext *)a->plugin_data;

	cs_insn *insn = NULL;
	int mode = (a->bits == 16) ? CS_MODE_THUMB : CS_MODE_ARM;
	int n, ret;
	mode |= (a->big_endian) ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
	if (a->cpu && strstr(a->cpu, "cortex")) {
		mode |= CS_MODE_MCLASS;
	}

	if (mode != ctx->omode || a->bits != ctx->obits) {
		cs_close(&ctx->handle);
		ctx->handle = 0; // unnecessary
		ctx->omode = mode;
		ctx->obits = a->bits;
	}
	op->size = (a->bits == 16) ? 2 : 4;
	op->addr = addr;
	if (ctx->handle == 0) {
		ret = (a->bits == 64) ? cs_open(CS_ARCH_ARM64, mode, &ctx->handle) : cs_open(CS_ARCH_ARM, mode, &ctx->handle);
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_ON);
		if (ret != CS_ERR_OK) {
			ctx->handle = 0;
			return -1;
		}
	}
	int haa = hackyArmAnal(a, op, buf, len); // TODO: disable this for capstone 5 after testing that everything works
	if (haa > 0) {
		return haa;
	}

	n = cs_disasm(ctx->handle, (ut8 *)buf, len, addr, 1, &insn);
	if (n < 1) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = strdup("invalid");
		}
	} else {
		patch_capstone_bugs(insn, a->bits, a->big_endian);
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = rz_str_newf("%s%s%s",
				insn->mnemonic,
				insn->op_str[0] ? " " : "",
				insn->op_str);
		}
		// bool thumb = cs_insn_group (handle, insn, ARM_GRP_THUMB);
		bool thumb = a->bits == 16;
		op->size = insn->size;
		op->id = insn->id;
		if (a->bits == 64) {
			anop64(ctx, op, insn);
			if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
				opex64(&op->opex, ctx->handle, insn);
			}
			if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
				rz_arm_cs_analysis_op_64_esil(a, op, addr, buf, len, &ctx->handle, insn);
			}
			if (mask & RZ_ANALYSIS_OP_MASK_IL) {
				op->il_op = rz_arm_cs_64_il(&ctx->handle, insn);
			}
		} else {
			anop32(a, ctx->handle, op, insn, thumb, (ut8 *)buf, len);
			if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
				opex(&op->opex, ctx->handle, insn);
			}
			if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
				rz_arm_cs_analysis_op_32_esil(a, op, addr, buf, len, &ctx->handle, insn, thumb);
			}
			if (mask & RZ_ANALYSIS_OP_MASK_IL) {
				op->il_op = rz_arm_cs_32_il(&ctx->handle, insn, thumb);
			}
		}
		set_opdir(op);
		if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
			op_fillval(a, op, ctx->handle, insn, a->bits);
		}
		cs_free(insn, n);
	}
	//		cs_close (&handle);
	return op->size;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	const char *p;
	if (analysis->bits == 64) {
		const char *snReg = (!strcmp(analysis->os, "android") || !strcmp(analysis->os, "linux")) ? "x8" : "x16";
		p =
			"=PC	pc\n"
			"=SP	sp\n"
			"=BP	x29\n"
			"=A0	x0\n"
			"=A1	x1\n"
			"=A2	x2\n"
			"=A3	x3\n"
			"=ZF	zf\n"
			"=SF	nf\n"
			"=OF	vf\n"
			"=CF	cf\n"
			"=SN	%s\n" // x8 on linux or android, x16 for the rest

			/* 64bit */
			"gpr	x0	.64	0	0\n"
			"gpr	x1	.64	8	0\n"
			"gpr	x2	.64	16	0\n"
			"gpr	x3	.64	24	0\n"
			"gpr	x4	.64	32	0\n"
			"gpr	x5	.64	40	0\n"
			"gpr	x6	.64	48	0\n"
			"gpr	x7	.64	56	0\n"
			"gpr	x8	.64	64	0\n"
			"gpr	x9	.64	72	0\n"
			"gpr	x10	.64	80	0\n"
			"gpr	x11	.64	88	0\n"
			"gpr	x12	.64	96	0\n"
			"gpr	x13	.64	104	0\n"
			"gpr	x14	.64	112	0\n"
			"gpr	x15	.64	120	0\n"
			"gpr	x16	.64	128	0\n"
			"gpr	x17	.64	136	0\n"
			"gpr	x18	.64	144	0\n"
			"gpr	x19	.64	152	0\n"
			"gpr	x20	.64	160	0\n"
			"gpr	x21	.64	168	0\n"
			"gpr	x22	.64	176	0\n"
			"gpr	x23	.64	184	0\n"
			"gpr	x24	.64	192	0\n"
			"gpr	x25	.64	200	0\n"
			"gpr	x26	.64	208	0\n"
			"gpr	x27	.64	216	0\n"
			"gpr	x28	.64	224	0\n"
			"gpr	x29	.64	232	0\n"
			"gpr	x30	.64	240	0\n"
			"gpr	tmp	.64	288	0\n"
			/* 32bit sub-registers */
			"gpr	w0	.32	0	0\n"
			"gpr	w1	.32	8	0\n"
			"gpr	w2	.32	16	0\n"
			"gpr	w3	.32	24	0\n"
			"gpr	w4	.32	32	0\n"
			"gpr	w5	.32	40	0\n"
			"gpr	w6	.32	48	0\n"
			"gpr	w7	.32	56	0\n"
			"gpr	w8	.32	64	0\n"
			"gpr	w9	.32	72	0\n"
			"gpr	w10	.32	80	0\n"
			"gpr	w11	.32	88	0\n"
			"gpr	w12	.32	96	0\n"
			"gpr	w13	.32	104	0\n"
			"gpr	w14	.32	112	0\n"
			"gpr	w15	.32	120	0\n"
			"gpr	w16	.32	128	0\n"
			"gpr	w17	.32	136	0\n"
			"gpr	w18	.32	144	0\n"
			"gpr	w19	.32	152	0\n"
			"gpr	w20	.32	160	0\n"
			"gpr	w21	.32	168	0\n"
			"gpr	w22	.32	176	0\n"
			"gpr	w23	.32	184	0\n"
			"gpr	w24	.32	192	0\n"
			"gpr	w25	.32	200	0\n"
			"gpr	w26	.32	208	0\n"
			"gpr	w27	.32	216	0\n"
			"gpr	w28	.32	224	0\n"
			"gpr	w29	.32	232	0\n"
			"gpr	w30	.32	240	0\n"
			"gpr	wsp	.32	248	0\n"
			"gpr	wzr	.32	?	0\n"

			/* aliases */
			"gpr	fp	.64	232	0\n" // fp = x29
			"gpr	lr	.64	240	0\n" // lr = x30
			"gpr	sp	.64	248	0\n"
			"gpr	pc	.64	256	0\n"
			"gpr	zr	.64	?	0\n"
			"gpr	xzr	.64	?	0\n"
			/* flags */
			"flg	pstate	.64	280	0   _____tfiae_____________j__qvczn\n" // x0
			//"flg	cpsr	.32	280	0\n" //	_____tfiae_____________j__qvczn\n"
			"flg	vf	.1	280.28	0	overflow\n" // set if overflows
			"flg	cf	.1	280.29	0	carry\n" // set if last op carries
			"flg	zf	.1	280.30	0	zero\n" // set if last op is 0
			"flg	nf	.1	280.31	0	sign\n" // msb bit of last op

			/* 64bit double */
			"fpu	d0	.64	0	0\n"
			"fpu	d1	.64	8	0\n"
			"fpu	d2	.64	16	0\n"
			"fpu	d3	.64	24	0\n"
			"fpu	d4	.64	32	0\n"
			"fpu	d5	.64	40	0\n"
			"fpu	d6	.64	48	0\n"
			"fpu	d7	.64	56	0\n"
			"fpu	d8	.64	64	0\n"
			"fpu	d9	.64	72	0\n"
			"fpu	d10	.64	80	0\n"
			"fpu	d11	.64	88	0\n"
			"fpu	d12	.64	96	0\n"
			"fpu	d13	.64	104	0\n"
			"fpu	d14	.64	112	0\n"
			"fpu	d15	.64	120	0\n"
			"fpu	d16	.64	128	0\n"
			"fpu	d17	.64	136	0\n"
			"fpu	d18	.64	144	0\n"
			"fpu	d19	.64	152	0\n"
			"fpu	d20	.64	160	0\n"
			"fpu	d21	.64	168	0\n"
			"fpu	d22	.64	176	0\n"
			"fpu	d23	.64	184	0\n"
			"fpu	d24	.64	192	0\n"
			"fpu	d25	.64	200	0\n"
			"fpu	d26	.64	208	0\n"
			"fpu	d27	.64	216	0\n"
			"fpu	d28	.64	224	0\n"
			"fpu	d29	.64	232	0\n"
			"fpu	d30	.64	240	0\n"
			"fpu	dsp	.64	248	0\n"
			/* 32bit float sub-registers */
			"fpu	s0	.32	0	0\n"
			"fpu	s1	.32	8	0\n"
			"fpu	s2	.32	16	0\n"
			"fpu	s3	.32	24	0\n"
			"fpu	s4	.32	32	0\n"
			"fpu	s5	.32	40	0\n"
			"fpu	s6	.32	48	0\n"
			"fpu	s7	.32	56	0\n"
			"fpu	s8	.32	64	0\n"
			"fpu	s9	.32	72	0\n"
			"fpu	s10	.32	80	0\n"
			"fpu	s11	.32	88	0\n"
			"fpu	s12	.32	96	0\n"
			"fpu	s13	.32	104	0\n"
			"fpu	s14	.32	112	0\n"
			"fpu	s15	.32	120	0\n"
			"fpu	s16	.32	128	0\n"
			"fpu	s17	.32	136	0\n"
			"fpu	s18	.32	144	0\n"
			"fpu	s19	.32	152	0\n"
			"fpu	s20	.32	160	0\n"
			"fpu	s21	.32	168	0\n"
			"fpu	s22	.32	176	0\n"
			"fpu	s23	.32	184	0\n"
			"fpu	s24	.32	192	0\n"
			"fpu	s25	.32	200	0\n"
			"fpu	s26	.32	208	0\n"
			"fpu	s27	.32	216	0\n"
			"fpu	s28	.32	224	0\n"
			"fpu	s29	.32	232	0\n"
			"fpu	s30	.32	240	0\n"
			/* 16bit sub-registers */
			"fpu	h0	.16	0	0\n"
			"fpu	h1	.16	8	0\n"
			"fpu	h2	.16	16	0\n"
			"fpu	h3	.16	24	0\n"
			"fpu	h4	.16	32	0\n"
			"fpu	h5	.16	40	0\n"
			"fpu	h6	.16	48	0\n"
			"fpu	h7	.16	56	0\n"
			"fpu	h8	.16	64	0\n"
			"fpu	h9	.16	72	0\n"
			"fpu	h10	.16	80	0\n"
			"fpu	h11	.16	88	0\n"
			"fpu	h12	.16	96	0\n"
			"fpu	h13	.16	104	0\n"
			"fpu	h14	.16	112	0\n"
			"fpu	h15	.16	120	0\n"
			"fpu	h16	.16	128	0\n"
			"fpu	h17	.16	136	0\n"
			"fpu	h18	.16	144	0\n"
			"fpu	h19	.16	152	0\n"
			"fpu	h20	.16	160	0\n"
			"fpu	h21	.16	168	0\n"
			"fpu	h22	.16	176	0\n"
			"fpu	h23	.16	184	0\n"
			"fpu	h24	.16	192	0\n"
			"fpu	h25	.16	200	0\n"
			"fpu	h26	.16	208	0\n"
			"fpu	h27	.16	216	0\n"
			"fpu	h28	.16	224	0\n"
			"fpu	h29	.16	232	0\n"
			"fpu	h30	.16	240	0\n"
			/* 8bit sub-registers */
			"fpu	b0	.8	0	0\n"
			"fpu	b1	.8	8	0\n"
			"fpu	b2	.8	16	0\n"
			"fpu	b3	.8	24	0\n"
			"fpu	b4	.8	32	0\n"
			"fpu	b5	.8	40	0\n"
			"fpu	b6	.8	48	0\n"
			"fpu	b7	.8	56	0\n"
			"fpu	b8	.8	64	0\n"
			"fpu	b9	.8	72	0\n"
			"fpu	b10	.8	80	0\n"
			"fpu	b11	.8	88	0\n"
			"fpu	b12	.8	96	0\n"
			"fpu	b13	.8	104	0\n"
			"fpu	b14	.8	112	0\n"
			"fpu	b15	.8	120	0\n"
			"fpu	b16	.8	128	0\n"
			"fpu	b17	.8	136	0\n"
			"fpu	b18	.8	144	0\n"
			"fpu	b19	.8	152	0\n"
			"fpu	b20	.8	160	0\n"
			"fpu	b21	.8	168	0\n"
			"fpu	b22	.8	176	0\n"
			"fpu	b23	.8	184	0\n"
			"fpu	b24	.8	192	0\n"
			"fpu	b25	.8	200	0\n"
			"fpu	b26	.8	208	0\n"
			"fpu	b27	.8	216	0\n"
			"fpu	b28	.8	224	0\n"
			"fpu	b29	.8	232	0\n"
			"fpu	b30	.8	240	0\n"
			"fpu	bsp	.8	248	0\n";
		return rz_str_newf(p, snReg);
	} else {
		p =
			"=PC	r15\n"
			"=LR	r14\n"
			"=SP	sp\n"
			"=BP	fp\n"
			"=A0	r0\n"
			"=A1	r1\n"
			"=A2	r2\n"
			"=A3	r3\n"
			"=ZF	zf\n"
			"=SF	nf\n"
			"=OF	vf\n"
			"=CF	cf\n"
			"=SN	r7\n"
			"gpr	sb	.32	36	0\n" // r9
			"gpr	sl	.32	40	0\n" // rl0
			"gpr	fp	.32	44	0\n" // r11
			"gpr	ip	.32	48	0\n" // r12
			"gpr	sp	.32	52	0\n" // r13
			"gpr	lr	.32	56	0\n" // r14
			"gpr	pc	.32	60	0\n" // r15

			"gpr	r0	.32	0	0\n"
			"gpr	r1	.32	4	0\n"
			"gpr	r2	.32	8	0\n"
			"gpr	r3	.32	12	0\n"
			"gpr	r4	.32	16	0\n"
			"gpr	r5	.32	20	0\n"
			"gpr	r6	.32	24	0\n"
			"gpr	r7	.32	28	0\n"
			"gpr	r8	.32	32	0\n"
			"gpr	r9	.32	36	0\n"
			"gpr	r10	.32	40	0\n"
			"gpr	r11	.32	44	0\n"
			"gpr	r12	.32	48	0\n"
			"gpr	r13	.32	52	0\n"
			"gpr	r14	.32	56	0\n"
			"gpr	r15	.32	60	0\n"
			"flg	cpsr	.32	64	0\n"

			// CPSR bit fields:
			// 576-580 Mode fields (and register sets associated to each field):
			// 10000 	User 	R0-R14, CPSR, PC
			// 10001 	FIQ 	R0-R7, R8_fiq-R14_fiq, CPSR, SPSR_fiq, PC
			// 10010 	IRQ 	R0-R12, R13_irq, R14_irq, CPSR, SPSR_irq, PC
			// 10011 	SVC (supervisor) 	R0-R12, R13_svc R14_svc CPSR, SPSR_irq, PC
			// 10111 	Abort 	R0-R12, R13_abt R14_abt CPSR, SPSR_abt PC
			// 11011 	Undefined 	R0-R12, R13_und R14_und, CPSR, SPSR_und PC
			// 11111 	System (ARMv4+) 	R0-R14, CPSR, PC
			"flg	tf	.1	.517	0	thumb\n" // +5
			// 582 FIQ disable bit
			// 583 IRQ disable bit
			// 584 Disable imprecise aborts flag
			"flg	ef	.1	.521	0	endian\n" // +9
			"flg	itc	.4	.522	0	if_then_count\n" // +10
			// Reserved
			"flg	gef	.4	.528	0	great_or_equal\n" // +16
			"flg	jf	.1	.536	0	java\n" // +24
			// Reserved
			"flg	qf	.1	.539	0	sticky_overflow\n" // +27
			"flg	vf	.1	.540	0	overflow\n" // +28
			"flg	cf	.1	.541	0	carry\n" // +29
			"flg	zf	.1	.542	0	zero\n" // +30
			"flg	nf	.1	.543	0	negative\n" // +31

			/* NEON and VFP registers */
			/* 32bit float sub-registers */
			"fpu	s0	.32	68	0\n"
			"fpu	s1	.32	72	0\n"
			"fpu	s2	.32	76	0\n"
			"fpu	s3	.32	80	0\n"
			"fpu	s4	.32	84	0\n"
			"fpu	s5	.32	88	0\n"
			"fpu	s6	.32	92	0\n"
			"fpu	s7	.32	96	0\n"
			"fpu	s8	.32	100	0\n"
			"fpu	s9	.32	104	0\n"
			"fpu	s10	.32	108	0\n"
			"fpu	s11	.32	112	0\n"
			"fpu	s12	.32	116	0\n"
			"fpu	s13	.32	120	0\n"
			"fpu	s14	.32	124	0\n"
			"fpu	s15	.32	128	0\n"
			"fpu	s16	.32	132	0\n"
			"fpu	s17	.32	136	0\n"
			"fpu	s18	.32	140	0\n"
			"fpu	s19	.32	144	0\n"
			"fpu	s20	.32	148	0\n"
			"fpu	s21	.32	152	0\n"
			"fpu	s22	.32	156	0\n"
			"fpu	s23	.32	160	0\n"
			"fpu	s24	.32	164	0\n"
			"fpu	s25	.32	168	0\n"
			"fpu	s26	.32	172	0\n"
			"fpu	s27	.32	176	0\n"
			"fpu	s28	.32	180	0\n"
			"fpu	s29	.32	184	0\n"
			"fpu	s30	.32	188	0\n"
			"fpu	s31	.32	192	0\n"

			/* 64bit double */
			"fpu	d0	.64	68	0\n"
			"fpu	d1	.64	76	0\n"
			"fpu	d2	.64	84	0\n"
			"fpu	d3	.64	92	0\n"
			"fpu	d4	.64	100	0\n"
			"fpu	d5	.64	108	0\n"
			"fpu	d6	.64	116	0\n"
			"fpu	d7	.64	124	0\n"
			"fpu	d8	.64	132	0\n"
			"fpu	d9	.64	140	0\n"
			"fpu	d10	.64	148	0\n"
			"fpu	d11	.64	156	0\n"
			"fpu	d12	.64	164	0\n"
			"fpu	d13	.64	172	0\n"
			"fpu	d14	.64	180	0\n"
			"fpu	d15	.64	188	0\n"
			"fpu	d16	.64	196	0\n"
			"fpu	d17	.64	204	0\n"
			"fpu	d18	.64	212	0\n"
			"fpu	d19	.64	220	0\n"
			"fpu	d20	.64	228	0\n"
			"fpu	d21	.64	236	0\n"
			"fpu	d22	.64	244	0\n"
			"fpu	d23	.64	252	0\n"
			"fpu	d24	.64	260	0\n"
			"fpu	d25	.64	268	0\n"
			"fpu	d26	.64	276	0\n"
			"fpu	d27	.64	284	0\n"
			"fpu	d28	.64	292	0\n"
			"fpu	d29	.64	300	0\n"
			"fpu	d30	.64	308	0\n"
			"fpu	d31	.64	316	0\n"

			/* 128bit double */
			"fpu	q0	.128	68	0\n"
			"fpu	q1	.128	84	0\n"
			"fpu	q2	.128	100	0\n"
			"fpu	q3	.128	116	0\n"
			"fpu	q4	.128	132	0\n"
			"fpu	q5	.128	148	0\n"
			"fpu	q6	.128	164	0\n"
			"fpu	q7	.128	180	0\n"
			"fpu	q8	.128	196	0\n"
			"fpu	q9	.128	212	0\n"
			"fpu	q10	.128	228	0\n"
			"fpu	q11	.128	244	0\n"
			"fpu	q12	.128	260	0\n"
			"fpu	q13	.128	276	0\n"
			"fpu	q14	.128	292	0\n"
			"fpu	q15	.128	308	0\n";
	}
	return strdup(p);
}

static int archinfo(RzAnalysis *analysis, int q) {
	if (q == RZ_ANALYSIS_ARCHINFO_DATA_ALIGN) {
		return 4;
	}
	if (q == RZ_ANALYSIS_ARCHINFO_ALIGN) {
		if (analysis && analysis->bits == 16) {
			return 2;
		}
		return 4;
	}
	if (q == RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE) {
		return 4;
	}
	if (q == RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE) {
		if (analysis && analysis->bits == 16) {
			return 2;
		}
		return 4;
	}
	return 4; // XXX
}

static ut8 *analysis_mask(RzAnalysis *analysis, int size, const ut8 *data, ut64 at) {
	RzAnalysisOp *op = NULL;
	ut8 *ret = NULL;
	int oplen, idx = 0, obits = analysis->bits;
	RzAnalysisHint *hint = NULL;

	if (!data) {
		return NULL;
	}

	op = rz_analysis_op_new();
	ret = malloc(size);
	memset(ret, 0xff, size);

	while (idx < size) {
		hint = rz_analysis_hint_get(analysis, at + idx);
		if (hint) {
			if (hint->bits != 0) {
				analysis->bits = hint->bits;
			}
			free(hint);
		}

		if ((oplen = analysis_op(analysis, op, at + idx, data + idx, size - idx, RZ_ANALYSIS_OP_MASK_BASIC)) < 1) {
			break;
		}
		if (op->ptr != UT64_MAX || op->jump != UT64_MAX) {
			if ((oplen * 8) > size - idx) {
				break;
			}
			ut32 opcode = rz_read_ble(data + idx, analysis->big_endian, oplen * 8);
			switch (oplen) {
			case 2:
				memcpy(ret + idx, "\xf0\x00", 2);
				break;
			case 4:
				if (analysis->bits == 64) {
					switch (op->id) {
					case ARM64_INS_LDP:
					case ARM64_INS_LDXP:
					case ARM64_INS_LDXR:
					case ARM64_INS_LDXRB:
					case ARM64_INS_LDXRH:
					case ARM64_INS_LDPSW:
					case ARM64_INS_LDNP:
					case ARM64_INS_LDTR:
					case ARM64_INS_LDTRB:
					case ARM64_INS_LDTRH:
					case ARM64_INS_LDTRSB:
					case ARM64_INS_LDTRSH:
					case ARM64_INS_LDTRSW:
					case ARM64_INS_LDUR:
					case ARM64_INS_LDURB:
					case ARM64_INS_LDURH:
					case ARM64_INS_LDURSB:
					case ARM64_INS_LDURSH:
					case ARM64_INS_LDURSW:
					case ARM64_INS_STP:
					case ARM64_INS_STNP:
					case ARM64_INS_STXR:
					case ARM64_INS_STXRB:
					case ARM64_INS_STXRH:
						rz_write_ble(ret + idx, 0xffffffff, analysis->big_endian, 32);
						break;
					case ARM64_INS_STRB:
					case ARM64_INS_STURB:
					case ARM64_INS_STURH:
					case ARM64_INS_STUR:
					case ARM64_INS_STR:
					case ARM64_INS_STTR:
					case ARM64_INS_STTRB:
					case ARM64_INS_STRH:
					case ARM64_INS_STTRH:
					case ARM64_INS_LDR:
					case ARM64_INS_LDRB:
					case ARM64_INS_LDRH:
					case ARM64_INS_LDRSB:
					case ARM64_INS_LDRSW:
					case ARM64_INS_LDRSH: {
						bool is_literal = (opcode & 0x38000000) == 0x18000000;
						if (is_literal) {
							rz_write_ble(ret + idx, 0xff000000, analysis->big_endian, 32);
						} else {
							rz_write_ble(ret + idx, 0xffffffff, analysis->big_endian, 32);
						}
						break;
					}
					case ARM64_INS_B:
					case ARM64_INS_BL:
					case ARM64_INS_CBZ:
					case ARM64_INS_CBNZ:
						if (op->type == RZ_ANALYSIS_OP_TYPE_CJMP) {
							rz_write_ble(ret + idx, 0xff00001f, analysis->big_endian, 32);
						} else {
							rz_write_ble(ret + idx, 0xfc000000, analysis->big_endian, 32);
						}
						break;
					case ARM64_INS_TBZ:
					case ARM64_INS_TBNZ:
						rz_write_ble(ret + idx, 0xfff8001f, analysis->big_endian, 32);
						break;
					case ARM64_INS_ADR:
					case ARM64_INS_ADRP:
						rz_write_ble(ret + idx, 0xff00001f, analysis->big_endian, 32);
						break;
					default:
						rz_write_ble(ret + idx, 0xfff00000, analysis->big_endian, 32);
					}
				} else {
					rz_write_ble(ret + idx, 0xfff00000, analysis->big_endian, 32);
				}
				break;
			}
		}
		idx += oplen;
	}

	analysis->bits = obits;
	rz_analysis_op_free(op);

	return ret;
}

static RzList *analysis_preludes(RzAnalysis *analysis) {
#define KW(d, ds, m, ms) rz_list_append(l, rz_search_keyword_new((const ut8 *)d, ds, (const ut8 *)m, ms, NULL))
	RzList *l = rz_list_newf((RzListFree)rz_search_keyword_free);
	switch (analysis->bits) {
	case 16:
		KW("\x00\xb5", 2, "\x0f\xff", 2);
		KW("\x08\xb5", 2, "\x0f\xff", 2);
		break;
	case 32:
		KW("\x00\x00\x2d\xe9", 4, "\x0f\x0f\xff\xff", 4);
		break;
	case 64:
		KW("\xf0\x0f\x00\xf8", 4, "\xf0\x0f\x00\xff", 4);
		KW("\xf0\x00\x00\xd1", 4, "\xf0\x00\x00\xff", 4);
		KW("\xf0\x00\x00\xa9", 4, "\xf0\x00\x00\xff", 4);
		KW("\x7f\x23\x03\xd5\xff", 5, NULL, 0);
		break;
	default:
		rz_list_free(l);
		l = NULL;
	}
	return l;
}

static int address_bits(RzAnalysis *analysis, int bits) {
	// thumb still has 32bit addrs, all other cases use the default behavior (-1)
	return bits == 16 ? 32 : -1;
}

static bool init(void **user) {
	ArmCSContext *ctx = RZ_NEW0(ArmCSContext);
	if (!ctx) {
		return false;
	}
	rz_arm_it_context_init(&ctx->it);
	ctx->handle = 0;
	ctx->omode = -1;
	ctx->obits = 32;
	*user = ctx;
	return true;
}

static bool fini(void *user) {
	rz_return_val_if_fail(user, false);
	ArmCSContext *ctx = (ArmCSContext *)user;
	cs_close(&ctx->handle);
	rz_arm_it_context_fini(&ctx->it);
	free(ctx);
	return true;
}

static RzAnalysisILConfig *il_config(RzAnalysis *analysis) {
	if (analysis->bits == 64) {
		return rz_arm_cs_64_il_config(analysis->big_endian);
	}
	return rz_arm_cs_32_il_config(analysis->big_endian);
}

RzAnalysisPlugin rz_analysis_plugin_arm_cs = {
	.name = "arm",
	.desc = "Capstone ARM analyzer",
	.license = "BSD",
	.esil = true,
	.arch = "arm",
	.archinfo = archinfo,
	.get_reg_profile = get_reg_profile,
	.analysis_mask = analysis_mask,
	.preludes = analysis_preludes,
	.bits = 16 | 32 | 64,
	.address_bits = address_bits,
	.op = &analysis_op,
	.il_config = il_config,
	.init = &init,
	.fini = &fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_arm_cs,
	.version = RZ_VERSION
};
#endif
