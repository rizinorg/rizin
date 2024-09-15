// SPDX-FileCopyrightText: 2024 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <rx/rx.h>

static void calculate_jmp_addr(RxInst *inst, RzAnalysisOp *op) {
	if (inst->v0.kind == RX_OPERAND_COND) {
		ut8 pcdsp_l = inst->v0.v.cond.pc_dsp_len;
		ut32 pcdsp_val = inst->v0.v.cond.pc_dsp_val;
		ut64 addr_inc = pcdsp_val;
		if (pcdsp_l >= 8) {
			// as SIMM, use signed extend
			ut8 shift = pcdsp_l - 1;
			if ((1 << shift) & pcdsp_val) {
				// as negative
				ut32 mask = 0xffffffff << shift;
				addr_inc = abs((st32)(pcdsp_val | mask));
				op->jump = op->addr - addr_inc;
				return;
			}
		}
		op->jump = op->addr + addr_inc;
	}
	op->fail = op->addr + op->size;
}

static int rx_operand_cnt(RxInst *inst) {
	int cnt = 0;
	if (inst->v0.kind != RX_OPERAND_NULL) {
		cnt++;
	}
	if (inst->v1.kind != RX_OPERAND_NULL) {
		cnt++;
	}
	if (inst->v2.kind != RX_OPERAND_NULL) {
		cnt++;
	}
	return cnt;
}

static inline RxOperand *rx_operand_get(RxInst *inst, int idx) {
	if (idx >= rx_operand_cnt(inst)) {
		RZ_LOG_WARN("Failed to get operand%d of ISA Renesas Rx\n", idx);
		rz_warn_if_reached();
		return NULL;
	}
	switch (idx) {
	case 0:
		return &inst->v0;
	case 1:
		return &inst->v1;
	case 2:
		return &inst->v2;
	default:
		return NULL;
	}
}

static int analysis_rx_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask) {
	op->addr = addr;
	op->type = RZ_ANALYSIS_OP_TYPE_ILL;

	RxInst inst = { 0 };
	st32 bytes_read = 0;
	if (!rx_dis(&inst, &bytes_read, buf, len)) {
		return bytes_read;
	} else {
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	}

	op->size = bytes_read;
	switch (inst.op) {
	// jump related instructions
	case RX_OP_RTS:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = 4;
		break;
	case RX_OP_RTSD:
		// use register to deallocate stack frames
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case RX_OP_BSR_A:
	case RX_OP_BSR_W:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		calculate_jmp_addr(&inst, op);
		break;
	case RX_OP_BCND_W:
	case RX_OP_BCND_B:
	case RX_OP_BCND_S:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		calculate_jmp_addr(&inst, op);
		break;
	case RX_OP_BRA_A:
	case RX_OP_BRA_B:
	case RX_OP_BRA_S:
	case RX_OP_BRA_W:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		calculate_jmp_addr(&inst, op);
		break;
	case RX_OP_BRA_L:
	case RX_OP_JMP:
		// use register to jump unconditionally
		op->type = RZ_ANALYSIS_OP_TYPE_IRJMP;
		break;
	case RX_OP_BSR_L:
	case RX_OP_JSR:
		// use register to call unconditionally
		op->type = RZ_ANALYSIS_OP_TYPE_IRCALL;
		break;

	// stack related operations
	case RX_OP_PUSH:
	case RX_OP_PUSHC:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		op->stackop = RZ_ANALYSIS_STACK_DEC;
		op->stackptr = 4;
		break;
	case RX_OP_PUSHM:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		op->stackop = RZ_ANALYSIS_STACK_DEC;
		op->stackptr = 4 * (inst.v1.v.reg.reg - inst.v0.v.reg.reg + 1);
		break;
	case RX_OP_POP:
	case RX_OP_POPM:
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = 4;
		break;
	case RX_OP_POPC:
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = 4 * (inst.v1.v.reg.reg - inst.v0.v.reg.reg + 1);
		break;

	// normal instruction
	case RX_OP_ADD_UB:
	case RX_OP_ADC:
		// add imm, rn, rm
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case RX_OP_ADD:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		if (rx_operand_cnt(&inst) == 2) {
			// add imm, sp
			const RxOperand *op0 = rx_operand_get(&inst, 0);
			if (op0->kind == RX_OPERAND_IMM) {
				const RxOperand *op1 = rx_operand_get(&inst, 1);
				if (op1->kind == RX_OPERAND_REG && op1->v.reg.reg == RX_REG_R0) {
					// modify SP
					op->stackop = RZ_ANALYSIS_STACK_INC;
					op->stackptr = op0->v.imm.imm;
				}
			}
		}
		break;
	case RX_OP_SUB:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		if (rx_operand_cnt(&inst) == 2) {
			// sub imm, sp
			const RxOperand *op0 = rx_operand_get(&inst, 0);
			if (op0->kind == RX_OPERAND_IMM) {
				const RxOperand *op1 = rx_operand_get(&inst, 1);
				if (op1->kind == RX_OPERAND_REG && op1->v.reg.reg == RX_REG_R0) {
					// modify SP
					op->stackop = RZ_ANALYSIS_STACK_DEC;
					op->stackptr = op0->v.imm.imm;
				}
			}
		}
		break;
	case RX_OP_SUB_UB:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case RX_OP_DIV:
	case RX_OP_DIV_UB:
	case RX_OP_DIVU:
	case RX_OP_DIVU_UB:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case RX_OP_MUL:
	case RX_OP_MULLO:
	case RX_OP_EMUL:
	case RX_OP_EMULU:
	case RX_OP_EMULU_UB:
	case RX_OP_EMUL_UB:
	case RX_OP_MUL_UB:
	case RX_OP_MULHI:
	case RX_OP_MACHI:
	case RX_OP_MACLO:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case RX_OP_AND:
	case RX_OP_AND_UB:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case RX_OP_OR:
	case RX_OP_OR_UB:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case RX_OP_NOT:
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case RX_OP_NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case RX_OP_NEG:
		op->type = RZ_ANALYSIS_OP_TYPE_CPL;
		break;
	case RX_OP_CMP:
	case RX_OP_CMP_UB:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case RX_OP_ROTL:
	case RX_OP_ROLC:
		op->type = RZ_ANALYSIS_OP_TYPE_ROL;
		break;
	case RX_OP_ROTR:
	case RX_OP_RORC:
		op->type = RZ_ANALYSIS_OP_TYPE_ROR;
		break;
	case RX_OP_SHAR:
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		break;
	case RX_OP_SHLR:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case RX_OP_SHLL:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case RX_OP_XCHG_UB:
	case RX_OP_XCHG:
		op->type = RZ_ANALYSIS_OP_TYPE_XCHG;
		break;
	case RX_OP_XOR:
	case RX_OP_XOR_UB:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case RX_OP_INT:
	case RX_OP_RTE:
	case RX_OP_RTFI:
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		break;
	case RX_OP_MOV:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		if (rx_operand_cnt(&inst) == 2) {
			// mov sp, rn
			const RxOperand *op0 = rx_operand_get(&inst, 0);
			const RxOperand *op1 = rx_operand_get(&inst, 1);
			if (op0->kind == RX_OPERAND_IMM) {
				if (op1->kind == RX_OPERAND_REG && op1->v.reg.reg == RX_REG_R0) {
					// modify SP
					op->stackop = RZ_ANALYSIS_STACK_SET;
					op->stackptr = op0->v.imm.imm;
				}
			}
		}
		break;
	case RX_OP_MOVU:
	case RX_OP_MVTIPL:
	case RX_OP_MVTC:
	case RX_OP_MVTACLO:
	case RX_OP_MVTACHI:
	case RX_OP_MVFACMI:
	case RX_OP_MVFACHI:
	case RX_OP_MVFC:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case RX_OP_ABS:
		op->type = RZ_ANALYSIS_OP_TYPE_ABS;
		break;

	// FPU
	case RX_OP_FADD:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case RX_OP_FSUB:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case RX_OP_FMUL:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case RX_OP_FDIV:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case RX_OP_FCMP:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case RX_OP_ITOF:
	case RX_OP_FTOI:
	case RX_OP_ITOF_UB:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	default:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	}

	return op->size;
}

static char *analysis_rx_reg_profile(RzAnalysis *analysis) {
	// check librz/reg/profile for register profile description
	const char *p =
		"=PC    pc\n"
		"=SP    r0\n"
		"=ZF    zf\n"
		"=CF    cf\n"
		"=SF    sf\n"
		"=OF    of\n"
		// ABI: https://www.renesas.com/us/en/document/mat/cc-rx-compiler-users-manual
		"=R0    r1\n"
		"=A0    r1\n"
		"=A1    r2\n"
		"=A2    r3\n"
		"=A3    r4\n"
		// general
		"gpr    r0   .32    0    0\n"
		"gpr    r1   .32    4    0\n"
		"gpr    r2   .32    8    0\n"
		"gpr    r3   .32    12    0\n"
		"gpr    r4   .32    16    0\n"
		"gpr    r5   .32    20    0\n"
		"gpr    r6   .32    24    0\n"
		"gpr    r7   .32    28    0\n"
		"gpr    r8   .32    32    0\n"
		"gpr    r9   .32    36    0\n"
		"gpr    r10   .32    40    0\n"
		"gpr    r11   .32    44    0\n"
		"gpr    r12   .32    48    0\n"
		"gpr    r13   .32    52    0\n"
		"gpr    r14   .32    56    0\n"
		"gpr    r15   .32    60    0\n"
		// control register
		"gpr    isp   .32    64    0\n"
		"gpr    usp   .32    68    0\n"
		"gpr    intb  .32    72    0\n"
		"gpr    pc    .32    76    0\n"

		// psw
		"gpr    psw   .32    80    0\n"
		"flg    ipl   .4     .644  0\n"
		"flg    pm    .1     .651  0\n"
		"flg    u     .1     .654  0\n"
		"flg    i     .1     .655  0\n"
		"flg    of    .1     .668  0\n"
		"flg    sf    .1     .669  0\n"
		"flg    zf    .1     .670  0\n"
		"flg    cf    .1     .671  0\n"

		"gpr    bpc   .32    84    0\n"
		"gpr    bpsw  .32    88    0\n"
		"gpr    fintv .32    92    0\n"

		// fpsw, contains multiple flags but ignore now
		"gpr    fpsw  .32    96    0\n"
		"flg    fsf   .1     .768  0\n"
		"flg    fxf   .1     .769  0\n"
		"flg    fuf   .1     .770  0\n"
		"flg    fzf   .1     .771  0\n"
		"flg    fof   .1     .772  0\n"
		"flg    fvf   .1     .773  0\n"
		"flg    rmode   .2   .798  0\n";
	return rz_str_dup(p);
}

RzAnalysisPlugin rz_analysis_plugin_rx = {
	.name = "rx",
	.arch = "rx",
	.desc = "Renesas RX Family analysis",
	.license = "LGPL3",
	.bits = 32,
	.op = &analysis_rx_op,
	.get_reg_profile = &analysis_rx_reg_profile,
};
