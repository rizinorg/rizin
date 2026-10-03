// SPDX-FileCopyrightText: 2012-2015 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2015 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2012-2015 Bhootravi <ravi2809@gmail.com>
// SPDX-FileCopyrightText: 2025 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_util.h>

#include <h8300/h8300_disas.h>

#define INS_OP(I) (cmd.ops[(I)])

/* The CPU names currently select a 16-bit H8/300 or an advanced-mode H8/300H.
 * Do not use analysis->bits here: the plugin advertises 16 for both CPUs. */
static ut64 h8300_address(const H8300Instruction *cmd, ut64 address) {
	rz_return_val_if_fail(cmd, address);
	return address & (cmd->cpu_type == CPU_H8300H ? 0xffffff : 0xffff);
}

static H8300Register h8300_sp(const H8300Instruction *cmd) {
	rz_return_val_if_fail(cmd, H8300_REG_INVALID);
	return cmd->cpu_type == CPU_H8300H ? H8300H_SP : H8300_SP;
}

static int h8300_return_size(const H8300Instruction *cmd) {
	rz_return_val_if_fail(cmd, 0);
	return cmd->cpu_type == CPU_H8300H ? 4 : 2;
}

static bool h8300_control_target(const H8300Instruction *cmd) {
	rz_return_val_if_fail(cmd, false);
	return (cmd->id >= H8300_INSN_BRA && cmd->id <= H8300_INSN_BLE) ||
		cmd->id == H8300_INSN_BSR || cmd->id == H8300_INSN_JSR || cmd->id == H8300_INSN_JMP;
}

static int h8300_data_size(H8300InsnId id) {
	switch (id) {
	case H8300_INSN_MOV_W:
	case H8300_INSN_ADD_W:
	case H8300_INSN_CMP_W:
	case H8300_INSN_XOR_W:
	case H8300_INSN_AND_W:
	case H8300_INSN_STC_W:
	case H8300_INSN_LDC_W:
	case H8300_INSN_INC_W:
	case H8300_INSN_ROTL_W:
	case H8300_INSN_ROTR_W:
	case H8300_INSN_ROTXL_W:
	case H8300_INSN_ROTXR_W:
	case H8300_INSN_SHAL_W:
	case H8300_INSN_SHAR_W:
	case H8300_INSN_SHLL_W:
	case H8300_INSN_SHLR_W:
	case H8300_INSN_NEG_W:
	case H8300_INSN_NOT_W:
	case H8300_INSN_OR_W:
	case H8300_INSN_SUB_W:
	case H8300_INSN_DEC_W:
	case H8300_INSN_MULXU_W:
	case H8300_INSN_MULXS_W:
	case H8300_INSN_DIVXU_W:
	case H8300_INSN_DIVXS_W:
	case H8300_INSN_EXTS_W:
	case H8300_INSN_EXTU_W:
	case H8300_INSN_POP_W:
	case H8300_INSN_PUSH_W:
		return 2;
	case H8300_INSN_MOV_L:
	case H8300_INSN_ADD_L:
	case H8300_INSN_CMP_L:
	case H8300_INSN_XOR_L:
	case H8300_INSN_AND_L:
	case H8300_INSN_INC_L:
	case H8300_INSN_ROTL_L:
	case H8300_INSN_ROTR_L:
	case H8300_INSN_ROTXL_L:
	case H8300_INSN_ROTXR_L:
	case H8300_INSN_SHAL_L:
	case H8300_INSN_SHAR_L:
	case H8300_INSN_SHLL_L:
	case H8300_INSN_SHLR_L:
	case H8300_INSN_NEG_L:
	case H8300_INSN_NOT_L:
	case H8300_INSN_OR_L:
	case H8300_INSN_SUB_L:
	case H8300_INSN_DEC_L:
	case H8300_INSN_EXTS_L:
	case H8300_INSN_EXTU_L:
	case H8300_INSN_POP_L:
	case H8300_INSN_PUSH_L:
		return 4;
	default: return 1; /* Bit operations and peripheral transfers access bytes. */
	}
}

static bool h8300_memory_operand(const H8300Instruction *cmd, const H8300Operand *operand) {
	rz_return_val_if_fail(cmd && operand, false);
	switch (operand->typ) {
	case H8300_OP_ABS:
	case H8300_OP_RI:
		return !h8300_control_target(cmd);
	case H8300_OP_MI8:
	case H8300_OP_RD:
	case H8300_OP_RPOSTINC:
	case H8300_OP_RPREDEC:
		return true;
	default: return false;
	}
}

static H8300Register h8300_operand_reg(const H8300Operand *operand) {
	rz_return_val_if_fail(operand, H8300_REG_INVALID);
	switch (operand->typ) {
	case H8300_OP_R8:
	case H8300_OP_R16:
	case H8300_OP_R32:
	case H8300_OP_RI:
	case H8300_OP_RPOSTINC:
	case H8300_OP_RPREDEC:
		return operand->reg;
	case H8300_OP_RD:
		return operand->rd.reg;
	default: return H8300_REG_INVALID;
	}
}

static RzAnalysisValueAccess h8300_operand_access(const H8300Instruction *cmd, size_t i) {
	rz_return_val_if_fail(cmd, RZ_ANALYSIS_ACC_UNKNOWN);
	if (i >= cmd->ops_count) {
		return RZ_ANALYSIS_ACC_UNKNOWN;
	}
	if (h8300_control_target(cmd) || i + 1 < cmd->ops_count) {
		return RZ_ANALYSIS_ACC_R;
	}
	switch (cmd->id) {
	case H8300_INSN_CMP_B:
	case H8300_INSN_CMP_W:
	case H8300_INSN_CMP_L:
	case H8300_INSN_BTST:
	case H8300_INSN_BLD:
	case H8300_INSN_BILD:
	case H8300_INSN_BAND:
	case H8300_INSN_BIAND:
	case H8300_INSN_BOR:
	case H8300_INSN_BIOR:
	case H8300_INSN_BXOR:
	case H8300_INSN_BIXOR:
	case H8300_INSN_PUSH_W:
	case H8300_INSN_PUSH_L:
	case H8300_INSN_TRAPA:
		return RZ_ANALYSIS_ACC_R;
	case H8300_INSN_MOV_B:
	case H8300_INSN_MOV_W:
	case H8300_INSN_MOV_L:
	case H8300_INSN_MOVFPE:
	case H8300_INSN_MOVTPE:
	case H8300_INSN_LDC_B:
	case H8300_INSN_LDC_W:
	case H8300_INSN_STC_B:
	case H8300_INSN_STC_W:
	case H8300_INSN_POP_W:
	case H8300_INSN_POP_L:
		return RZ_ANALYSIS_ACC_W;
	default:
		return RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W;
	}
}

static RzAnalysisValueAccess h8300_ccr_access(const H8300Instruction *cmd) {
	rz_return_val_if_fail(cmd, RZ_ANALYSIS_ACC_UNKNOWN);
	if (cmd->id >= H8300_INSN_BHI && cmd->id <= H8300_INSN_BLE) {
		return RZ_ANALYSIS_ACC_R;
	}
	switch (cmd->id) {
	case H8300_INSN_BST:
	case H8300_INSN_BIST:
		return RZ_ANALYSIS_ACC_R;
	case H8300_INSN_RTE:
		return RZ_ANALYSIS_ACC_W;
	case H8300_INSN_INVALID:
	case H8300_INSN_NOP:
	case H8300_INSN_SLEEP:
	case H8300_INSN_ADDS:
	case H8300_INSN_SUBS:
	case H8300_INSN_BRA:
	case H8300_INSN_BRN:
	case H8300_INSN_BSR:
	case H8300_INSN_JMP:
	case H8300_INSN_JSR:
	case H8300_INSN_RTS:
	case H8300_INSN_EEPMOV_B:
	case H8300_INSN_EEPMOV_W:
	case H8300_INSN_MULXU_B:
	case H8300_INSN_MULXU_W:
	case H8300_INSN_BSET:
	case H8300_INSN_BCLR:
	case H8300_INSN_BNOT:
	case H8300_INSN_LDC_B:
	case H8300_INSN_LDC_W:
	case H8300_INSN_STC_B:
	case H8300_INSN_STC_W:
		return RZ_ANALYSIS_ACC_UNKNOWN; /* No effect, or an explicit CCR operand. */
	default:
		/* Instructions modifying some flags also preserve the other CCR bits. */
		return RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W;
	}
}

static void h8300_op2val(RzAnalysis *analysis, const H8300Instruction *cmd, RzAnalysisValue *av, size_t i) {
	rz_return_if_fail(analysis && cmd && av);
	if (i >= cmd->ops_count) {
		return;
	}
	const H8300Operand *operand = &cmd->ops[i];
	av->access = h8300_operand_access(cmd, i);
	H8300Register reg = h8300_operand_reg(operand);
	if (reg != H8300_REG_INVALID) {
		av->reg = rz_reg_get(analysis->reg, h8300_get_register_name(reg), RZ_REG_TYPE_ANY);
	}
	if (h8300_memory_operand(cmd, operand)) {
		av->type = RZ_ANALYSIS_VAL_MEM;
		av->memref = operand->typ == H8300_OP_MI8 ? h8300_return_size(cmd) : h8300_data_size(cmd->id);
		switch (operand->typ) {
		case H8300_OP_ABS:
		case H8300_OP_MI8:
			av->absolute = true;
			av->base = h8300_address(cmd, operand->imm);
			break;
		case H8300_OP_RD:
			av->delta = operand->rd.disp;
			break;
		case H8300_OP_RPREDEC:
			av->delta = -av->memref;
			break;
		default: break;
		}
		return;
	}
	switch (operand->typ) {
	case H8300_OP_R8:
	case H8300_OP_R16:
	case H8300_OP_R32:
	case H8300_OP_RI: /* JMP/JSR @Rn uses Rn as the target, without a load. */
		av->type = RZ_ANALYSIS_VAL_REG;
		break;
	case H8300_OP_CCR:
		av->type = RZ_ANALYSIS_VAL_REG;
		av->reg = rz_reg_get(analysis->reg, "ccr", RZ_REG_TYPE_ANY);
		break;
	case H8300_OP_IMM:
		av->type = RZ_ANALYSIS_VAL_IMM;
		av->imm = operand->imm;
		break;
	case H8300_OP_ABS:
		av->type = RZ_ANALYSIS_VAL_IMM;
		av->imm = h8300_address(cmd, operand->imm);
		break;
	case H8300_OP_PCREL:
		av->type = RZ_ANALYSIS_VAL_IMM;
		av->imm = h8300_address(cmd, cmd->pc + cmd->size + operand->disp);
		break;
	default: break;
	}
}

static bool h8300_add_access(RzAnalysisOp *op, RzAnalysisValue *value) {
	rz_return_val_if_fail(op && op->access && value, false);
	if (value->type == RZ_ANALYSIS_VAL_REG) {
		if (!value->reg) {
			return true;
		}
		RzListIter *iter;
		RzAnalysisValue *existing;
		rz_list_foreach (op->access, iter, existing) {
			if (existing->type == RZ_ANALYSIS_VAL_REG && existing->reg == value->reg) {
				existing->access |= value->access;
				return true;
			}
		}
	}
	RzAnalysisValue *copy = rz_analysis_value_copy(value);
	if (!copy) {
		return false;
	}
	if (!rz_list_append(op->access, copy)) {
		rz_analysis_value_free(copy);
		return false;
	}
	return true;
}

static bool h8300_add_reg_access(RzAnalysis *analysis, RzAnalysisOp *op, const char *name, RzAnalysisValueAccess access) {
	rz_return_val_if_fail(analysis && op && name, false);
	RzAnalysisValue value = {
		.type = RZ_ANALYSIS_VAL_REG,
		.reg = rz_reg_get(analysis->reg, name, RZ_REG_TYPE_ANY),
		.access = access,
	};
	return h8300_add_access(op, &value);
}

static void h8300_analyze_val(RzAnalysis *analysis, RzAnalysisOp *op, const H8300Instruction *cmd) {
	rz_return_if_fail(analysis && op && cmd);
	op->access = rz_list_newf((RzListFree)rz_analysis_value_free);
	if (!op->access) {
		return;
	}
	size_t srci = 0;
	for (size_t i = 0; i < cmd->ops_count; i++) {
		RzAnalysisValue value = { 0 };
		h8300_op2val(analysis, cmd, &value, i);
		if (value.type == RZ_ANALYSIS_VAL_UNK) {
			continue;
		}
		if (value.access & RZ_ANALYSIS_ACC_W) {
			op->dst = rz_analysis_value_copy(&value);
			if (!op->dst) {
				return;
			}
		} else if (srci < RZ_ARRAY_SIZE(op->src)) {
			op->src[srci] = rz_analysis_value_copy(&value);
			if (!op->src[srci++]) {
				return;
			}
		}
		if (!h8300_add_access(op, &value)) {
			return;
		}
		if (value.type == RZ_ANALYSIS_VAL_MEM && value.reg) {
			RzAnalysisValueAccess access = RZ_ANALYSIS_ACC_R;
			if (cmd->ops[i].typ == H8300_OP_RPREDEC || cmd->ops[i].typ == H8300_OP_RPOSTINC) {
				access |= RZ_ANALYSIS_ACC_W;
			}
			if (!h8300_add_reg_access(analysis, op, value.reg->name, access)) {
				return;
			}
		}
	}
	RzAnalysisValueAccess ccr_access = h8300_ccr_access(cmd);
	if (ccr_access && !h8300_add_reg_access(analysis, op, "ccr", ccr_access)) {
		return;
	}
	RzAnalysisValueAccess pc_access = RZ_ANALYSIS_ACC_W;
	if (h8300_control_target(cmd)) {
		pc_access |= RZ_ANALYSIS_ACC_R;
	}
	if (!h8300_add_reg_access(analysis, op, "pc", pc_access)) {
		return;
	}
	bool push = cmd->id == H8300_INSN_PUSH_W || cmd->id == H8300_INSN_PUSH_L;
	bool pop = cmd->id == H8300_INSN_POP_W || cmd->id == H8300_INSN_POP_L;
	bool call = cmd->id == H8300_INSN_JSR || cmd->id == H8300_INSN_BSR;
	bool ret = cmd->id == H8300_INSN_RTS || cmd->id == H8300_INSN_RTE;
	if (push || pop || call || ret || cmd->id == H8300_INSN_TRAPA) {
		const char *sp = h8300_get_register_name(h8300_sp(cmd));
		if (!h8300_add_reg_access(analysis, op, sp, RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W)) {
			return;
		}
		int size = push || pop ? h8300_data_size(cmd->id) : h8300_return_size(cmd);
		if (cmd->id == H8300_INSN_RTE || cmd->id == H8300_INSN_TRAPA) {
			size = 4;
		}
		RzAnalysisValue value = {
			.type = RZ_ANALYSIS_VAL_MEM,
			.access = pop || ret ? RZ_ANALYSIS_ACC_R : RZ_ANALYSIS_ACC_W,
			.reg = rz_reg_get(analysis->reg, sp, RZ_REG_TYPE_ANY),
			.memref = size,
			.delta = pop || ret ? 0 : -size,
		};
		if (!h8300_add_access(op, &value)) {
			return;
		}
	}
	if (cmd->id == H8300_INSN_EEPMOV_B || cmd->id == H8300_INSN_EEPMOV_W) {
		/* The count is dynamic. Describe the byte transfers and register updates,
		 * rather than pretending the instruction transfers a fixed-size block. */
		const char *count = cmd->id == H8300_INSN_EEPMOV_B ? "r4l" : "r4";
		const char *src = cmd->cpu_type == CPU_H8300H ? "er5" : "r5";
		const char *dst = cmd->cpu_type == CPU_H8300H ? "er6" : "r6";
		if (!h8300_add_reg_access(analysis, op, count, RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W) ||
			!h8300_add_reg_access(analysis, op, src, RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W) ||
			!h8300_add_reg_access(analysis, op, dst, RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W)) {
			return;
		}
		RzAnalysisValue value = {
			.type = RZ_ANALYSIS_VAL_MEM,
			.memref = 1,
			.access = RZ_ANALYSIS_ACC_R,
			.reg = rz_reg_get(analysis->reg, src, RZ_REG_TYPE_ANY),
		};
		if (!h8300_add_access(op, &value)) {
			return;
		}
		value.access = RZ_ANALYSIS_ACC_W;
		value.reg = rz_reg_get(analysis->reg, dst, RZ_REG_TYPE_ANY);
		h8300_add_access(op, &value);
	}
}

static bool h8300_sp_alias(H8300Register reg) {
	return reg == H8300_ER7 || reg == H8300_R7 || reg == H8300_E7 || reg == H8300_R7H || reg == H8300_R7L;
}

static void h8300_stack_effect(RzAnalysisOp *op, const H8300Instruction *cmd) {
	rz_return_if_fail(op && cmd);
	st64 delta = 0;
	switch (cmd->id) {
	case H8300_INSN_JSR:
	case H8300_INSN_BSR:
		/* The callee balances its return-address push. Model the net effect on
		 * the caller's continuation; access/IL describe the actual push. */
		op->stackop = RZ_ANALYSIS_STACK_NOP;
		return;
	case H8300_INSN_RTS: delta = h8300_return_size(cmd); break;
	case H8300_INSN_RTE: delta = 4; break;
	case H8300_INSN_PUSH_W: delta = -2; break;
	case H8300_INSN_PUSH_L: delta = -4; break;
	case H8300_INSN_POP_W:
	case H8300_INSN_POP_L:
		if (cmd->ops_count != 1 || h8300_sp_alias(h8300_operand_reg(&cmd->ops[0]))) {
			return;
		}
		delta = h8300_data_size(cmd->id);
		break;
	default:
		for (size_t i = 0; i < cmd->ops_count; i++) {
			const H8300Operand *operand = &cmd->ops[i];
			if ((h8300_operand_access(cmd, i) & RZ_ANALYSIS_ACC_W) &&
				!h8300_memory_operand(cmd, operand) && h8300_sp_alias(h8300_operand_reg(operand))) {
				/* Only full-width constant arithmetic has a known SP delta. */
				if (h8300_operand_reg(operand) != h8300_sp(cmd) || cmd->ops_count != 2 || cmd->ops[0].typ != H8300_OP_IMM) {
					return;
				}
				switch (cmd->id) {
				case H8300_INSN_ADD_W:
				case H8300_INSN_ADD_L:
				case H8300_INSN_SUB_W:
				case H8300_INSN_SUB_L:
				case H8300_INSN_ADDS:
				case H8300_INSN_SUBS:
				case H8300_INSN_INC_W:
				case H8300_INSN_INC_L:
				case H8300_INSN_DEC_W:
				case H8300_INSN_DEC_L:
					delta = cmd->cpu_type == CPU_H8300H ? (st32)cmd->ops[0].imm : (st16)cmd->ops[0].imm;
					if (op->type == RZ_ANALYSIS_OP_TYPE_SUB) {
						delta = -delta;
					}
					break;
				default: return;
				}
			}
			if (h8300_operand_reg(operand) == h8300_sp(cmd)) {
				if (operand->typ == H8300_OP_RPREDEC) {
					delta -= h8300_data_size(cmd->id);
				} else if (operand->typ == H8300_OP_RPOSTINC) {
					delta += h8300_data_size(cmd->id);
				}
			}
		}
		break;
	}
	if (delta) {
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -delta;
	}
}

static void h8300_metadata(RzAnalysisOp *op, const H8300Instruction *cmd) {
	rz_return_if_fail(op && cmd);
	op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	for (size_t i = 0; i < cmd->ops_count; i++) {
		const H8300Operand *operand = &cmd->ops[i];
		RzAnalysisValueAccess access = h8300_operand_access(cmd, i);
		if (operand->typ == H8300_OP_IMM && op->val == UT64_MAX) {
			op->val = operand->imm;
		}
		if (h8300_memory_operand(cmd, operand)) {
			op->direction |= (access & RZ_ANALYSIS_ACC_R ? RZ_ANALYSIS_OP_DIR_READ : 0) |
				(access & RZ_ANALYSIS_ACC_W ? RZ_ANALYSIS_OP_DIR_WRITE : 0);
			op->refptr = op->ptrsize = operand->typ == H8300_OP_MI8 ? h8300_return_size(cmd) : h8300_data_size(cmd->id);
			if (operand->typ == H8300_OP_ABS || operand->typ == H8300_OP_MI8) {
				op->ptr = h8300_address(cmd, operand->imm);
			} else {
				op->ireg = h8300_get_register_name(h8300_operand_reg(operand));
				op->disp = operand->typ == H8300_OP_RD ? (st64)operand->rd.disp : operand->typ == H8300_OP_RPREDEC ? -op->refptr
																   : 0;
			}
		} else if (operand->typ == H8300_OP_R8 || operand->typ == H8300_OP_R16 || operand->typ == H8300_OP_R32) {
			if ((access & RZ_ANALYSIS_ACC_W) || op->type == RZ_ANALYSIS_OP_TYPE_CMP) {
				op->reg = h8300_get_register_name(operand->reg);
			}
		}
	}
	if (op->type == RZ_ANALYSIS_OP_TYPE_MOV) {
		if (op->direction == RZ_ANALYSIS_OP_DIR_READ) {
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		} else if (op->direction == RZ_ANALYSIS_OP_DIR_WRITE) {
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		}
	}
	if (h8300_control_target(cmd) && cmd->id != H8300_INSN_BRN) {
		op->direction |= RZ_ANALYSIS_OP_DIR_EXEC;
	}
	if (op->type == RZ_ANALYSIS_OP_TYPE_RET) {
		op->direction = RZ_ANALYSIS_OP_DIR_EXEC;
		op->eob = true;
	}
	if (op->type == RZ_ANALYSIS_OP_TYPE_PUSH || op->type == RZ_ANALYSIS_OP_TYPE_POP) {
		op->direction = op->type == RZ_ANALYSIS_OP_TYPE_PUSH ? RZ_ANALYSIS_OP_DIR_WRITE : RZ_ANALYSIS_OP_DIR_READ;
		op->refptr = op->ptrsize = h8300_data_size(cmd->id);
	}
	if (cmd->id == H8300_INSN_MOVFPE || cmd->id == H8300_INSN_MOVTPE) {
		op->mmio_address = op->ptr;
	}
	if (cmd->id == H8300_INSN_EEPMOV_B || cmd->id == H8300_INSN_EEPMOV_W) {
		op->direction = RZ_ANALYSIS_OP_DIR_READ | RZ_ANALYSIS_OP_DIR_WRITE;
	}
	switch (cmd->id) {
	case H8300_INSN_MULXS_B:
	case H8300_INSN_MULXS_W:
	case H8300_INSN_DIVXS_B:
	case H8300_INSN_DIVXS_W:
	case H8300_INSN_EXTS_W:
	case H8300_INSN_EXTS_L:
	case H8300_INSN_SHAR_B:
	case H8300_INSN_SHAR_W:
	case H8300_INSN_SHAR_L:
		op->sign = true;
		break;
	default: break;
	}
	h8300_stack_effect(op, cmd);
}

static RzTypeCond h8300_cond(H8300InsnId id) {
	switch (id) {
	case H8300_INSN_BRN: return RZ_TYPE_COND_NV;
	case H8300_INSN_BHI: return RZ_TYPE_COND_HI;
	case H8300_INSN_BLS: return RZ_TYPE_COND_LS;
	case H8300_INSN_BCC: return RZ_TYPE_COND_HS;
	case H8300_INSN_BCS: return RZ_TYPE_COND_LO;
	case H8300_INSN_BNE: return RZ_TYPE_COND_NE;
	case H8300_INSN_BEQ: return RZ_TYPE_COND_EQ;
	case H8300_INSN_BVC: return RZ_TYPE_COND_VC;
	case H8300_INSN_BVS: return RZ_TYPE_COND_VS;
	case H8300_INSN_BPL: return RZ_TYPE_COND_PL;
	case H8300_INSN_BMI: return RZ_TYPE_COND_MI;
	case H8300_INSN_BGE: return RZ_TYPE_COND_GE;
	case H8300_INSN_BLT: return RZ_TYPE_COND_LT;
	case H8300_INSN_BGT: return RZ_TYPE_COND_GT;
	case H8300_INSN_BLE: return RZ_TYPE_COND_LE;
	default: return RZ_TYPE_COND_AL;
	}
}

static RzStructuredData *h8300_opex(RzAnalysis *analysis, const H8300Instruction *cmd) {
	rz_return_val_if_fail(analysis && cmd, NULL);
	RzStructuredData *root = rz_structured_data_new_map();
	if (!root) {
		return NULL;
	}
	RzStructuredData *opex = rz_structured_data_map_add_map(root, "opex");
	if (!opex) {
		goto fail;
	}
	RzStructuredData *operands = rz_structured_data_map_add_array(opex, "operands");
	if (!operands) {
		goto fail;
	}
	for (size_t i = 0; i < cmd->ops_count; i++) {
		RzAnalysisValue value = { 0 };
		h8300_op2val(analysis, cmd, &value, i);
		RzStructuredData *operand = rz_structured_data_array_add_map(operands);
		if (!operand) {
			goto fail;
		}
		const char *access = value.access == RZ_ANALYSIS_ACC_R ? "r" : value.access == RZ_ANALYSIS_ACC_W ? "w"
														 : "rw";
		if (!rz_structured_data_map_add_string(operand, "access", access)) {
			goto fail;
		}
		switch (value.type) {
		case RZ_ANALYSIS_VAL_REG:
			if (!value.reg || !rz_structured_data_map_add_string(operand, "type", "reg") ||
				!rz_structured_data_map_add_string(operand, "value", value.reg->name)) {
				goto fail;
			}
			break;
		case RZ_ANALYSIS_VAL_IMM:
			if (!rz_structured_data_map_add_string(operand, "type", "imm") ||
				!rz_structured_data_map_add_unsigned(operand, "value", value.imm, true)) {
				goto fail;
			}
			if (cmd->ops[i].typ == H8300_OP_PCREL && !rz_structured_data_map_add_signed(operand, "disp", cmd->ops[i].disp)) {
				goto fail;
			}
			break;
		case RZ_ANALYSIS_VAL_MEM:
			if (!rz_structured_data_map_add_string(operand, "type", "mem") ||
				!rz_structured_data_map_add_unsigned(operand, "size", value.memref, false)) {
				goto fail;
			}
			if (value.absolute) {
				if (!rz_structured_data_map_add_unsigned(operand, "address", value.base, true)) {
					goto fail;
				}
			} else if (!value.reg || !rz_structured_data_map_add_string(operand, "base", value.reg->name) ||
				!rz_structured_data_map_add_signed(operand, "disp", value.delta)) {
				goto fail;
			}
			const char *mode = "indirect";
			switch (cmd->ops[i].typ) {
			case H8300_OP_ABS: mode = "absolute"; break;
			case H8300_OP_MI8: mode = "memory_indirect"; break;
			case H8300_OP_RD: mode = "displacement"; break;
			case H8300_OP_RPREDEC: mode = "predecrement"; break;
			case H8300_OP_RPOSTINC: mode = "postincrement"; break;
			default: break;
			}
			if (!rz_structured_data_map_add_string(operand, "address_mode", mode)) {
				goto fail;
			}
			break;
		default: goto fail;
		}
	}
	return root;
fail:
	rz_structured_data_free(root);
	return NULL;
}

static int h8300_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask) {
	int ret;
	H8300Instruction cmd = { 0 };

	if (!op) {
		return 2;
	}

	op->addr = addr;
	ret = op->size = h8300_decode_command(buf, len, &cmd, addr, rz_analysis_get_cpu(analysis));

	if (ret < 1 || cmd.id == H8300_INSN_INVALID) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		return ret;
	}

	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	op->id = cmd.id;
	op->cond = h8300_cond(cmd.id);

	switch (cmd.id) {
	case H8300_INSN_MOV_B:
	case H8300_INSN_MOV_W:
	case H8300_INSN_MOV_L:
	case H8300_INSN_EEPMOV_B:
	case H8300_INSN_EEPMOV_W:
	case H8300_INSN_MOVFPE:
	case H8300_INSN_MOVTPE:
	case H8300_INSN_LDC_B:
	case H8300_INSN_LDC_W:
	case H8300_INSN_BLD:
	case H8300_INSN_BILD:
	case H8300_INSN_STC_B:
	case H8300_INSN_STC_W:
	case H8300_INSN_BST:
	case H8300_INSN_BIST:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case H8300_INSN_CMP_B:
	case H8300_INSN_CMP_W:
	case H8300_INSN_CMP_L:
	case H8300_INSN_BTST:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case H8300_INSN_AND_B:
	case H8300_INSN_AND_W:
	case H8300_INSN_AND_L:
	case H8300_INSN_ANDC:
	case H8300_INSN_BAND:
	case H8300_INSN_BIAND:
	case H8300_INSN_BCLR:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case H8300_INSN_RTS:
	case H8300_INSN_RTE:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case H8300_INSN_SHAL_B:
	case H8300_INSN_SHAL_W:
	case H8300_INSN_SHAL_L:
		op->type = RZ_ANALYSIS_OP_TYPE_SAL;
		break;
	case H8300_INSN_SHAR_B:
	case H8300_INSN_SHAR_W:
	case H8300_INSN_SHAR_L:
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		break;
	case H8300_INSN_SHLL_B:
	case H8300_INSN_SHLL_W:
	case H8300_INSN_SHLL_L:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case H8300_INSN_SHLR_B:
	case H8300_INSN_SHLR_W:
	case H8300_INSN_SHLR_L:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case H8300_INSN_XOR_B:
	case H8300_INSN_XOR_W:
	case H8300_INSN_XOR_L:
	case H8300_INSN_XORC:
	case H8300_INSN_BXOR:
	case H8300_INSN_BIXOR:
	case H8300_INSN_BNOT:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case H8300_INSN_OR_B:
	case H8300_INSN_OR_W:
	case H8300_INSN_OR_L:
	case H8300_INSN_ORC:
	case H8300_INSN_BOR:
	case H8300_INSN_BIOR:
	case H8300_INSN_BSET:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case H8300_INSN_ADD_B:
	case H8300_INSN_ADD_W:
	case H8300_INSN_ADD_L:
	case H8300_INSN_ADDS:
	case H8300_INSN_ADDX:
	case H8300_INSN_INC_B:
	case H8300_INSN_INC_W:
	case H8300_INSN_INC_L:
	case H8300_INSN_DAA:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case H8300_INSN_SUB_B:
	case H8300_INSN_SUB_W:
	case H8300_INSN_SUB_L:
	case H8300_INSN_SUBS:
	case H8300_INSN_SUBX:
	case H8300_INSN_DEC_B:
	case H8300_INSN_DEC_W:
	case H8300_INSN_DEC_L:
	case H8300_INSN_DAS:
	case H8300_INSN_NEG_B:
	case H8300_INSN_NEG_W:
	case H8300_INSN_NEG_L:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case H8300_INSN_MULXU_B:
	case H8300_INSN_MULXU_W:
	case H8300_INSN_MULXS_B:
	case H8300_INSN_MULXS_W:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case H8300_INSN_DIVXS_B:
	case H8300_INSN_DIVXS_W:
	case H8300_INSN_DIVXU_B:
	case H8300_INSN_DIVXU_W:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case H8300_INSN_NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case H8300_INSN_BSR:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = h8300_address(&cmd, addr + cmd.size + INS_OP(0).disp);
		op->fail = h8300_address(&cmd, addr + cmd.size);
		break;
	case H8300_INSN_JSR:
		switch (cmd.fmt) {
		case H8300_INSN_FORMAT_RI:
			op->type = RZ_ANALYSIS_OP_TYPE_IRCALL;
			op->ireg = h8300_get_register_name(INS_OP(0).reg);
			break;
		case H8300_INSN_FORMAT_ABS:
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			op->jump = h8300_address(&cmd, INS_OP(0).imm);
			break;
		case H8300_INSN_FORMAT_MI8:
			op->type = RZ_ANALYSIS_OP_TYPE_ICALL;
			op->ptr = INS_OP(0).imm;
			break;
		default:
			op->type = RZ_ANALYSIS_OP_TYPE_ICALL;
			break;
		}
		op->fail = h8300_address(&cmd, addr + cmd.size);
		break;
	case H8300_INSN_JMP:
		switch (cmd.fmt) {
		case H8300_INSN_FORMAT_RI:
			op->type = RZ_ANALYSIS_OP_TYPE_IRJMP;
			op->ireg = h8300_get_register_name(INS_OP(0).reg);
			break;
		case H8300_INSN_FORMAT_ABS:
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			op->jump = h8300_address(&cmd, INS_OP(0).imm);
			break;
		case H8300_INSN_FORMAT_MI8:
			op->type = RZ_ANALYSIS_OP_TYPE_MJMP;
			op->ptr = INS_OP(0).imm;
			break;
		default: break;
		}
		op->eob = true;
		break;
	case H8300_INSN_BRA:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = h8300_address(&cmd, addr + cmd.size + INS_OP(0).disp);
		op->eob = true;
		break;
	case H8300_INSN_BRN:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case H8300_INSN_BHI:
	case H8300_INSN_BLS:
	case H8300_INSN_BCC:
	case H8300_INSN_BCS:
	case H8300_INSN_BNE:
	case H8300_INSN_BEQ:
	case H8300_INSN_BVC:
	case H8300_INSN_BVS:
	case H8300_INSN_BPL:
	case H8300_INSN_BMI:
	case H8300_INSN_BGE:
	case H8300_INSN_BLT:
	case H8300_INSN_BGT:
	case H8300_INSN_BLE:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = h8300_address(&cmd, addr + cmd.size + INS_OP(0).disp);
		op->eob = true;
		op->fail = h8300_address(&cmd, addr + cmd.size);
		break;
	case H8300_INSN_ROTR_B:
	case H8300_INSN_ROTXR_B:
	case H8300_INSN_ROTR_W:
	case H8300_INSN_ROTXR_W:
	case H8300_INSN_ROTR_L:
	case H8300_INSN_ROTXR_L:
		op->type = RZ_ANALYSIS_OP_TYPE_ROR;
		break;
	case H8300_INSN_ROTL_B:
	case H8300_INSN_ROTL_W:
	case H8300_INSN_ROTL_L:
	case H8300_INSN_ROTXL_B:
	case H8300_INSN_ROTXL_W:
	case H8300_INSN_ROTXL_L:
		op->type = RZ_ANALYSIS_OP_TYPE_ROL;
		break;
	case H8300_INSN_NOT_B:
	case H8300_INSN_NOT_W:
	case H8300_INSN_NOT_L:
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case H8300_INSN_EXTS_W:
	case H8300_INSN_EXTS_L:
	case H8300_INSN_EXTU_W:
	case H8300_INSN_EXTU_L:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case H8300_INSN_POP_W:
	case H8300_INSN_POP_L:
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		break;
	case H8300_INSN_PUSH_W:
	case H8300_INSN_PUSH_L:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case H8300_INSN_TRAPA:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case H8300_INSN_SLEEP:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;

	case H8300_INSN_INVALID: break;
	}

	h8300_metadata(op, &cmd);
	if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
		op->opex = h8300_opex(analysis, &cmd);
	}

	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		H8300InstructionStr ins_str = { 0 };
		if (h8300_make_opstr(&cmd, &ins_str)) {
			op->mnemonic = rz_str_newf("%s%s%s", ins_str.instr, RZ_STR_ISEMPTY(ins_str.ops_str) ? "" : " ", ins_str.ops_str);
		} else {
			op->mnemonic = rz_str_dup("invalid");
		}
	}

	if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
		h8300_analyze_val(analysis, op, &cmd);
	}

	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		h8300_analyze_op_esil(analysis, op, addr, buf);
	}

	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		h8300_analyze_op_il(analysis, op, &cmd);
	}

	return ret;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	if (h8300_cpu_type(rz_analysis_get_cpu(analysis)) == CPU_H8300H) {
		char *p =
			"=PC	pc\n"
			"=SP	er7\n"
			"=BP	er6\n"
			"=A0	r0\n"
			"gpr	er0	.32	0	0\n"
			"gpr	r0	.16	0	0\n"
			"gpr	r0h	.8	0	0\n"
			"gpr	r0l	.8	1	0\n"
			"gpr	e0	.16	2	0\n"

			"gpr	er1	.32	4	0\n"
			"gpr	r1	.16	4	0\n"
			"gpr	r1h	.8	4	0\n"
			"gpr	r1l	.8	5	0\n"
			"gpr	e1	.16	6	0\n"

			"gpr	er2	.32	8	0\n"
			"gpr	r2	.16	8	0\n"
			"gpr	r2h	.8	8	0\n"
			"gpr	r2l	.8	9	0\n"
			"gpr	e2	.16	10	0\n"

			"gpr	er3	.32	12	0\n"
			"gpr	r3	.16	12	0\n"
			"gpr	r3h	.8	12	0\n"
			"gpr	r3l	.8	13	0\n"
			"gpr	e3	.16	14	0\n"

			"gpr	er4	.32	16	0\n"
			"gpr	r4	.16	16	0\n"
			"gpr	r4h	.8	16	0\n"
			"gpr	r4l	.8	17	0\n"
			"gpr	e4	.16	18	0\n"

			"gpr	er5	.32	20	0\n"
			"gpr	r5	.16	20	0\n"
			"gpr	r5h	.8	20	0\n"
			"gpr	r5l	.8	21	0\n"
			"gpr	e5	.16	22	0\n"

			"gpr	er6	.32	24	0\n"
			"gpr	r6	.16	24	0\n"
			"gpr	r6h	.8	24	0\n"
			"gpr	r6l	.8	25	0\n"
			"gpr	e6	.16	26	0\n"

			"gpr	er7	.32	28	0\n"
			"gpr	r7	.16	28	0\n"
			"gpr	r7h	.8	28	0\n"
			"gpr	r7l	.8	29	0\n"
			"gpr	e7	.16	30	0\n"

			"gpr	pc	.24	32	0\n"
			"gpr	ccr	.8	35	0\n"
			"gpr	I	.1	.287	0\n"
			"gpr	U1	.1	.286	0\n"
			"gpr	H	.1	.285	0\n"
			"gpr	U2	.1	.284	0\n"
			"gpr	N	.1	.283	0\n"
			"gpr	Z	.1	.282	0\n"
			"gpr	V	.1	.281	0\n"
			"gpr	C	.1	.280	0\n";
		return strdup(p);
	}
	char *p =
		"=PC	pc\n"
		"=SP	r7\n"
		"=BP	r6\n"
		"=A0	r0\n"
		"gpr	r0	.16	0	0\n"
		"gpr	r0h	.8	0	0\n"
		"gpr	r0l	.8	1	0\n"
		"gpr	r1	.16	2	0\n"
		"gpr	r1h	.8	2	0\n"
		"gpr	r1l	.8	3	0\n"
		"gpr	r2	.16	4	0\n"
		"gpr	r2h	.8	4	0\n"
		"gpr	r2l	.8	5	0\n"
		"gpr	r3	.16	6	0\n"
		"gpr	r3h	.8	6	0\n"
		"gpr	r3l	.8	7	0\n"
		"gpr	r4	.16	8	0\n"
		"gpr	r4h	.8	8	0\n"
		"gpr	r4l	.8	9	0\n"
		"gpr	r5	.16	10	0\n"
		"gpr	r5h	.8	10	0\n"
		"gpr	r5l	.8	11	0\n"
		"gpr	r6	.16	12	0\n"
		"gpr	r6h	.8	12	0\n"
		"gpr	r6l	.8	13	0\n"
		"gpr	r7	.16	14	0\n"
		"gpr	r7h	.8	14	0\n"
		"gpr	r7l	.8	15	0\n"
		"gpr	pc	.16	16	0\n"
		"gpr	ccr	.8	18	0\n"
		"gpr	I	.1	.151	0\n"
		"gpr	U1	.1	.150	0\n"
		"gpr	H	.1	.149	0\n"
		"gpr	U2	.1	.148	0\n"
		"gpr	N	.1	.147	0\n"
		"gpr	Z	.1	.146	0\n"
		"gpr	V	.1	.145	0\n"
		"gpr	C	.1	.144	0\n";
	return rz_str_dup(p);
}

static RzList /*<RzSearchKeyword *>*/ *h8300_preludes(RzAnalysis *analysis) {
#define KW(d, m) rz_list_append(kws, rz_search_keyword_new_hexmask(d, m))
	RzList *kws = rz_list_newf((RzListFree)rz_search_keyword_free);
	if (!kws) {
		return kws;
	}
	KW("01006df6", "ffffffff");
	return kws;
}

static int h8300_archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 2;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 10;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		return 2;
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 1;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return true;
	default:
		return -1;
	}
}

RzAnalysisPlugin rz_analysis_plugin_h8300 = {
	.name = "h8300",
	.desc = "H8300 code analysis plugin",
	.license = "LGPL3",
	.arch = "h8300",
	.bits = 16,
	.op = &h8300_op,
	.esil = true,
	.get_reg_profile = get_reg_profile,
	.il_config = h8300_il_config,
	.preludes = h8300_preludes,
	.archinfo = h8300_archinfo,
};
