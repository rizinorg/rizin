// SPDX-FileCopyrightText: 2015-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include <capstone/capstone.h>

#ifdef CAPSTONE_M68K_H
#define CAPSTONE_HAS_M68K 1
#else
#define CAPSTONE_HAS_M68K 0
#ifdef _MSC_VER
#pragma message("Cannot find capstone-m68k support")
#else
#warning Cannot find capstone-m68k support
#endif
#endif

#if CAPSTONE_HAS_M68K
#include <capstone/m68k.h>
#include "m68k/m68k_cs.h"
#include "m68k/m68k_il.h"
// http://www.mrc.uidaho.edu/mrc/people/jff/digital/M68Kir.html

#define OPERAND(x)  insn->detail->m68k.operands[x]
#define REG(x)      cs_reg_name(*handle, insn->detail->m68k.operands[x].reg)
#define IMM(x)      insn->detail->m68k.operands[x].imm
#define MEMBASE(x)  cs_reg_name(*handle, insn->detail->m68k.operands[x].mem.base)
#define MEMINDEX(x) insn->detail->m68k.operands[x].mem.index
#define MEMDISP(x)  insn->detail->m68k.operands[x].mem.disp

static inline ut64 make_64bits_address(ut64 address) {
	return UT32_MAX & address;
}

static inline void handle_branch_instruction(RzAnalysisOp *op, ut64 addr, cs_m68k *m68k, ut32 type, int index) {
	if (m68k->operands[index].type == M68K_OP_BR_DISP) {
		op->type = type;
		// TODO: disp_size is ignored
		op->jump = make_64bits_address(addr + m68k->operands[index].br_disp.disp + 2);
		op->fail = make_64bits_address(addr + op->size);
	}
}

static inline void handle_jump_instruction(RzAnalysisOp *op, ut64 addr, cs_m68k *m68k, ut32 type) {
	if (!m68k || m68k->op_count < 1) {
		op->type = type;
		return;
	}

	const cs_m68k_op *operand = &m68k->operands[0];
	// Handle PC relative mode jump
	if (operand->address_mode == M68K_AM_PCI_DISP) {
		op->type = type;
		op->jump = make_64bits_address(addr + operand->mem.disp + 2);
	} else if (operand->type == M68K_OP_IMM) {
		op->type = type;
		op->jump = make_64bits_address(operand->imm);
	} else if (rz_m68k_op_is_absolute_mem(operand)) {
		op->type = type;
		op->jump = make_64bits_address(rz_m68k_op_absolute_mem_address(operand));
	} else {
		op->type = (type == RZ_ANALYSIS_OP_TYPE_CALL) ? RZ_ANALYSIS_OP_TYPE_ICALL : RZ_ANALYSIS_OP_TYPE_IJMP;
	}

	op->fail = make_64bits_address(addr + op->size);
}

static inline void m68k_opex_add_reg(csh handle, RzStructuredData *operand, m68k_reg reg) {
	rz_structured_data_map_add_string(operand, "type", "reg");
	rz_structured_data_map_add_string(operand, "value", cs_reg_name(handle, reg));
}

static RzStructuredData *mk68_opex(csh handle, cs_insn *insn) {
	if (!insn->detail) {
		return NULL;
	}

	RzStructuredData *root = rz_structured_data_new_map();
	if (!root) {
		return NULL;
	}

	RzStructuredData *opex = rz_structured_data_map_add_map(root, "opex");
	if (!opex) {
		rz_structured_data_free(root);
		return NULL;
	}

	RzStructuredData *operands = rz_structured_data_map_add_array(opex, "operands");
	cs_m68k *x = &insn->detail->m68k;
	for (st32 i = 0; i < x->op_count; i++) {
		cs_m68k_op *op = &x->operands[i];
		RzStructuredData *operand = rz_structured_data_array_add_map(operands);
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
		if (op->flags != M68K_OP_FLAG_NONE) {
			rz_structured_data_map_add_unsigned(operand, "flags", op->flags, false);
		}
#endif
		switch (op->type) {
		case M68K_OP_INVALID:
			if (!rz_m68k_reg_is_fpu(op->reg)) {
				rz_structured_data_map_add_string(operand, "type", "invalid");
				break;
			}
			// fallthrough
		case M68K_OP_REG:
			m68k_opex_add_reg(handle, operand, op->reg);
			break;
		case M68K_OP_REG_PAIR:
			rz_structured_data_map_add_string(operand, "type", "reg_pair");
			rz_structured_data_map_add_string(operand, "reg_0", cs_reg_name(handle, op->reg_pair.reg_0));
			rz_structured_data_map_add_string(operand, "reg_1", cs_reg_name(handle, op->reg_pair.reg_1));
			break;
		case M68K_OP_IMM:
			rz_structured_data_map_add_string(operand, "type", "imm");
			rz_structured_data_map_add_signed(operand, "value", (st64)op->imm);
			break;
		case M68K_OP_FP_SINGLE:
			rz_structured_data_map_add_string(operand, "type", "fp_single");
			rz_structured_data_map_add_double(operand, "value", op->simm);
			break;
		case M68K_OP_FP_DOUBLE:
			rz_structured_data_map_add_string(operand, "type", "fp_double");
			rz_structured_data_map_add_double(operand, "value", op->dimm);
			break;
		case M68K_OP_REG_BITS:
			rz_structured_data_map_add_string(operand, "type", "reg_bits");
			rz_structured_data_map_add_unsigned(operand, "value", op->register_bits, true);
			break;
		case M68K_OP_BR_DISP:
			rz_structured_data_map_add_string(operand, "type", "br_disp");
			rz_structured_data_map_add_signed(operand, "disp", op->br_disp.disp);
			rz_structured_data_map_add_unsigned(operand, "disp_size", op->br_disp.disp_size, false);
			break;
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
		case M68K_OP_SHIFT:
			rz_structured_data_map_add_string(operand, "type", "shift");
			break;
#endif
		case M68K_OP_MEM:
			rz_structured_data_map_add_string(operand, "type", "mem");
			rz_structured_data_map_add_unsigned(operand, "address_mode", op->address_mode, false);
			if (op->mem.base_reg != M68K_REG_INVALID) {
				rz_structured_data_map_add_string(operand, "base_reg", cs_reg_name(handle, op->mem.base_reg));
			}
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
			if (rz_m68k_op_is_absolute_mem(op)) {
				rz_structured_data_map_add_unsigned(operand, "address", op->mem.address, false);
			}
#endif
			if (op->mem.index_reg != M68K_REG_INVALID) {
				rz_structured_data_map_add_string(operand, "index_reg", cs_reg_name(handle, op->mem.index_reg));
			}
			if (op->mem.in_base_reg != M68K_REG_INVALID) {
				rz_structured_data_map_add_string(operand, "in_base_reg", cs_reg_name(handle, op->mem.in_base_reg));
			}
			rz_structured_data_map_add_signed(operand, "in_disp", op->mem.in_disp);
			rz_structured_data_map_add_signed(operand, "out_disp", op->mem.out_disp);
			rz_structured_data_map_add_signed(operand, "disp", op->mem.disp);
			rz_structured_data_map_add_signed(operand, "scale", op->mem.scale);
			rz_structured_data_map_add_signed(operand, "bitfield", op->mem.bitfield);
			rz_structured_data_map_add_signed(operand, "width", op->mem.width);
			rz_structured_data_map_add_signed(operand, "offset", op->mem.offset);
			rz_structured_data_map_add_signed(operand, "index_size", op->mem.index_size);
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
			rz_structured_data_map_add_signed(operand, "in_disp_size", op->mem.in_disp_size);
			rz_structured_data_map_add_signed(operand, "out_disp_size", op->mem.out_disp_size);
			rz_structured_data_map_add_signed(operand, "disp_size", op->mem.disp_size);
#endif
			break;
		default:
			rz_structured_data_map_add_string(operand, "type", "invalid");
			break;
		}
	}
	if (rz_m68k_fpu_insn_needs_hidden_dst(insn)) {
		RzStructuredData *operand = rz_structured_data_array_add_map(operands);
		m68k_opex_add_reg(handle, operand, rz_m68k_fpu_insn_extension_dst_reg(insn));
	}

	return root;
}

static inline int m68k_op_memref(const cs_m68k *m68k) {
	if (!m68k) {
		return 0;
	}
	switch (m68k->op_size.type) {
	case M68K_SIZE_TYPE_CPU:
		switch (m68k->op_size.cpu_size) {
		case M68K_CPU_SIZE_BYTE:
			return 1;
		case M68K_CPU_SIZE_WORD:
			return 2;
		case M68K_CPU_SIZE_LONG:
			return 4;
		default:
			return 0;
		}
	case M68K_SIZE_TYPE_FPU:
		switch (m68k->op_size.fpu_size) {
		case M68K_FPU_SIZE_SINGLE:
			return 4;
		case M68K_FPU_SIZE_DOUBLE:
			return 8;
		case M68K_FPU_SIZE_EXTENDED:
			return 12;
		default:
			return 0;
		}
	default:
		return 0;
	}
}

static inline RzRegItem *m68k_reg_get(RzAnalysis *a, csh handle, m68k_reg reg) {
	if (!a || reg == M68K_REG_INVALID) {
		return NULL;
	}
	const char *name = cs_reg_name(handle, reg);
	return RZ_STR_ISNOTEMPTY(name) ? rz_reg_get(a->reg, name, RZ_REG_TYPE_ANY) : NULL;
}

static RzAnalysisValue *m68k_value_from_operand(RzAnalysis *a, csh handle, const cs_m68k_op *operand, int memref, RzAnalysisValueAccess access) {
	if (!operand) {
		return NULL;
	}

	RzAnalysisValue *value = rz_analysis_value_new();
	if (!value) {
		return NULL;
	}
	value->access = access;

	switch (operand->type) {
	case M68K_OP_REG:
		value->type = RZ_ANALYSIS_VAL_REG;
		value->reg = m68k_reg_get(a, handle, operand->reg);
		if (!value->reg) {
			rz_analysis_value_free(value);
			return NULL;
		}
		break;
	case M68K_OP_INVALID:
		if (!rz_m68k_op_is_fpu_reg(operand)) {
			rz_analysis_value_free(value);
			return NULL;
		}
		value->type = RZ_ANALYSIS_VAL_REG;
		value->reg = m68k_reg_get(a, handle, operand->reg);
		if (!value->reg) {
			rz_analysis_value_free(value);
			return NULL;
		}
		break;
	case M68K_OP_IMM:
		value->type = RZ_ANALYSIS_VAL_IMM;
		value->imm = (st64)operand->imm;
		break;
	case M68K_OP_BR_DISP:
		value->type = RZ_ANALYSIS_VAL_IMM;
		value->imm = operand->br_disp.disp;
		break;
	case M68K_OP_MEM:
		value->type = RZ_ANALYSIS_VAL_MEM;
		value->memref = memref;
		value->reg = m68k_reg_get(a, handle, operand->mem.base_reg);
		if (!value->reg) {
			value->reg = m68k_reg_get(a, handle, operand->mem.in_base_reg);
		}
		value->regdelta = m68k_reg_get(a, handle, operand->mem.index_reg);
		value->mul = operand->mem.scale;
		value->delta = operand->mem.disp + operand->mem.in_disp + operand->mem.out_disp;
		if (rz_m68k_op_is_absolute_mem(operand)) {
			value->absolute = true;
			value->base = rz_m68k_op_absolute_mem_address(operand);
			value->delta = 0;
		} else if (!value->reg && !value->regdelta && value->delta) {
			value->absolute = true;
			value->base = (ut64)value->delta;
			value->delta = 0;
		}
		break;
	case M68K_OP_REG_PAIR:
		value->type = RZ_ANALYSIS_VAL_REG;
		value->reg = m68k_reg_get(a, handle, operand->reg_pair.reg_0);
		if (!value->reg) {
			rz_analysis_value_free(value);
			return NULL;
		}
		break;
	default:
		rz_analysis_value_free(value);
		return NULL;
	}

	return value;
}

static RzAnalysisValue *m68k_value_from_reg(RzAnalysis *a, csh handle, m68k_reg reg, RzAnalysisValueAccess access) {
	RzAnalysisValue *value = rz_analysis_value_new();
	if (!value) {
		return NULL;
	}
	value->access = access;
	value->type = RZ_ANALYSIS_VAL_REG;
	value->reg = m68k_reg_get(a, handle, reg);
	if (!value->reg) {
		rz_analysis_value_free(value);
		return NULL;
	}
	return value;
}

static inline void m68k_note_memref(RzAnalysisOp *op, RzAnalysisValue *value) {
	if (value && value->type == RZ_ANALYSIS_VAL_MEM && value->memref > 0) {
		op->refptr = value->memref;
	}
}

static bool m68k_add_src_value(RzAnalysisOp *op, RzAnalysisValue *value) {
	if (!value) {
		return false;
	}
	for (size_t i = 0; i < RZ_ARRAY_SIZE(op->src); i++) {
		if (!op->src[i]) {
			op->src[i] = value;
			m68k_note_memref(op, value);
			return true;
		}
	}
	rz_analysis_value_free(value);
	return false;
}

static void m68k_set_dst_value(RzAnalysisOp *op, RzAnalysisValue *value) {
	if (!value) {
		return;
	}
	if (op->dst) {
		rz_analysis_value_free(op->dst);
	}
	op->dst = value;
	m68k_note_memref(op, value);
}

static void m68k_add_src_operand(RzAnalysis *a, RzAnalysisOp *op, csh handle, const cs_m68k *m68k, int operand_index) {
	if (!m68k || operand_index < 0 || operand_index >= m68k->op_count) {
		return;
	}
	RzAnalysisValue *value = m68k_value_from_operand(a, handle, &m68k->operands[operand_index], m68k_op_memref(m68k), RZ_ANALYSIS_ACC_R);
	m68k_add_src_value(op, value);
}

static void m68k_set_dst_operand(RzAnalysis *a, RzAnalysisOp *op, csh handle, const cs_m68k *m68k, int operand_index, RzAnalysisValueAccess access) {
	if (!m68k || operand_index < 0 || operand_index >= m68k->op_count) {
		return;
	}
	RzAnalysisValue *value = m68k_value_from_operand(a, handle, &m68k->operands[operand_index], m68k_op_memref(m68k), access);
	m68k_set_dst_value(op, value);
}

static void m68k_fill_fpu_hidden_dst(RzAnalysis *a, RzAnalysisOp *op, csh handle, const cs_insn *insn) {
	if (!insn || !insn->detail || !rz_m68k_fpu_insn_needs_hidden_dst(insn)) {
		return;
	}

	const cs_m68k *m68k = &insn->detail->m68k;
	for (int i = 0; i < m68k->op_count; i++) {
		m68k_add_src_operand(a, op, handle, m68k, i);
	}

	m68k_reg dst_reg = rz_m68k_fpu_insn_extension_dst_reg(insn);
	if ((op->type & RZ_ANALYSIS_OP_TYPE_MASK) == RZ_ANALYSIS_OP_TYPE_CMP) {
		m68k_add_src_value(op, m68k_value_from_reg(a, handle, dst_reg, RZ_ANALYSIS_ACC_R));
		return;
	}

	RzAnalysisValueAccess access = RZ_ANALYSIS_ACC_W;
	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_ADD:
	case RZ_ANALYSIS_OP_TYPE_SUB:
	case RZ_ANALYSIS_OP_TYPE_MUL:
	case RZ_ANALYSIS_OP_TYPE_DIV:
	case RZ_ANALYSIS_OP_TYPE_MOD:
		access |= RZ_ANALYSIS_ACC_R;
		break;
	default:
		break;
	}
	m68k_set_dst_value(op, m68k_value_from_reg(a, handle, dst_reg, access));
}

static void m68k_fill_fpu_sincos(RzAnalysis *a, RzAnalysisOp *op, csh handle, const cs_insn *insn) {
	if (!insn || !insn->detail) {
		return;
	}
	const cs_m68k *m68k = &insn->detail->m68k;
	if (m68k->op_count > 0) {
		m68k_add_src_operand(a, op, handle, m68k, 0);
	}
	if (m68k->op_count > 1 && m68k->operands[1].type == M68K_OP_REG_PAIR) {
		m68k_set_dst_value(op, m68k_value_from_reg(a, handle, m68k->operands[1].reg_pair.reg_1, RZ_ANALYSIS_ACC_W));
		return;
	}
	if (m68k->op_count > 2) {
		m68k_set_dst_operand(a, op, handle, m68k, 2, RZ_ANALYSIS_ACC_W);
		return;
	}

	m68k_reg dst_reg = rz_m68k_fpu_insn_extension_dst_reg(insn);
	if (dst_reg == M68K_REG_INVALID) {
		return;
	}
	m68k_set_dst_value(op, m68k_value_from_reg(a, handle, dst_reg, RZ_ANALYSIS_ACC_W));
}

static void m68k_fill_srcs_before_dst(RzAnalysis *a, RzAnalysisOp *op, csh handle, const cs_m68k *m68k, bool dst_is_read) {
	if (!m68k || m68k->op_count < 1) {
		return;
	}

	int dst_index = m68k->op_count - 1;
	for (int i = 0; i < dst_index; i++) {
		m68k_add_src_operand(a, op, handle, m68k, i);
	}
	m68k_set_dst_operand(a, op, handle, m68k, dst_index, dst_is_read ? (RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W) : RZ_ANALYSIS_ACC_W);
}

static void m68k_fill_all_srcs(RzAnalysis *a, RzAnalysisOp *op, csh handle, const cs_m68k *m68k) {
	if (!m68k) {
		return;
	}
	for (int i = 0; i < m68k->op_count; i++) {
		m68k_add_src_operand(a, op, handle, m68k, i);
	}
}

static void m68k_fill_unary_rw(RzAnalysis *a, RzAnalysisOp *op, csh handle, const cs_m68k *m68k) {
	if (!m68k || m68k->op_count < 1) {
		return;
	}
	m68k_set_dst_operand(a, op, handle, m68k, 0, RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W);
	if (op->dst) {
		RzAnalysisValue *src = rz_analysis_value_copy(op->dst);
		if (src) {
			src->access = RZ_ANALYSIS_ACC_R;
			m68k_add_src_value(op, src);
		}
	}
}

static void m68k_fill_clear(RzAnalysis *a, RzAnalysisOp *op, csh handle, const cs_m68k *m68k) {
	if (!m68k || m68k->op_count < 1) {
		return;
	}
	m68k_set_dst_operand(a, op, handle, m68k, 0, RZ_ANALYSIS_ACC_W);
	RzAnalysisValue *src = rz_analysis_value_new();
	if (src) {
		src->type = RZ_ANALYSIS_VAL_IMM;
		src->access = RZ_ANALYSIS_ACC_R;
		src->imm = 0;
		m68k_add_src_value(op, src);
	}
}

static void m68k_fill_indirect_target(RzAnalysis *a, RzAnalysisOp *op, csh handle, const cs_m68k *m68k) {
	if (!m68k || m68k->op_count < 1) {
		return;
	}
	m68k_add_src_operand(a, op, handle, m68k, 0);
}

static void m68k_fill_callm(RzAnalysis *a, RzAnalysisOp *op, csh handle, const cs_m68k *m68k) {
	if (!m68k || m68k->op_count < 2) {
		return;
	}
	m68k_add_src_operand(a, op, handle, m68k, 0);
	m68k_add_src_operand(a, op, handle, m68k, 1);
}

#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
static void m68k_fill_strldsr(RzAnalysis *a, RzAnalysisOp *op, csh handle, const cs_m68k *m68k) {
	if (!m68k || m68k->op_count < 1) {
		return;
	}
	m68k_add_src_operand(a, op, handle, m68k, 0);
	m68k_add_src_value(op, m68k_value_from_reg(a, handle, M68K_REG_SR, RZ_ANALYSIS_ACC_R));
	m68k_set_dst_value(op, m68k_value_from_reg(a, handle, M68K_REG_SR, RZ_ANALYSIS_ACC_W));
}

static void m68k_fill_coprocessor_transfer(RzAnalysis *a, RzAnalysisOp *op, csh handle, const cs_m68k *m68k) {
	if (!m68k || m68k->op_count < 2) {
		return;
	}
	m68k_add_src_operand(a, op, handle, m68k, 0);
	m68k_set_dst_operand(a, op, handle, m68k, 1, RZ_ANALYSIS_ACC_W);
}
#endif

static void m68k_fill_fpu_state_transfer(RzAnalysis *a, RzAnalysisOp *op, csh handle, const cs_m68k *m68k, bool restore) {
	if (!m68k || m68k->op_count < 1) {
		return;
	}
	if (restore) {
		m68k_add_src_operand(a, op, handle, m68k, 0);
	} else {
		m68k_set_dst_operand(a, op, handle, m68k, 0, RZ_ANALYSIS_ACC_W);
	}
}

static void m68k_fill_scc(RzAnalysis *a, RzAnalysisOp *op, csh handle, const cs_m68k *m68k) {
	if (!m68k || m68k->op_count < 1) {
		return;
	}
	m68k_add_src_value(op, m68k_value_from_reg(a, handle, M68K_REG_SR, RZ_ANALYSIS_ACC_R));
	m68k_set_dst_operand(a, op, handle, m68k, 0, RZ_ANALYSIS_ACC_W);
}

static void m68k_fill_fpu_unknown(RzAnalysis *a, RzAnalysisOp *op, csh handle, const cs_m68k *m68k) {
	if (!m68k || m68k->op_count < 1) {
		return;
	}
	if (m68k->op_count == 1) {
		m68k_fill_unary_rw(a, op, handle, m68k);
	} else {
		m68k_fill_srcs_before_dst(a, op, handle, m68k, false);
	}
}

static void m68k_set_move_type(RzAnalysisOp *op, const cs_m68k *m68k) {
	if (!m68k || m68k->op_count < 2) {
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		return;
	}
	const cs_m68k_op *src = &m68k->operands[0];
	const cs_m68k_op *dst = &m68k->operands[m68k->op_count - 1];
	if (dst->type == M68K_OP_MEM) {
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
	} else if (src->type == M68K_OP_MEM) {
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
	} else {
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
	}
}

static RZ_UNUSED void m68k_set_cast_type(RzAnalysisOp *op, const cs_m68k *m68k) {
	if (!m68k || m68k->op_count < 2) {
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		return;
	}
	const cs_m68k_op *src = &m68k->operands[0];
	const cs_m68k_op *dst = &m68k->operands[m68k->op_count - 1];
	if (dst->type == M68K_OP_MEM) {
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
	} else if (src->type == M68K_OP_MEM) {
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
	} else {
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
	}
}

static void m68k_set_opdir(RzAnalysisOp *op) {
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
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_CJMP:
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_CALL:
	case RZ_ANALYSIS_OP_TYPE_UCALL:
		op->direction = RZ_ANALYSIS_OP_DIR_EXEC;
		break;
	default:
		break;
	}
}

static void m68k_handle_fpu_instruction(RzAnalysisOp *op, ut64 addr, cs_m68k *m68k, unsigned int insn_id) {
	op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
	switch (insn_id) {
	case M68K_INS_FMOVE:
	case M68K_INS_FSMOVE:
	case M68K_INS_FDMOVE:
	case M68K_INS_FMOVECR:
	case M68K_INS_FMOVEM:
		m68k_set_move_type(op, m68k);
		break;
	case M68K_INS_FADD:
	case M68K_INS_FSADD:
	case M68K_INS_FDADD:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case M68K_INS_FSUB:
	case M68K_INS_FSSUB:
	case M68K_INS_FDSUB:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case M68K_INS_FMUL:
	case M68K_INS_FSMUL:
	case M68K_INS_FDMUL:
	case M68K_INS_FSGLMUL:
	case M68K_INS_FSCALE:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case M68K_INS_FDIV:
	case M68K_INS_FSDIV:
	case M68K_INS_FDDIV:
	case M68K_INS_FSGLDIV:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case M68K_INS_FMOD:
	case M68K_INS_FREM:
		op->type = RZ_ANALYSIS_OP_TYPE_MOD;
		break;
	case M68K_INS_FCMP:
	case M68K_INS_FTST:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case M68K_INS_FABS:
	case M68K_INS_FSABS:
	case M68K_INS_FDABS:
		op->type = RZ_ANALYSIS_OP_TYPE_ABS;
		break;
	case M68K_INS_FNEG:
	case M68K_INS_FSNEG:
	case M68K_INS_FDNEG:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case M68K_INS_FINT:
	case M68K_INS_FINTRZ:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case M68K_INS_FACOS:
	case M68K_INS_FASIN:
	case M68K_INS_FATAN:
	case M68K_INS_FATANH:
	case M68K_INS_FCOS:
	case M68K_INS_FCOSH:
	case M68K_INS_FETOX:
	case M68K_INS_FETOXM1:
	case M68K_INS_FGETEXP:
	case M68K_INS_FGETMAN:
	case M68K_INS_FLOG10:
	case M68K_INS_FLOG2:
	case M68K_INS_FLOGN:
	case M68K_INS_FLOGNP1:
	case M68K_INS_FSIN:
	case M68K_INS_FSINCOS:
	case M68K_INS_FSINH:
	case M68K_INS_FSQRT:
	case M68K_INS_FSSQRT:
	case M68K_INS_FDSQRT:
	case M68K_INS_FTAN:
	case M68K_INS_FTANH:
	case M68K_INS_FTENTOX:
	case M68K_INS_FTWOTOX:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case M68K_INS_FNOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case M68K_INS_FSAVE:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case M68K_INS_FRESTORE:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case M68K_INS_FSF:
	case M68K_INS_FSBEQ:
	case M68K_INS_FSOGT:
	case M68K_INS_FSOGE:
	case M68K_INS_FSOLT:
	case M68K_INS_FSOLE:
	case M68K_INS_FSOGL:
	case M68K_INS_FSOR:
	case M68K_INS_FSUN:
	case M68K_INS_FSUEQ:
	case M68K_INS_FSUGT:
	case M68K_INS_FSUGE:
	case M68K_INS_FSULT:
	case M68K_INS_FSULE:
	case M68K_INS_FSNE:
	case M68K_INS_FST:
	case M68K_INS_FSSF:
	case M68K_INS_FSSEQ:
	case M68K_INS_FSGT:
	case M68K_INS_FSGE:
	case M68K_INS_FSLT:
	case M68K_INS_FSLE:
	case M68K_INS_FSGL:
	case M68K_INS_FSGLE:
	case M68K_INS_FSNGLE:
	case M68K_INS_FSNGL:
	case M68K_INS_FSNLE:
	case M68K_INS_FSNLT:
	case M68K_INS_FSNGE:
	case M68K_INS_FSNGT:
	case M68K_INS_FSSNE:
	case M68K_INS_FSST:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case M68K_INS_FTRAPF:
	case M68K_INS_FTRAPEQ:
	case M68K_INS_FTRAPOGT:
	case M68K_INS_FTRAPOGE:
	case M68K_INS_FTRAPOLT:
	case M68K_INS_FTRAPOLE:
	case M68K_INS_FTRAPOGL:
	case M68K_INS_FTRAPOR:
	case M68K_INS_FTRAPUN:
	case M68K_INS_FTRAPUEQ:
	case M68K_INS_FTRAPUGT:
	case M68K_INS_FTRAPUGE:
	case M68K_INS_FTRAPULT:
	case M68K_INS_FTRAPULE:
	case M68K_INS_FTRAPNE:
	case M68K_INS_FTRAPT:
	case M68K_INS_FTRAPSF:
	case M68K_INS_FTRAPSEQ:
	case M68K_INS_FTRAPGT:
	case M68K_INS_FTRAPGE:
	case M68K_INS_FTRAPLT:
	case M68K_INS_FTRAPLE:
	case M68K_INS_FTRAPGL:
	case M68K_INS_FTRAPGLE:
	case M68K_INS_FTRAPNGLE:
	case M68K_INS_FTRAPNGL:
	case M68K_INS_FTRAPNLE:
	case M68K_INS_FTRAPNLT:
	case M68K_INS_FTRAPNGE:
	case M68K_INS_FTRAPNGT:
	case M68K_INS_FTRAPSNE:
	case M68K_INS_FTRAPST:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case M68K_INS_FBF:
	case M68K_INS_FBEQ:
	case M68K_INS_FBOGT:
	case M68K_INS_FBOGE:
	case M68K_INS_FBOLT:
	case M68K_INS_FBOLE:
	case M68K_INS_FBOGL:
	case M68K_INS_FBOR:
	case M68K_INS_FBUN:
	case M68K_INS_FBUEQ:
	case M68K_INS_FBUGT:
	case M68K_INS_FBUGE:
	case M68K_INS_FBULT:
	case M68K_INS_FBULE:
	case M68K_INS_FBNE:
	case M68K_INS_FBT:
	case M68K_INS_FBSF:
	case M68K_INS_FBSEQ:
	case M68K_INS_FBGT:
	case M68K_INS_FBGE:
	case M68K_INS_FBLT:
	case M68K_INS_FBLE:
	case M68K_INS_FBGL:
	case M68K_INS_FBGLE:
	case M68K_INS_FBNGLE:
	case M68K_INS_FBNGL:
	case M68K_INS_FBNLE:
	case M68K_INS_FBNLT:
	case M68K_INS_FBNGE:
	case M68K_INS_FBNGT:
	case M68K_INS_FBSNE:
	case M68K_INS_FBST:
		handle_branch_instruction(op, addr, m68k, RZ_ANALYSIS_OP_TYPE_CJMP, 0);
		break;
	case M68K_INS_FDBF:
	case M68K_INS_FDBEQ:
	case M68K_INS_FDBOGT:
	case M68K_INS_FDBOGE:
	case M68K_INS_FDBOLT:
	case M68K_INS_FDBOLE:
	case M68K_INS_FDBOGL:
	case M68K_INS_FDBOR:
	case M68K_INS_FDBUN:
	case M68K_INS_FDBUEQ:
	case M68K_INS_FDBUGT:
	case M68K_INS_FDBUGE:
	case M68K_INS_FDBULT:
	case M68K_INS_FDBULE:
	case M68K_INS_FDBNE:
	case M68K_INS_FDBT:
	case M68K_INS_FDBSF:
	case M68K_INS_FDBSEQ:
	case M68K_INS_FDBGT:
	case M68K_INS_FDBGE:
	case M68K_INS_FDBLT:
	case M68K_INS_FDBLE:
	case M68K_INS_FDBGL:
	case M68K_INS_FDBGLE:
	case M68K_INS_FDBNGLE:
	case M68K_INS_FDBNGL:
	case M68K_INS_FDBNLE:
	case M68K_INS_FDBNLT:
	case M68K_INS_FDBNGE:
	case M68K_INS_FDBNGT:
	case M68K_INS_FDBSNE:
	case M68K_INS_FDBST:
		handle_branch_instruction(op, addr, m68k, RZ_ANALYSIS_OP_TYPE_CJMP, 1);
		break;
	default:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	}
}

typedef struct {
	csh handle;
	int omode;
	int obits;
} M68KContext;

static bool m68k_init(void **user) {
	M68KContext *ctx = RZ_NEW0(M68KContext);
	rz_return_val_if_fail(ctx, false);
	ctx->handle = 0;
	ctx->omode = -1;
	ctx->obits = 32;
	*user = ctx;
	return true;
}

static void op_fillval(RzAnalysis *a, RzAnalysisOp *op, csh handle, cs_insn *insn) {
	cs_m68k *m68k = &insn->detail->m68k;
	switch (insn->id) {
	case M68K_INS_CLR:
		m68k_fill_clear(a, op, handle, m68k);
		return;
	case M68K_INS_NEG:
	case M68K_INS_NEGX:
	case M68K_INS_NOT:
	case M68K_INS_SWAP:
	case M68K_INS_EXT:
	case M68K_INS_EXTB:
		m68k_fill_unary_rw(a, op, handle, m68k);
		return;
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
	case M68K_INS_BITREV:
	case M68K_INS_BYTEREV:
	case M68K_INS_FF1:
	case M68K_INS_SATS:
		m68k_fill_unary_rw(a, op, handle, m68k);
		return;
	case M68K_INS_STRLDSR:
		m68k_fill_strldsr(a, op, handle, m68k);
		return;
	case M68K_INS_CP0LD:
	case M68K_INS_CP1LD:
	case M68K_INS_CP0ST:
	case M68K_INS_CP1ST:
		m68k_fill_coprocessor_transfer(a, op, handle, m68k);
		return;
#endif
	case M68K_INS_FSAVE:
		m68k_fill_fpu_state_transfer(a, op, handle, m68k, false);
		return;
	case M68K_INS_FRESTORE:
		m68k_fill_fpu_state_transfer(a, op, handle, m68k, true);
		return;
	case M68K_INS_CALLM:
		m68k_fill_callm(a, op, handle, m68k);
		return;
	case M68K_INS_ST:
	case M68K_INS_SF:
	case M68K_INS_SHI:
	case M68K_INS_SLS:
	case M68K_INS_SCC:
	case M68K_INS_SHS:
	case M68K_INS_SCS:
	case M68K_INS_SLO:
	case M68K_INS_SNE:
	case M68K_INS_SEQ:
	case M68K_INS_SVC:
	case M68K_INS_SVS:
	case M68K_INS_SPL:
	case M68K_INS_SMI:
	case M68K_INS_SGE:
	case M68K_INS_SLT:
	case M68K_INS_SGT:
	case M68K_INS_SLE:
		m68k_fill_scc(a, op, handle, m68k);
		return;
	case M68K_INS_FSINCOS:
		m68k_fill_fpu_sincos(a, op, handle, insn);
		return;
	default:
		break;
	}

	if (rz_m68k_fpu_insn_needs_hidden_dst(insn)) {
		m68k_fill_fpu_hidden_dst(a, op, handle, insn);
		return;
	}
	if (rz_m68k_fpu_insn_has_data_dst(insn->id) && rz_m68k_fpu_insn_single_op_is_complete(insn)) {
		m68k_fill_unary_rw(a, op, handle, m68k);
		return;
	}

	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_LOAD:
	case RZ_ANALYSIS_OP_TYPE_MOV:
	case RZ_ANALYSIS_OP_TYPE_STORE:
	case RZ_ANALYSIS_OP_TYPE_CAST:
		m68k_fill_srcs_before_dst(a, op, handle, m68k, false);
		break;
	case RZ_ANALYSIS_OP_TYPE_LEA:
		if (m68k->op_count > 1) {
			m68k_add_src_operand(a, op, handle, m68k, 0);
			m68k_set_dst_operand(a, op, handle, m68k, m68k->op_count - 1, RZ_ANALYSIS_ACC_W);
		} else {
			m68k_fill_all_srcs(a, op, handle, m68k);
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_ADD:
	case RZ_ANALYSIS_OP_TYPE_SUB:
	case RZ_ANALYSIS_OP_TYPE_MUL:
	case RZ_ANALYSIS_OP_TYPE_DIV:
	case RZ_ANALYSIS_OP_TYPE_MOD:
	case RZ_ANALYSIS_OP_TYPE_SHL:
	case RZ_ANALYSIS_OP_TYPE_SHR:
	case RZ_ANALYSIS_OP_TYPE_SAR:
	case RZ_ANALYSIS_OP_TYPE_SAL:
	case RZ_ANALYSIS_OP_TYPE_OR:
	case RZ_ANALYSIS_OP_TYPE_AND:
	case RZ_ANALYSIS_OP_TYPE_XOR:
	case RZ_ANALYSIS_OP_TYPE_XCHG:
	case RZ_ANALYSIS_OP_TYPE_ROR:
	case RZ_ANALYSIS_OP_TYPE_ROL:
	case RZ_ANALYSIS_OP_TYPE_ABS:
	case RZ_ANALYSIS_OP_TYPE_BCNT:
	case RZ_ANALYSIS_OP_TYPE_REV:
		m68k_fill_srcs_before_dst(a, op, handle, m68k, true);
		break;
	case RZ_ANALYSIS_OP_TYPE_CMP:
		m68k_fill_all_srcs(a, op, handle, m68k);
		break;
	case RZ_ANALYSIS_OP_TYPE_TRAP:
		m68k_fill_all_srcs(a, op, handle, m68k);
		break;
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_UCALL:
		m68k_fill_indirect_target(a, op, handle, m68k);
		break;
	default:
		if (op->family == RZ_ANALYSIS_OP_FAMILY_FPU &&
			(op->type & RZ_ANALYSIS_OP_TYPE_MASK) == RZ_ANALYSIS_OP_TYPE_UNK) {
			m68k_fill_fpu_unknown(a, op, handle, m68k);
		}
		break;
	}
}

static inline void m68k_invalid_il_nop(RzAnalysisOp *op, RzAnalysisOpMask mask) {
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = rz_il_op_new_nop();
	}
}

static int m68k_analyze_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	M68KContext *ctx = (M68KContext *)a->plugin_data;
	int n, ret, opsize = -1;
	cs_insn *insn = NULL;
	cs_m68k *m68k;
	cs_detail *detail;

	cs_mode mode = rz_m68k_cs_mode(rz_analysis_get_cpu(a));

	if (mode != ctx->omode || a->bits != ctx->obits) {
		cs_close(&ctx->handle);
		ctx->handle = 0;
		ctx->omode = -1;
		ctx->obits = a->bits;
	}
	op->size = 4;
	if (ctx->handle == 0) {
		ret = cs_open(CS_ARCH_M68K, mode, &ctx->handle);
		if (ret != CS_ERR_OK) {
			goto fin;
		}
		ctx->omode = mode;
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_ON);
	}
	n = cs_disasm(ctx->handle, (ut8 *)buf, len, addr, 1, &insn);
	if (n < 1 || insn->size < 1) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		opsize = op->size = 2;
		m68k_invalid_il_nop(op, mask);
		goto beach;
	}
	detail = insn->detail;
	m68k = &detail->m68k;
	op->id = insn->id;
	opsize = op->size = insn->size;
	if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
		op->opex = mk68_opex(ctx->handle, insn);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = rz_m68k_cs_get_il_op(ctx->handle, insn, addr);
	}
	switch (insn->id) {
	case M68K_INS_INVALID:
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			rz_il_op_effect_free(op->il_op);
			op->il_op = rz_il_op_new_nop();
		}
		break;
	case M68K_INS_ADD:
	case M68K_INS_ADDA:
	case M68K_INS_ADDI:
	case M68K_INS_ADDQ:
	case M68K_INS_ADDX:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case M68K_INS_AND:
	case M68K_INS_ANDI:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case M68K_INS_ASL:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case M68K_INS_ASR:
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		break;
	case M68K_INS_ABCD:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case M68K_INS_BKPT:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case M68K_INS_BHS:
	case M68K_INS_BLO:
	case M68K_INS_BHI:
	case M68K_INS_BLS:
	case M68K_INS_BCC:
	case M68K_INS_BCS:
	case M68K_INS_BNE:
	case M68K_INS_BEQ:
	case M68K_INS_BVC:
	case M68K_INS_BVS:
	case M68K_INS_BPL:
	case M68K_INS_BMI:
	case M68K_INS_BGE:
	case M68K_INS_BLT:
	case M68K_INS_BGT:
	case M68K_INS_BLE:
		handle_branch_instruction(op, addr, m68k, RZ_ANALYSIS_OP_TYPE_CJMP, 0);
		break;
	case M68K_INS_BRA:
		handle_branch_instruction(op, addr, m68k, RZ_ANALYSIS_OP_TYPE_JMP, 0);
		break;
	case M68K_INS_BSR:
		handle_branch_instruction(op, addr, m68k, RZ_ANALYSIS_OP_TYPE_CALL, 0);
		break;
	case M68K_INS_BCHG:
	case M68K_INS_BCLR:
	case M68K_INS_BSET:
	case M68K_INS_BTST:
	case M68K_INS_BFCHG:
	case M68K_INS_BFCLR:
	case M68K_INS_BFEXTS:
	case M68K_INS_BFEXTU:
	case M68K_INS_BFFFO:
	case M68K_INS_BFINS:
	case M68K_INS_BFSET:
	case M68K_INS_BFTST:
	case M68K_INS_CAS:
	case M68K_INS_CAS2:
	case M68K_INS_CHK:
	case M68K_INS_CHK2:
		// TODO:
		break;
	case M68K_INS_CALLM:
		if (m68k->op_count > 1) {
			op->type = RZ_ANALYSIS_OP_TYPE_ICALL;
			op->fail = make_64bits_address(addr + op->size);
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
		}
		break;
	case M68K_INS_CLR:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case M68K_INS_CMP:
	case M68K_INS_CMPA:
	case M68K_INS_CMPI:
	case M68K_INS_CMPM:
	case M68K_INS_CMP2:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case M68K_INS_CINVL:
	case M68K_INS_CINVP:
	case M68K_INS_CINVA:
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		break;
	case M68K_INS_CPUSHL:
	case M68K_INS_CPUSHP:
	case M68K_INS_CPUSHA:
		op->type = RZ_ANALYSIS_OP_TYPE_SYNC;
		break;
	case M68K_INS_DBT:
	case M68K_INS_DBF:
	case M68K_INS_DBHI:
	case M68K_INS_DBLS:
	case M68K_INS_DBCC:
	case M68K_INS_DBCS:
	case M68K_INS_DBNE:
	case M68K_INS_DBEQ:
	case M68K_INS_DBVC:
	case M68K_INS_DBVS:
	case M68K_INS_DBPL:
	case M68K_INS_DBMI:
	case M68K_INS_DBGE:
	case M68K_INS_DBLT:
	case M68K_INS_DBGT:
	case M68K_INS_DBLE:
	case M68K_INS_DBRA:
		handle_branch_instruction(op, addr, m68k, RZ_ANALYSIS_OP_TYPE_CJMP, 1);
		break;
	case M68K_INS_DIVS:
	case M68K_INS_DIVSL:
	case M68K_INS_DIVU:
	case M68K_INS_DIVUL:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case M68K_INS_EOR:
	case M68K_INS_EORI:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case M68K_INS_EXG:
		op->type = RZ_ANALYSIS_OP_TYPE_XCHG;
		break;
	case M68K_INS_EXT:
	case M68K_INS_EXTB:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case M68K_INS_FABS:
	case M68K_INS_FSABS:
	case M68K_INS_FDABS:
	case M68K_INS_FACOS:
	case M68K_INS_FADD:
	case M68K_INS_FSADD:
	case M68K_INS_FDADD:
	case M68K_INS_FASIN:
	case M68K_INS_FATAN:
	case M68K_INS_FATANH:
	case M68K_INS_FBF:
	case M68K_INS_FBEQ:
	case M68K_INS_FBOGT:
	case M68K_INS_FBOGE:
	case M68K_INS_FBOLT:
	case M68K_INS_FBOLE:
	case M68K_INS_FBOGL:
	case M68K_INS_FBOR:
	case M68K_INS_FBUN:
	case M68K_INS_FBUEQ:
	case M68K_INS_FBUGT:
	case M68K_INS_FBUGE:
	case M68K_INS_FBULT:
	case M68K_INS_FBULE:
	case M68K_INS_FBNE:
	case M68K_INS_FBT:
	case M68K_INS_FBSF:
	case M68K_INS_FBSEQ:
	case M68K_INS_FBGT:
	case M68K_INS_FBGE:
	case M68K_INS_FBLT:
	case M68K_INS_FBLE:
	case M68K_INS_FBGL:
	case M68K_INS_FBGLE:
	case M68K_INS_FBNGLE:
	case M68K_INS_FBNGL:
	case M68K_INS_FBNLE:
	case M68K_INS_FBNLT:
	case M68K_INS_FBNGE:
	case M68K_INS_FBNGT:
	case M68K_INS_FBSNE:
	case M68K_INS_FBST:
	case M68K_INS_FCMP:
	case M68K_INS_FCOS:
	case M68K_INS_FCOSH:
	case M68K_INS_FDBF:
	case M68K_INS_FDBEQ:
	case M68K_INS_FDBOGT:
	case M68K_INS_FDBOGE:
	case M68K_INS_FDBOLT:
	case M68K_INS_FDBOLE:
	case M68K_INS_FDBOGL:
	case M68K_INS_FDBOR:
	case M68K_INS_FDBUN:
	case M68K_INS_FDBUEQ:
	case M68K_INS_FDBUGT:
	case M68K_INS_FDBUGE:
	case M68K_INS_FDBULT:
	case M68K_INS_FDBULE:
	case M68K_INS_FDBNE:
	case M68K_INS_FDBT:
	case M68K_INS_FDBSF:
	case M68K_INS_FDBSEQ:
	case M68K_INS_FDBGT:
	case M68K_INS_FDBGE:
	case M68K_INS_FDBLT:
	case M68K_INS_FDBLE:
	case M68K_INS_FDBGL:
	case M68K_INS_FDBGLE:
	case M68K_INS_FDBNGLE:
	case M68K_INS_FDBNGL:
	case M68K_INS_FDBNLE:
	case M68K_INS_FDBNLT:
	case M68K_INS_FDBNGE:
	case M68K_INS_FDBNGT:
	case M68K_INS_FDBSNE:
	case M68K_INS_FDBST:
	case M68K_INS_FDIV:
	case M68K_INS_FSDIV:
	case M68K_INS_FDDIV:
	case M68K_INS_FETOX:
	case M68K_INS_FETOXM1:
	case M68K_INS_FGETEXP:
	case M68K_INS_FGETMAN:
	case M68K_INS_FINT:
	case M68K_INS_FINTRZ:
	case M68K_INS_FLOG10:
	case M68K_INS_FLOG2:
	case M68K_INS_FLOGN:
	case M68K_INS_FLOGNP1:
	case M68K_INS_FMOD:
	case M68K_INS_FMOVE:
	case M68K_INS_FSMOVE:
	case M68K_INS_FDMOVE:
	case M68K_INS_FMOVECR:
	case M68K_INS_FMOVEM:
	case M68K_INS_FMUL:
	case M68K_INS_FSMUL:
	case M68K_INS_FDMUL:
	case M68K_INS_FNEG:
	case M68K_INS_FSNEG:
	case M68K_INS_FDNEG:
	case M68K_INS_FNOP:
	case M68K_INS_FREM:
	case M68K_INS_FRESTORE:
	case M68K_INS_FSAVE:
	case M68K_INS_FSCALE:
	case M68K_INS_FSGLDIV:
	case M68K_INS_FSGLMUL:
	case M68K_INS_FSIN:
	case M68K_INS_FSINCOS:
	case M68K_INS_FSINH:
	case M68K_INS_FSQRT:
	case M68K_INS_FSSQRT:
	case M68K_INS_FDSQRT:
	case M68K_INS_FSF:
	case M68K_INS_FSBEQ:
	case M68K_INS_FSOGT:
	case M68K_INS_FSOGE:
	case M68K_INS_FSOLT:
	case M68K_INS_FSOLE:
	case M68K_INS_FSOGL:
	case M68K_INS_FSOR:
	case M68K_INS_FSUN:
	case M68K_INS_FSUEQ:
	case M68K_INS_FSUGT:
	case M68K_INS_FSUGE:
	case M68K_INS_FSULT:
	case M68K_INS_FSULE:
	case M68K_INS_FSNE:
	case M68K_INS_FST:
	case M68K_INS_FSSF:
	case M68K_INS_FSSEQ:
	case M68K_INS_FSGT:
	case M68K_INS_FSGE:
	case M68K_INS_FSLT:
	case M68K_INS_FSLE:
	case M68K_INS_FSGL:
	case M68K_INS_FSGLE:
	case M68K_INS_FSNGLE:
	case M68K_INS_FSNGL:
	case M68K_INS_FSNLE:
	case M68K_INS_FSNLT:
	case M68K_INS_FSNGE:
	case M68K_INS_FSNGT:
	case M68K_INS_FSSNE:
	case M68K_INS_FSST:
	case M68K_INS_FSUB:
	case M68K_INS_FSSUB:
	case M68K_INS_FDSUB:
	case M68K_INS_FTAN:
	case M68K_INS_FTANH:
	case M68K_INS_FTENTOX:
	case M68K_INS_FTRAPF:
	case M68K_INS_FTRAPEQ:
	case M68K_INS_FTRAPOGT:
	case M68K_INS_FTRAPOGE:
	case M68K_INS_FTRAPOLT:
	case M68K_INS_FTRAPOLE:
	case M68K_INS_FTRAPOGL:
	case M68K_INS_FTRAPOR:
	case M68K_INS_FTRAPUN:
	case M68K_INS_FTRAPUEQ:
	case M68K_INS_FTRAPUGT:
	case M68K_INS_FTRAPUGE:
	case M68K_INS_FTRAPULT:
	case M68K_INS_FTRAPULE:
	case M68K_INS_FTRAPNE:
	case M68K_INS_FTRAPT:
	case M68K_INS_FTRAPSF:
	case M68K_INS_FTRAPSEQ:
	case M68K_INS_FTRAPGT:
	case M68K_INS_FTRAPGE:
	case M68K_INS_FTRAPLT:
	case M68K_INS_FTRAPLE:
	case M68K_INS_FTRAPGL:
	case M68K_INS_FTRAPGLE:
	case M68K_INS_FTRAPNGLE:
	case M68K_INS_FTRAPNGL:
	case M68K_INS_FTRAPNLE:
	case M68K_INS_FTRAPNLT:
	case M68K_INS_FTRAPNGE:
	case M68K_INS_FTRAPNGT:
	case M68K_INS_FTRAPSNE:
	case M68K_INS_FTRAPST:
	case M68K_INS_FTST:
	case M68K_INS_FTWOTOX:
		m68k_handle_fpu_instruction(op, addr, m68k, insn->id);
		break;
	case M68K_INS_ILLEGAL:
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		break;
	case M68K_INS_JMP:
		handle_jump_instruction(op, addr, m68k, RZ_ANALYSIS_OP_TYPE_JMP);
		break;
	case M68K_INS_JSR:
		handle_jump_instruction(op, addr, m68k, RZ_ANALYSIS_OP_TYPE_CALL);
		break;
	case M68K_INS_LSL:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case M68K_INS_LINK:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -(st16)IMM(1);
		break;
	case M68K_INS_LSR:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case M68K_INS_PEA:
	case M68K_INS_LEA:
		op->type = RZ_ANALYSIS_OP_TYPE_LEA;
		break;
	case M68K_INS_MOVE:
	case M68K_INS_MOVEA:
	case M68K_INS_MOVEC:
	case M68K_INS_MOVEM:
	case M68K_INS_MOVEP:
	case M68K_INS_MOVEQ:
	case M68K_INS_MOVES:
	case M68K_INS_MOVE16:
		m68k_set_move_type(op, m68k);
		break;
	case M68K_INS_PMOVE:
	case M68K_INS_PMOVEFD:
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		m68k_set_move_type(op, m68k);
		break;
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
	case M68K_INS_MOV3Q:
	case M68K_INS_MOVCLR:
		m68k_set_move_type(op, m68k);
		break;
	case M68K_INS_MVS:
		op->sign = true;
		m68k_set_cast_type(op, m68k);
		break;
	case M68K_INS_MVZ:
		op->sign = false;
		m68k_set_cast_type(op, m68k);
		break;
	case M68K_INS_MAC:
	case M68K_INS_MSAC:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case M68K_INS_SATS:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case M68K_INS_BITREV:
	case M68K_INS_BYTEREV:
		op->type = RZ_ANALYSIS_OP_TYPE_REV;
		break;
	case M68K_INS_FF1:
		op->type = RZ_ANALYSIS_OP_TYPE_BCNT;
		break;
	case M68K_INS_INTOUCH:
		op->type = RZ_ANALYSIS_OP_TYPE_SYNC;
		break;
	case M68K_INS_STRLDSR:
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -4;
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case M68K_INS_WDDATA:
	case M68K_INS_WDEBUG:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
#endif
#ifdef RZ_CAPSTONE_HAS_M68K_CPU32
	case M68K_INS_TBLS:
	case M68K_INS_TBLU:
	case M68K_INS_TBLSN:
	case M68K_INS_TBLUN:
		m68k_set_move_type(op, m68k);
		break;
	case M68K_INS_BGND:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
#endif
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
	case M68K_INS_TPF:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case M68K_INS_CP0BCBUSY:
	case M68K_INS_CP1BCBUSY:
		handle_branch_instruction(op, addr, m68k, RZ_ANALYSIS_OP_TYPE_CJMP, 0);
		break;
	case M68K_INS_CP0LD:
	case M68K_INS_CP1LD:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case M68K_INS_CP0ST:
	case M68K_INS_CP1ST:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case M68K_INS_CP0NOP:
	case M68K_INS_CP1NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
#endif
	case M68K_INS_MULS:
	case M68K_INS_MULU:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case M68K_INS_NBCD:
	case M68K_INS_NEG:
	case M68K_INS_NEGX:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case M68K_INS_NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case M68K_INS_NOT:
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case M68K_INS_OR:
	case M68K_INS_ORI:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case M68K_INS_PACK:
	case M68K_INS_PFLUSH:
	case M68K_INS_PFLUSHA:
	case M68K_INS_PFLUSHAN:
	case M68K_INS_PFLUSHN:
	case M68K_INS_PLOADR:
	case M68K_INS_PLOADW:
	case M68K_INS_PLPAR:
	case M68K_INS_PLPAW:
	case M68K_INS_PTESTR:
	case M68K_INS_PTESTW:
	case M68K_INS_HALT:
	case M68K_INS_PULSE:
	case M68K_INS_RESET:
		break;
	case M68K_INS_REMS:
	case M68K_INS_REMU:
		op->type = RZ_ANALYSIS_OP_TYPE_MOD;
		break;
	case M68K_INS_ROL:
		op->type = RZ_ANALYSIS_OP_TYPE_ROL;
		break;
	case M68K_INS_ROR:
		op->type = RZ_ANALYSIS_OP_TYPE_ROR;
		break;
	case M68K_INS_ROXL:
	case M68K_INS_ROXR:
		break;
	case M68K_INS_RTD:
	case M68K_INS_RTE:
	case M68K_INS_RTM:
	case M68K_INS_RTR:
	case M68K_INS_RTS:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case M68K_INS_SBCD:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case M68K_INS_ST:
	case M68K_INS_SF:
	case M68K_INS_SHI:
	case M68K_INS_SLS:
	case M68K_INS_SCC:
	case M68K_INS_SHS:
	case M68K_INS_SCS:
	case M68K_INS_SLO:
	case M68K_INS_SNE:
	case M68K_INS_SEQ:
	case M68K_INS_SVC:
	case M68K_INS_SVS:
	case M68K_INS_SPL:
	case M68K_INS_SMI:
	case M68K_INS_SGE:
	case M68K_INS_SLT:
	case M68K_INS_SGT:
	case M68K_INS_SLE:
		op->type = RZ_ANALYSIS_OP_TYPE_CMOV;
		break;
	case M68K_INS_LPSTOP:
	case M68K_INS_STOP:
		break;
	case M68K_INS_SUB:
	case M68K_INS_SUBA:
	case M68K_INS_SUBI:
	case M68K_INS_SUBQ:
	case M68K_INS_SUBX:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case M68K_INS_SWAP:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case M68K_INS_TAS:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case M68K_INS_TRAP:
	case M68K_INS_TRAPV:
	case M68K_INS_TRAPT:
	case M68K_INS_TRAPF:
	case M68K_INS_TRAPHI:
	case M68K_INS_TRAPLS:
	case M68K_INS_TRAPCC:
	case M68K_INS_TRAPHS:
	case M68K_INS_TRAPCS:
	case M68K_INS_TRAPLO:
	case M68K_INS_TRAPNE:
	case M68K_INS_TRAPEQ:
	case M68K_INS_TRAPVC:
	case M68K_INS_TRAPVS:
	case M68K_INS_TRAPPL:
	case M68K_INS_TRAPMI:
	case M68K_INS_TRAPGE:
	case M68K_INS_TRAPLT:
	case M68K_INS_TRAPGT:
	case M68K_INS_TRAPLE:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case M68K_INS_TST:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case M68K_INS_UNPK: // unpack BCD
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case M68K_INS_UNLK:
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		// reset stackframe
		op->stackop = RZ_ANALYSIS_STACK_SET;
		op->stackptr = 0;
		break;
	}
	m68k_set_opdir(op);
	if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
		op_fillval(a, op, ctx->handle, insn);
	}
beach:
	cs_free(insn, n);
	// cs_close (&handle);
fin:
	return opsize;
}

static char *m68k_get_reg_profile(RzAnalysis *analysis) {
	// The GPR offsets follow Linux/m68k struct user_regs_struct, which is also
	// the ELF core PRSTATUS regset layout.
	// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/m68k/include/asm/user.h
	const char *p =
		"=PC    pc\n"
		"=SP    a7\n"
		"=BP    a6\n"
		"=A0    a0\n"
		"=A1    a1\n"
		"=A2    a2\n"
		"=A3    a3\n"
		"gpr	d0		.32	56	0\n"
		"gpr	d1		.32	0	0\n"
		"gpr	d2		.32	4	0\n"
		"gpr	d3		.32	8	0\n"
		"gpr	d4		.32	12	0\n"
		"gpr	d5		.32	16	0\n"
		"gpr	d6		.32	20	0\n"
		"gpr	d7		.32	24	0\n"
		"gpr	a0		.32	28	0\n"
		"gpr	a1		.32	32	0\n"
		"gpr	a2 		.32	36	0\n"
		"gpr	a3 		.32	40	0\n"
		"gpr	a4 		.32	44	0\n"
		"gpr	a5		.32	48	0\n"
		"gpr	a6 		.32	52	0\n"
		"gpr	a7 		.32	60	0\n"
		"gpr	pc 		.32	72	0\n"
		"gpr	ccr 	.8	71	0\n" // subset of the SR, available from any mode
		"gpr	fpcr	.32	112	0\n"
		"gpr	fpsr	.32	116	0\n"
		"gpr	fpiar	.32	120	0\n"
		"gpr	sr 		.16	70	0\n" // only available for read and write access during supervisor mode
		"gpr	sfc 	.32	124	0\n" // source function code register
		"gpr	dfc		.32	128	0\n" // destination function code register
		"gpr	usp		.32	240	0\n" // user stack point this is an shadow register of A7 user mode, SR bit 0xD is 0
		"gpr	vbr		.32	132	0\n" // vector base register, this is a Address pointer
		"gpr	cacr	.32	136	0\n" // cache control register, implementation specific
		"gpr	caar	.32	140	0\n" // cache address register, 68020, 68EC020, 68030 and 68EC030 only.
		"gpr	msp		.32	144	0\n" // master stack pointer, this is an shadow register of A7 supervisor mode, SR bits 0xD && 0xC are set
		"gpr	isp		.32	148	0\n" // interrupt stack pointer, this is an shadow register of A7  supervisor mode, SR bit 0xD is set, 0xC is not.
		"gpr	tc		.32	152	0\n"
		"gpr	itt0	.32	156	0\n" // in 68EC040 this is IACR0
		"gpr	itt1	.32	160	0\n" // in 68EC040 this is IACR1
		"gpr	dtt0	.32	164	0\n" // in 68EC040 this is DACR0
		"gpr	dtt1	.32	168	0\n" // in 68EC040 this is DACR1
		"gpr	mmusr	.32	172	0\n"
		"gpr	urp		.32	176	0\n"
		"gpr	srp		.64	180	0\n"
		"gpr	tt0		.32	188	0\n"
		"gpr	tt1		.32	192	0\n"
		"gpr	crp		.64	196	0\n"
		"gpr	acc		.32	204	0\n"
		"gpr	acc0	.32	208	0\n"
		"gpr	acc1	.32	212	0\n"
		"gpr	acc2	.32	216	0\n"
		"gpr	acc3	.32	220	0\n"
		"gpr	accext01	.32	224	0\n"
		"gpr	accext23	.32	228	0\n"
		"gpr	macsr	.32	232	0\n"
		"gpr	mask	.32	236	0\n"
		"fpu	fp0		.80	244	0\n" // FPU data register 0, 80-bit extended precision
		"fpu	fp1		.80	254	0\n" // FPU data register 1, 80-bit extended precision
		"fpu	fp2		.80	264	0\n" // FPU data register 2, 80-bit extended precision
		"fpu	fp3		.80	274	0\n" // FPU data register 3, 80-bit extended precision
		"fpu	fp4		.80	284	0\n" // FPU data register 4, 80-bit extended precision
		"fpu	fp5		.80	294	0\n" // FPU data register 5, 80-bit extended precision
		"fpu	fp6		.80	304	0\n" // FPU data register 6, 80-bit extended precision
		"fpu	fp7		.80	314	0\n" // FPU data register 7, 80-bit extended precision
		"gpr	cp_external_data	.32	324	0\n";
	return rz_str_dup(p);
}

static bool m68k_fini(void *user) {
	M68KContext *ctx = (M68KContext *)user;
	if (ctx) {
		cs_close(&ctx->handle);
		free(ctx);
	}
	return true;
}

static int m68k_archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 2;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return M68K_LONGEST_INSTRUCTION;
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

RzAnalysisPlugin rz_analysis_plugin_m68k_cs = {
	.name = "m68k",
	.desc = "Capstone M68K analyzer",
	.license = "BSD",
	.esil = false,
	.arch = "m68k",
	.get_reg_profile = &m68k_get_reg_profile,
	.bits = 32,
	.op = &m68k_analyze_op,
	.init = m68k_init,
	.fini = m68k_fini,
	.archinfo = m68k_archinfo,
	.il_config = rz_m68k_cs_il_config,
};

#else
RzAnalysisPlugin rz_analysis_plugin_m68k_cs = {
	.name = "m68k (unsupported)",
	.desc = "Capstone M68K analyzer (unsupported)",
	.license = "BSD",
	.arch = "m68k",
	.bits = 32,
};
#endif

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_m68k_cs,
	.version = RZ_VERSION
};
#endif
