// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "m68k/m68k_cs.h"

#include <string.h>

#include <rz_util/rz_assert.h>

#define M68K_FPU_EXT_DST(ext) (((ext) >> 7) & 7)

RZ_IPI bool rz_m68k_reg_is_dreg(m68k_reg reg) {
	return reg >= M68K_REG_D0 && reg <= M68K_REG_D7;
}

RZ_IPI bool rz_m68k_reg_is_areg(m68k_reg reg) {
	return reg >= M68K_REG_A0 && reg <= M68K_REG_A7;
}

RZ_IPI bool rz_m68k_reg_is_gpr(m68k_reg reg) {
	return rz_m68k_reg_is_dreg(reg) || rz_m68k_reg_is_areg(reg);
}

RZ_IPI bool rz_m68k_reg_is_control(m68k_reg reg) {
	switch (reg) {
	case M68K_REG_SFC:
	case M68K_REG_DFC:
	case M68K_REG_USP:
	case M68K_REG_VBR:
	case M68K_REG_CACR:
	case M68K_REG_CAAR:
	case M68K_REG_MSP:
	case M68K_REG_ISP:
	case M68K_REG_TC:
	case M68K_REG_ITT0:
	case M68K_REG_ITT1:
	case M68K_REG_DTT0:
	case M68K_REG_DTT1:
	case M68K_REG_MMUSR:
	case M68K_REG_URP:
	case M68K_REG_SRP:
		return true;
	default:
		return false;
	}
}

RZ_IPI bool rz_m68k_op_is_control_reg(RZ_NONNULL const cs_m68k_op *op) {
	rz_return_val_if_fail(op, false);
	if (op->type != M68K_OP_REG) {
		return false;
	}
	return rz_m68k_reg_is_control(op->reg);
}

RZ_IPI bool rz_m68k_reg_name_is_mmu_root_pointer(RZ_NULLABLE const char *name) {
	return name && (!strcmp(name, "srp") || !strcmp(name, "crp"));
}

RZ_IPI bool rz_m68k_reg_is_fpu(m68k_reg reg) {
	return reg >= M68K_REG_FP0 && reg <= M68K_REG_FP7;
}

RZ_IPI bool rz_m68k_op_is_fpu_reg(RZ_NONNULL const cs_m68k_op *op) {
	rz_return_val_if_fail(op, false);
	if (op->type != M68K_OP_REG) {
		return false;
	}
	return rz_m68k_reg_is_fpu(op->reg);
}

RZ_IPI bool rz_m68k_reg_is_fpu_control(m68k_reg reg) {
	return reg == M68K_REG_FPCR || reg == M68K_REG_FPSR || reg == M68K_REG_FPIAR;
}

RZ_IPI bool rz_m68k_reg_is_acc(m68k_reg reg) {
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
	return reg == M68K_REG_ACC || (reg >= M68K_REG_ACC0 && reg <= M68K_REG_ACC3);
#else
	return false;
#endif
}

RZ_IPI bool rz_m68k_op_is_predec_areg(RZ_NONNULL const cs_m68k_op *op) {
	rz_return_val_if_fail(op, false);
	if (op->address_mode != M68K_AM_REGI_ADDR_PRE_DEC) {
		return false;
	}
	return rz_m68k_reg_is_areg(op->reg);
}

RZ_IPI bool rz_m68k_op_is_data_reg(RZ_NONNULL const cs_m68k_op *op) {
	rz_return_val_if_fail(op, false);
	if (op->type != M68K_OP_REG) {
		return false;
	}
	return rz_m68k_reg_is_dreg(op->reg);
}

RZ_IPI bool rz_m68k_op_is_addr_reg(RZ_NONNULL const cs_m68k_op *op) {
	rz_return_val_if_fail(op, false);
	if (op->type != M68K_OP_REG) {
		return false;
	}
	return rz_m68k_reg_is_areg(op->reg);
}

RZ_IPI bool rz_m68k_op_is_gpr(RZ_NONNULL const cs_m68k_op *op) {
	rz_return_val_if_fail(op, false);
	if (op->type != M68K_OP_REG) {
		return false;
	}
	return rz_m68k_reg_is_gpr(op->reg);
}

RZ_IPI bool rz_m68k_op_is_acc_reg(RZ_NONNULL const cs_m68k_op *op) {
	rz_return_val_if_fail(op, false);
	if (op->type != M68K_OP_REG) {
		return false;
	}
	return rz_m68k_reg_is_acc(op->reg);
}

RZ_IPI bool rz_m68k_op_is_fpu_control_reg(RZ_NONNULL const cs_m68k_op *op) {
	rz_return_val_if_fail(op, false);
	if (op->type != M68K_OP_REG) {
		return false;
	}
	return rz_m68k_reg_is_fpu_control(op->reg);
}

RZ_IPI bool rz_m68k_insn_uses_fpu_operand(RZ_NONNULL const cs_m68k *m68k) {
	rz_return_val_if_fail(m68k, false);
	for (ut8 i = 0; i < m68k->op_count; i++) {
		const cs_m68k_op *op = &m68k->operands[i];
		switch (op->type) {
		case M68K_OP_INVALID:
			// Capstone can retain an invalid operand for malformed or
			// unsupported FPU encodings while decoding later operands.
			continue;
		case M68K_OP_FP_SINGLE:
		case M68K_OP_FP_DOUBLE:
			return true;
		case M68K_OP_REG:
			if (rz_m68k_reg_is_fpu(op->reg)) {
				return true;
			}
			break;
		default:
			break;
		}
	}
	return false;
}

RZ_IPI ut32 rz_m68k_detail_op_bits(RZ_NONNULL const cs_m68k *m68k, ut32 fallback_bits) {
	rz_return_val_if_fail(m68k, fallback_bits);
	if (m68k->op_size.type == M68K_SIZE_TYPE_CPU) {
		switch (m68k->op_size.cpu_size) {
		case M68K_CPU_SIZE_BYTE:
			return 8;
		case M68K_CPU_SIZE_WORD:
			return 16;
		case M68K_CPU_SIZE_LONG:
			return 32;
		default:
			break;
		}
	}
	if (m68k->op_size.type == M68K_SIZE_TYPE_FPU) {
		switch (m68k->op_size.fpu_size) {
		case M68K_FPU_SIZE_SINGLE:
			return 32;
		case M68K_FPU_SIZE_DOUBLE:
			return 64;
		case M68K_FPU_SIZE_EXTENDED:
			return 80;
		default:
			break;
		}
	}
	return fallback_bits;
}

RZ_IPI ut32 rz_m68k_bits_access_bytes(ut32 bits) {
	return RZ_MAX(1, bits / 8);
}

RZ_IPI ut32 rz_m68k_reg_stack_access_bytes(m68k_reg reg, ut32 bits) {
	ut32 bytes = rz_m68k_bits_access_bytes(bits);
	// A7 is 32 bits; this is the address-register delta, not its width. A
	// byte-sized predecrement/postincrement adjusts A7 by 2 bytes to preserve
	// stack word alignment (M68000 PRM).
	return reg == M68K_REG_A7 && bytes == 1 ? 2 : bytes;
}

RZ_IPI m68k_reg rz_m68k_op_base_reg(RZ_NONNULL const cs_m68k_op *op) {
	rz_return_val_if_fail(op, M68K_REG_INVALID);
	if (op->mem.base_reg != M68K_REG_INVALID) {
		return op->mem.base_reg;
	}
	return rz_m68k_reg_is_areg(op->reg) ? op->reg : M68K_REG_INVALID;
}

RZ_IPI ut32 rz_m68k_op_absolute_address(RZ_NONNULL const cs_m68k_op *op, bool short_addr) {
	rz_return_val_if_fail(op, 0);
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
	st64 address = op->mem.address;
#else
	st64 address = op->imm ? op->imm : op->mem.disp;
#endif
	return short_addr ? (ut32)(st32)(st16)address : (ut32)address;
}

RZ_IPI bool rz_m68k_op_is_mem_addr(RZ_NONNULL const cs_m68k_op *op) {
	rz_return_val_if_fail(op, false);
	switch (op->address_mode) {
	case M68K_AM_REGI_ADDR:
	case M68K_AM_REGI_ADDR_POST_INC:
	case M68K_AM_REGI_ADDR_PRE_DEC:
	case M68K_AM_REGI_ADDR_DISP:
	case M68K_AM_AREGI_INDEX_8_BIT_DISP:
	case M68K_AM_AREGI_INDEX_BASE_DISP:
	case M68K_AM_MEMI_PRE_INDEX:
	case M68K_AM_MEMI_POST_INDEX:
	case M68K_AM_PCI_DISP:
	case M68K_AM_PCI_INDEX_8_BIT_DISP:
	case M68K_AM_PCI_INDEX_BASE_DISP:
	case M68K_AM_PC_MEMI_PRE_INDEX:
	case M68K_AM_PC_MEMI_POST_INDEX:
	case M68K_AM_ABSOLUTE_DATA_SHORT:
	case M68K_AM_ABSOLUTE_DATA_LONG:
		return true;
	default:
		return op->type == M68K_OP_MEM;
	}
}

RZ_IPI ut64 rz_m68k_op_absolute_mem_address(RZ_NONNULL const cs_m68k_op *operand) {
	rz_return_val_if_fail(operand, 0);
	if (operand->type != M68K_OP_MEM) {
		return 0;
	}
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
	return operand->mem.address;
#else
	if (operand->imm) {
		return operand->imm;
	}
	return (ut64)(st64)(operand->mem.disp + operand->mem.in_disp + operand->mem.out_disp);
#endif
}

RZ_IPI bool rz_m68k_op_is_absolute_mem(RZ_NONNULL const cs_m68k_op *operand) {
	rz_return_val_if_fail(operand, false);
	if (operand->type != M68K_OP_MEM) {
		return false;
	}
	switch (operand->address_mode) {
	case M68K_AM_ABSOLUTE_DATA_SHORT:
	case M68K_AM_ABSOLUTE_DATA_LONG:
		return true;
	default:
		break;
	}
	return operand->mem.base_reg == M68K_REG_INVALID &&
		operand->mem.index_reg == M68K_REG_INVALID &&
		operand->mem.in_base_reg == M68K_REG_INVALID;
}

RZ_IPI bool rz_m68k_insn_cache_requires_address(ut32 insn_id) {
	switch (insn_id) {
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
	case M68K_INS_INTOUCH:
#endif
	case M68K_INS_CINVL:
	case M68K_INS_CINVP:
	case M68K_INS_CPUSHL:
	case M68K_INS_CPUSHP:
		return true;
	default:
		return false;
	}
}

RZ_IPI bool rz_m68k_op_is_data_reg_pair(RZ_NONNULL const cs_m68k_op *op) {
	rz_return_val_if_fail(op, false);
	if (op->type != M68K_OP_REG_PAIR) {
		return false;
	}
	return rz_m68k_reg_is_dreg(op->reg_pair.reg_0) && rz_m68k_reg_is_dreg(op->reg_pair.reg_1);
}

RZ_IPI bool rz_m68k_op_is_gpr_reg_pair(RZ_NONNULL const cs_m68k_op *op) {
	rz_return_val_if_fail(op, false);
	if (op->type != M68K_OP_REG_PAIR) {
		return false;
	}
	m68k_reg r0 = op->reg_pair.reg_0;
	m68k_reg r1 = op->reg_pair.reg_1;
	return rz_m68k_reg_is_gpr(r0) && rz_m68k_reg_is_gpr(r1);
}

#ifdef RZ_CAPSTONE_HAS_M68K_CPU32
RZ_IPI bool rz_m68k_tbl_insn_is_signed(m68k_insn insn) {
	return insn == M68K_INS_TBLS || insn == M68K_INS_TBLSN;
}

RZ_IPI bool rz_m68k_tbl_insn_is_unrounded(m68k_insn insn) {
	return insn == M68K_INS_TBLSN || insn == M68K_INS_TBLUN;
}
#endif

RZ_IPI bool rz_m68k_fpu_insn_extension_word(RZ_NONNULL const cs_insn *insn, RZ_NONNULL ut16 *extension) {
	rz_return_val_if_fail(insn && extension, false);
	if (insn->size < 4) {
		return false;
	}
	*extension = ((ut16)insn->bytes[2] << 8) | insn->bytes[3];
	return true;
}

RZ_IPI m68k_reg rz_m68k_fpu_insn_extension_dst_reg(RZ_NONNULL const cs_insn *insn) {
	rz_return_val_if_fail(insn, M68K_REG_INVALID);
	ut16 extension = 0;
	if (!rz_m68k_fpu_insn_extension_word(insn, &extension)) {
		return M68K_REG_INVALID;
	}
	return M68K_REG_FP0 + M68K_FPU_EXT_DST(extension);
}

// Capstone collapses some FPU read-modify-write instructions to one operand
// when source and destination are the same
// (for example "frem fp0"). The
// destination remains encoded in the FPU extension word; materialize it as a
// synthetic second operand so analysis and IL can use a uniform two-operand
// form.

RZ_IPI bool rz_m68k_fpu_insn_hidden_dst_op(RZ_NONNULL const cs_insn *insn, RZ_NONNULL cs_m68k_op *dst) {
	rz_return_val_if_fail(insn && dst, false);
	m68k_reg reg = rz_m68k_fpu_insn_extension_dst_reg(insn);
	if (!rz_m68k_reg_is_fpu(reg)) {
		return false;
	}
	memset(dst, 0, sizeof(*dst));
	dst->type = M68K_OP_REG;
	dst->reg = reg;
	return true;
}

RZ_IPI bool rz_m68k_fpu_op_from_reg(RZ_NONNULL cs_m68k_op *op, m68k_reg reg) {
	rz_return_val_if_fail(op, false);
	if (!rz_m68k_reg_is_fpu(reg)) {
		return false;
	}
	memset(op, 0, sizeof(*op));
	op->type = M68K_OP_REG;
	op->reg = reg;
	return true;
}

RZ_IPI RZ_NULLABLE const cs_m68k_op *rz_m68k_fpu_insn_second_op_or_hidden_dst(RZ_NONNULL const cs_insn *insn, RZ_NONNULL cs_m68k_op *hidden_dst) {
	rz_return_val_if_fail(insn && insn->detail && hidden_dst, NULL);
	const cs_m68k *m68k = &insn->detail->m68k;
	if (m68k->op_count > 1) {
		return &m68k->operands[1];
	}
	return rz_m68k_fpu_insn_hidden_dst_op(insn, hidden_dst) ? hidden_dst : NULL;
}

RZ_IPI RZ_NULLABLE const cs_m68k_op *rz_m68k_fpu_insn_unary_dst_op(RZ_NONNULL const cs_insn *insn, RZ_NONNULL const cs_m68k_op *src, RZ_NONNULL cs_m68k_op *hidden_dst) {
	rz_return_val_if_fail(insn && insn->detail && src && hidden_dst, NULL);
	const cs_m68k *m68k = &insn->detail->m68k;
	if (m68k->op_count > 1) {
		return &m68k->operands[1];
	}
	if (rz_m68k_op_is_fpu_reg(src)) {
		m68k_reg reg = rz_m68k_fpu_insn_extension_dst_reg(insn);
		if (rz_m68k_reg_is_fpu(reg) && reg != src->reg && rz_m68k_fpu_insn_hidden_dst_op(insn, hidden_dst)) {
			return hidden_dst;
		}
		return src;
	}
	return rz_m68k_fpu_insn_hidden_dst_op(insn, hidden_dst) ? hidden_dst : NULL;
}

RZ_IPI bool rz_m68k_fpu_insn_has_data_dst(unsigned int insn_id) {
	switch (insn_id) {
	case M68K_INS_FMOVECR:
	case M68K_INS_FABS:
	case M68K_INS_FSABS:
	case M68K_INS_FDABS:
	case M68K_INS_FACOS:
	case M68K_INS_FASIN:
	case M68K_INS_FATAN:
	case M68K_INS_FATANH:
	case M68K_INS_FCOS:
	case M68K_INS_FCOSH:
	case M68K_INS_FETOX:
	case M68K_INS_FETOXM1:
	case M68K_INS_FLOG10:
	case M68K_INS_FLOG2:
	case M68K_INS_FLOGN:
	case M68K_INS_FLOGNP1:
	case M68K_INS_FNEG:
	case M68K_INS_FSNEG:
	case M68K_INS_FDNEG:
	case M68K_INS_FSIN:
	case M68K_INS_FSINH:
	case M68K_INS_FSQRT:
	case M68K_INS_FSSQRT:
	case M68K_INS_FDSQRT:
	case M68K_INS_FTAN:
	case M68K_INS_FTANH:
	case M68K_INS_FTENTOX:
	case M68K_INS_FTWOTOX:
	case M68K_INS_FINT:
	case M68K_INS_FINTRZ:
	case M68K_INS_FGETEXP:
	case M68K_INS_FGETMAN:
	case M68K_INS_FADD:
	case M68K_INS_FSADD:
	case M68K_INS_FDADD:
	case M68K_INS_FSUB:
	case M68K_INS_FSSUB:
	case M68K_INS_FDSUB:
	case M68K_INS_FMUL:
	case M68K_INS_FSMUL:
	case M68K_INS_FDMUL:
	case M68K_INS_FSGLMUL:
	case M68K_INS_FDIV:
	case M68K_INS_FSDIV:
	case M68K_INS_FDDIV:
	case M68K_INS_FSGLDIV:
	case M68K_INS_FMOD:
	case M68K_INS_FREM:
	case M68K_INS_FSCALE:
	case M68K_INS_FCMP:
		return true;
	default:
		return false;
	}
}

RZ_IPI bool rz_m68k_fpu_insn_single_op_is_complete(RZ_NONNULL const cs_insn *insn) {
	rz_return_val_if_fail(insn && insn->detail, false);
	if (insn->detail->m68k.op_count != 1) {
		return false;
	}
	const cs_m68k_op *operand = &insn->detail->m68k.operands[0];
	if (!rz_m68k_op_is_fpu_reg(operand)) {
		return false;
	}
	switch (insn->id) {
	case M68K_INS_FABS:
	case M68K_INS_FSABS:
	case M68K_INS_FDABS:
	case M68K_INS_FACOS:
	case M68K_INS_FASIN:
	case M68K_INS_FATAN:
	case M68K_INS_FATANH:
	case M68K_INS_FCOS:
	case M68K_INS_FCOSH:
	case M68K_INS_FETOX:
	case M68K_INS_FETOXM1:
	case M68K_INS_FLOG10:
	case M68K_INS_FLOG2:
	case M68K_INS_FLOGN:
	case M68K_INS_FLOGNP1:
	case M68K_INS_FNEG:
	case M68K_INS_FSNEG:
	case M68K_INS_FDNEG:
	case M68K_INS_FSIN:
	case M68K_INS_FSINH:
	case M68K_INS_FSQRT:
	case M68K_INS_FSSQRT:
	case M68K_INS_FDSQRT:
	case M68K_INS_FTAN:
	case M68K_INS_FTANH:
	case M68K_INS_FTENTOX:
	case M68K_INS_FTWOTOX:
	case M68K_INS_FINT:
	case M68K_INS_FINTRZ:
	case M68K_INS_FGETEXP:
	case M68K_INS_FGETMAN:
	case M68K_INS_FTST:
		return rz_m68k_fpu_insn_extension_dst_reg(insn) == operand->reg;
	default:
		return false;
	}
}

RZ_IPI bool rz_m68k_fpu_insn_needs_hidden_dst(RZ_NONNULL const cs_insn *insn) {
	rz_return_val_if_fail(insn && insn->detail, false);
	if (insn->detail->m68k.op_count != 1 || !rz_m68k_fpu_insn_has_data_dst(insn->id)) {
		return false;
	}
	if (rz_m68k_fpu_insn_single_op_is_complete(insn)) {
		return false;
	}
	return rz_m68k_reg_is_fpu(rz_m68k_fpu_insn_extension_dst_reg(insn));
}

RZ_IPI bool rz_m68k_fpu_size_is_extended(RZ_NONNULL const cs_m68k *m68k) {
	rz_return_val_if_fail(m68k, false);
	return m68k->op_size.type == M68K_SIZE_TYPE_FPU && m68k->op_size.fpu_size == M68K_FPU_SIZE_EXTENDED;
}

RZ_IPI bool rz_m68k_fpu_op_detail_is_invalid(RZ_NULLABLE const cs_m68k_op *op) {
	return !op ||
		op->type == M68K_OP_INVALID ||
		(op->type == M68K_OP_REG && op->reg == M68K_REG_INVALID) ||
		(op->type == M68K_OP_MEM && op->address_mode == M68K_AM_NONE);
}

RZ_IPI bool rz_m68k_fpu_op_is_illegal_read(RZ_NONNULL const cs_m68k *m68k, RZ_NONNULL const cs_m68k_op *op) {
	rz_return_val_if_fail(m68k && op, false);
	if (rz_m68k_op_is_fpu_reg(op)) {
		return false;
	}
	// Capstone produced no usable operand data; there is nothing to read.
	if (rz_m68k_fpu_op_detail_is_invalid(op)) {
		return true;
	}
	// A GPR cannot supply an FPU-sized operand (e.g. fmove.x d0, fp0 is illegal).
	if (m68k->op_size.type == M68K_SIZE_TYPE_FPU && rz_m68k_op_is_gpr(op)) {
		return true;
	}
	// FP immediates use M68K_OP_FP_SINGLE/DOUBLE; an integer immediate cannot
	// encode an FPU-sized value.
	if (m68k->op_size.type == M68K_SIZE_TYPE_FPU && op->type == M68K_OP_IMM) {
		return true;
	}
	// An immediate cannot encode an 80-bit extended precision value.
	if (op->type == M68K_OP_IMM && rz_m68k_detail_op_bits(m68k, 80) == 80) {
		return true;
	}
	return false;
}

RZ_IPI bool rz_m68k_fpu_op_is_illegal_write(RZ_NONNULL const cs_m68k *m68k, RZ_NONNULL const cs_m68k_op *op) {
	rz_return_val_if_fail(m68k && op, false);
	if (rz_m68k_op_is_fpu_reg(op)) {
		return false;
	}
	if (rz_m68k_fpu_op_detail_is_invalid(op)) {
		return true;
	}
	if (m68k->op_size.type == M68K_SIZE_TYPE_FPU) {
		return !rz_m68k_op_is_mem_addr(op);
	}
	return op->type != M68K_OP_REG && !rz_m68k_op_is_mem_addr(op);
}

RZ_IPI bool rz_m68k_fpu_insn_data_alias_has_dst(RZ_NONNULL const cs_insn *insn) {
	rz_return_val_if_fail(insn && insn->detail, false);
	if (insn->detail->m68k.op_count < 1) {
		return false;
	}
	cs_m68k_op hidden_dst;
	const cs_m68k_op *dst = rz_m68k_fpu_insn_second_op_or_hidden_dst(insn, &hidden_dst);
	return dst && rz_m68k_op_is_fpu_reg(dst);
}
