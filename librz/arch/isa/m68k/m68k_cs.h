// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_M68K_CS_H
#define RZ_M68K_CS_H

#include <rz_types.h>
#include <rz_util/rz_str.h>
#include <capstone/capstone.h>

#define M68K_MIN_OP_SIZE 2
#define M68K_MAX_OP_SIZE 22

static inline cs_mode rz_m68k_cs_mode(RZ_NULLABLE const char *cpu) {
	if (!cpu) {
		return CS_MODE_M68K_040;
	}
#ifdef RZ_CAPSTONE_HAS_M68K_CPU32
	if (rz_str_casestr(cpu, "cpu32")) {
		return CS_MODE_M68K_CPU32;
	}
#endif
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
	if (rz_str_casestr(cpu, "cfv1")) {
		return CS_MODE_M68K_CFV1;
	}
	if (rz_str_casestr(cpu, "cfv2")) {
		return CS_MODE_M68K_CFV2;
	}
	if (rz_str_casestr(cpu, "cfv3")) {
		return CS_MODE_M68K_CFV3;
	}
	if (rz_str_casestr(cpu, "cfv4e")) {
		return CS_MODE_M68K_CFV4E;
	}
	if (rz_str_casestr(cpu, "cfv4")) {
		return CS_MODE_M68K_CFV4;
	}
	if (rz_str_casestr(cpu, "cfv5")) {
		return CS_MODE_M68K_CFV5;
	}
	if (rz_str_casestr(cpu, "coldfire")) {
		return CS_MODE_M68K_COLDFIRE;
	}
#endif
	if (strstr(cpu, "68000")) {
		return CS_MODE_M68K_000;
	}
	if (strstr(cpu, "68010")) {
		return CS_MODE_M68K_010;
	}
	if (strstr(cpu, "68020")) {
		return CS_MODE_M68K_020;
	}
	if (strstr(cpu, "68030")) {
		return CS_MODE_M68K_030;
	}
	if (strstr(cpu, "68040")) {
		return CS_MODE_M68K_040;
	}
	if (strstr(cpu, "68060")) {
		return CS_MODE_M68K_060;
	}
	return CS_MODE_M68K_040;
}

RZ_IPI bool rz_m68k_reg_is_dreg(m68k_reg reg);
RZ_IPI bool rz_m68k_reg_is_areg(m68k_reg reg);
RZ_IPI bool rz_m68k_reg_is_gpr(m68k_reg reg);
RZ_IPI bool rz_m68k_reg_is_control(m68k_reg reg);
RZ_IPI bool rz_m68k_op_is_control_reg(RZ_NONNULL const cs_m68k_op *op);
RZ_IPI bool rz_m68k_reg_name_is_mmu_root_pointer(RZ_NULLABLE const char *name);
RZ_IPI bool rz_m68k_reg_is_fpu(m68k_reg reg);
RZ_IPI bool rz_m68k_op_is_fpu_reg(RZ_NONNULL const cs_m68k_op *op);
RZ_IPI bool rz_m68k_reg_is_fpu_control(m68k_reg reg);
RZ_IPI bool rz_m68k_reg_is_acc(m68k_reg reg);
RZ_IPI bool rz_m68k_op_is_predec_areg(RZ_NONNULL const cs_m68k_op *op);
RZ_IPI bool rz_m68k_op_is_data_reg(RZ_NONNULL const cs_m68k_op *op);
RZ_IPI bool rz_m68k_op_is_addr_reg(RZ_NONNULL const cs_m68k_op *op);
RZ_IPI bool rz_m68k_op_is_gpr(RZ_NONNULL const cs_m68k_op *op);
RZ_IPI bool rz_m68k_op_is_status_reg(RZ_NONNULL const cs_m68k_op *op);
RZ_IPI bool rz_m68k_op_is_acc_reg(RZ_NONNULL const cs_m68k_op *op);
RZ_IPI bool rz_m68k_op_is_fpu_control_reg(RZ_NONNULL const cs_m68k_op *op);
RZ_IPI bool rz_m68k_insn_uses_fpu_operand(RZ_NONNULL const cs_m68k *m68k);

RZ_IPI ut32 rz_m68k_detail_op_bits(RZ_NONNULL const cs_m68k *m68k, ut32 fallback_bits);
RZ_IPI ut32 rz_m68k_bits_access_bytes(ut32 bits);
RZ_IPI ut32 rz_m68k_reg_stack_access_bytes(m68k_reg reg, ut32 bits);
RZ_IPI m68k_reg rz_m68k_op_base_reg(RZ_NONNULL const cs_m68k_op *op);
RZ_IPI ut32 rz_m68k_op_absolute_address(RZ_NONNULL const cs_m68k_op *op, bool short_addr);
RZ_IPI bool rz_m68k_op_is_mem_addr(RZ_NONNULL const cs_m68k_op *op);

RZ_IPI ut64 rz_m68k_op_absolute_mem_address(RZ_NONNULL const cs_m68k_op *operand);
RZ_IPI bool rz_m68k_op_is_absolute_mem(RZ_NONNULL const cs_m68k_op *operand);
RZ_IPI bool rz_m68k_insn_cache_requires_address(ut32 insn_id);
RZ_IPI bool rz_m68k_op_is_data_reg_pair(RZ_NONNULL const cs_m68k_op *op);
RZ_IPI bool rz_m68k_op_is_gpr_reg_pair(RZ_NONNULL const cs_m68k_op *op);
#ifdef RZ_CAPSTONE_HAS_M68K_CPU32
RZ_IPI bool rz_m68k_tbl_insn_is_signed(m68k_insn insn);
RZ_IPI bool rz_m68k_tbl_insn_is_unrounded(m68k_insn insn);
#endif

RZ_IPI bool rz_m68k_fpu_insn_extension_word(RZ_NONNULL const cs_insn *insn, RZ_NONNULL ut16 *extension);
RZ_IPI m68k_reg rz_m68k_fpu_insn_extension_dst_reg(RZ_NONNULL const cs_insn *insn);
RZ_IPI bool rz_m68k_fpu_insn_hidden_dst_op(RZ_NONNULL const cs_insn *insn, RZ_NONNULL cs_m68k_op *dst);
RZ_IPI bool rz_m68k_fpu_op_from_reg(RZ_NONNULL cs_m68k_op *op, m68k_reg reg);
RZ_IPI RZ_NULLABLE const cs_m68k_op *rz_m68k_fpu_insn_second_op_or_hidden_dst(RZ_NONNULL const cs_insn *insn, RZ_NONNULL cs_m68k_op *hidden_dst);
RZ_IPI RZ_NULLABLE const cs_m68k_op *rz_m68k_fpu_insn_unary_dst_op(RZ_NONNULL const cs_insn *insn, RZ_NONNULL const cs_m68k_op *src, RZ_NONNULL cs_m68k_op *hidden_dst);
RZ_IPI bool rz_m68k_fpu_insn_has_data_dst(ut32 insn_id);
RZ_IPI bool rz_m68k_fpu_insn_single_op_is_complete(RZ_NONNULL const cs_insn *insn);
RZ_IPI bool rz_m68k_fpu_insn_needs_hidden_dst(RZ_NONNULL const cs_insn *insn);
RZ_IPI bool rz_m68k_fpu_size_is_extended(RZ_NONNULL const cs_m68k *m68k);
RZ_IPI bool rz_m68k_fpu_op_detail_is_invalid(RZ_NULLABLE const cs_m68k_op *op);
RZ_IPI bool rz_m68k_fpu_op_is_illegal_read(RZ_NONNULL const cs_m68k *m68k, RZ_NONNULL const cs_m68k_op *op);
RZ_IPI bool rz_m68k_fpu_op_is_illegal_write(RZ_NONNULL const cs_m68k *m68k, RZ_NONNULL const cs_m68k_op *op);
RZ_IPI bool rz_m68k_fpu_insn_data_alias_has_dst(RZ_NONNULL const cs_insn *insn);

#endif // RZ_M68K_CS_H
