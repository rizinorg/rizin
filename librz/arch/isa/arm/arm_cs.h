// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ARM_CS_H
#define RZ_ARM_CS_H

#include "analysis_private.h"

#if CC_SUPPORTS_W_ENUM_COMPARE
#pragma GCC diagnostic ignored "-Wenum-compare"
#endif

#ifdef CC_SUPPORTS_W_ENUM_CONVERION
#pragma GCC diagnostic ignored "-Wenum-conversion"
#endif

#define CAPSTONE_AARCH64_COMPAT_HEADER
#include <capstone/capstone.h>

RZ_IPI int rz_arm_cs_analysis_op_32_esil(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn, bool thumb);
RZ_IPI int rz_arm_cs_analysis_op_64_esil(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn);

RZ_IPI bool rz_arm_cs_is_group_member(RZ_NONNULL const cs_insn *insn, arm_insn_group feature);

/**
 * \brief Fields of the CPSR or SPSR that an MSR writes, as in the mask of its encoding
 */
typedef enum {
	RZ_ARM_PSR_FIELD_C = 1 << 0, ///< Control, bits [7:0]
	RZ_ARM_PSR_FIELD_X = 1 << 1, ///< Extension, bits [15:8]
	RZ_ARM_PSR_FIELD_S = 1 << 2, ///< Status, bits [23:16]
	RZ_ARM_PSR_FIELD_F = 1 << 3, ///< Flags, bits [31:24]
} RzArmPsrField;

RZ_IPI ut32 rz_arm_cs_msr_psr_fields(RZ_NONNULL const cs_insn *insn, RZ_NONNULL RZ_OUT bool *spsr);

#if CS_NEXT_VERSION >= 6
RZ_IPI bool rz_arm_cs_is_float_insn(const cs_insn *insn);
RZ_IPI const char *rz_arm32_cs_esil_prefix_cond(RzAnalysisOp *op, ARMCC_CondCodes cond_type);
#else
RZ_IPI const char *rz_arm32_cs_esil_prefix_cond(RzAnalysisOp *op, arm_cc cond_type);
#endif
RZ_IPI const char *rz_arm64_cs_esil_prefix_cond(RzAnalysisOp *op, arm64_cc cond_type);

RZ_IPI RzILOpEffect *rz_arm_cs_32_il(csh *handle, cs_insn *insn, bool thumb);
RZ_IPI RzAnalysisILConfig *rz_arm_cs_32_il_config(bool big_endian, bool mclass);
RZ_IPI RzILOpEffect *rz_arm_cs_64_il(csh *handle, cs_insn *insn);
RZ_IPI RzAnalysisILConfig *rz_arm_cs_64_il_config(bool big_endian);

#endif
