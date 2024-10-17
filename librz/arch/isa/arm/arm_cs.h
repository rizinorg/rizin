// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ARM_CS_H
#define RZ_ARM_CS_H

#include <rz_analysis.h>
#pragma GCC diagnostic ignored "-Wenum-compare"
#pragma GCC diagnostic ignored "-Wenum-conversion"
#define CAPSTONE_AARCH64_COMPAT_HEADER
#include <capstone/capstone.h>

RZ_IPI int rz_arm_cs_analysis_op_32_esil(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn, bool thumb);
RZ_IPI int rz_arm_cs_analysis_op_64_esil(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn);

RZ_IPI bool rz_arm_cs_is_group_member(RZ_NONNULL const cs_insn *insn, arm_insn_group feature);

#if CS_NEXT_VERSION >= 6
RZ_IPI bool rz_arm_cs_is_float_insn(const cs_insn *insn);
RZ_IPI const char *rz_arm32_cs_esil_prefix_cond(RzAnalysisOp *op, ARMCC_CondCodes cond_type);
#else
RZ_IPI const char *rz_arm32_cs_esil_prefix_cond(RzAnalysisOp *op, arm_cc cond_type);
#endif
RZ_IPI const char *rz_arm64_cs_esil_prefix_cond(RzAnalysisOp *op, ARM64CC_CondCode cond_type);

RZ_IPI RzILOpEffect *rz_arm_cs_32_il(csh *handle, cs_insn *insn, bool thumb);
RZ_IPI RzAnalysisILConfig *rz_arm_cs_32_il_config(bool big_endian);
RZ_IPI RzILOpEffect *rz_arm_cs_64_il(csh *handle, cs_insn *insn);
RZ_IPI RzAnalysisILConfig *rz_arm_cs_64_il_config(bool big_endian);

#endif
