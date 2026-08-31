// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "riscv_il_fd_common.h"

static const RzFloatFormat rz_riscv_il_fd_f32 = RZ_FLOAT_IEEE754_BIN_32;
static const RzFloatFormat rz_riscv_il_fd_f64 = RZ_FLOAT_IEEE754_BIN_64;

// D-extension entry points specialize the common core with the binary64 format.

#define DEFINE_FD_PASSTHROUGH(wrapper, called) \
	RzILOpEffect *wrapper(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		return called(rz_riscv_il_fd_f64, analysis, op, insn, current_addr, size); \
	}

DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fld, riscv_il_fd_lift_load)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fsd, riscv_il_fd_lift_store)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fadd_d, riscv_il_fd_lift_add)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fsub_d, riscv_il_fd_lift_sub)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fmul_d, riscv_il_fd_lift_mul)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fdiv_d, riscv_il_fd_lift_div)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fsqrt_d, riscv_il_fd_lift_sqrt)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fmadd_d, riscv_il_fd_lift_fmadd)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fmsub_d, riscv_il_fd_lift_fmsub)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fnmadd_d, riscv_il_fd_lift_fnmadd)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fnmsub_d, riscv_il_fd_lift_fnmsub)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fsgnj_d, riscv_il_fd_lift_fsgnj)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fsgnjn_d, riscv_il_fd_lift_fsgnjn)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fsgnjx_d, riscv_il_fd_lift_fsgnjx)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fmin_d, riscv_il_fd_lift_fmin)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fmax_d, riscv_il_fd_lift_fmax)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_feq_d, riscv_il_fd_lift_feq)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_flt_d, riscv_il_fd_lift_flt)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fle_d, riscv_il_fd_lift_fle)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fclass_d, riscv_il_fd_lift_fclass)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fcvt_w_d, riscv_il_fd_lift_fcvt_w)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fcvt_wu_d, riscv_il_fd_lift_fcvt_wu)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fcvt_l_d, riscv_il_fd_lift_fcvt_l)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fcvt_lu_d, riscv_il_fd_lift_fcvt_lu)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fcvt_d_w, riscv_il_fd_lift_fcvt_from_w)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fcvt_d_wu, riscv_il_fd_lift_fcvt_from_wu)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fcvt_d_l, riscv_il_fd_lift_fcvt_from_l)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fcvt_d_lu, riscv_il_fd_lift_fcvt_from_lu)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fmv_x_d, riscv_il_fd_lift_fmv_to_x)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fmv_d_x, riscv_il_fd_lift_fmv_from_x)

#undef DEFINE_FD_PASSTHROUGH

RzILOpEffect *rz_riscv_lift_fcvt_d_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fcvt_format(rz_riscv_il_fd_f64, rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fcvt_s_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fcvt_format(rz_riscv_il_fd_f32, rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}
