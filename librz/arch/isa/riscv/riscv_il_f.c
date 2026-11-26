// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "riscv_il_fd_common.h"

// F-extension entry points specialize the common core with the binary32 format.

#define DEFINE_FD_PASSTHROUGH(wrapper, called) \
	RzILOpEffect *wrapper(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		return called(RZ_FLOAT_IEEE754_BIN_32, analysis, op, insn, current_addr, size); \
	}

DEFINE_FD_PASSTHROUGH(rz_riscv_lift_flw, riscv_il_fd_lift_load)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fsw, riscv_il_fd_lift_store)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fadd_s, riscv_il_fd_lift_add)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fsub_s, riscv_il_fd_lift_sub)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fmul_s, riscv_il_fd_lift_mul)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fdiv_s, riscv_il_fd_lift_div)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fsqrt_s, riscv_il_fd_lift_sqrt)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fmadd_s, riscv_il_fd_lift_fmadd)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fmsub_s, riscv_il_fd_lift_fmsub)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fnmadd_s, riscv_il_fd_lift_fnmadd)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fnmsub_s, riscv_il_fd_lift_fnmsub)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fsgnj_s, riscv_il_fd_lift_fsgnj)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fsgnjn_s, riscv_il_fd_lift_fsgnjn)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fsgnjx_s, riscv_il_fd_lift_fsgnjx)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fmin_s, riscv_il_fd_lift_fmin)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fmax_s, riscv_il_fd_lift_fmax)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_feq_s, riscv_il_fd_lift_feq)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_flt_s, riscv_il_fd_lift_flt)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fle_s, riscv_il_fd_lift_fle)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fclass_s, riscv_il_fd_lift_fclass)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fcvt_w_s, riscv_il_fd_lift_fcvt_w)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fcvt_wu_s, riscv_il_fd_lift_fcvt_wu)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fcvt_l_s, riscv_il_fd_lift_fcvt_l)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fcvt_lu_s, riscv_il_fd_lift_fcvt_lu)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fcvt_s_w, riscv_il_fd_lift_fcvt_from_w)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fcvt_s_wu, riscv_il_fd_lift_fcvt_from_wu)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fcvt_s_l, riscv_il_fd_lift_fcvt_from_l)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fcvt_s_lu, riscv_il_fd_lift_fcvt_from_lu)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fmv_x_w, riscv_il_fd_lift_fmv_to_x)
DEFINE_FD_PASSTHROUGH(rz_riscv_lift_fmv_w_x, riscv_il_fd_lift_fmv_from_x)

#undef DEFINE_FD_PASSTHROUGH
