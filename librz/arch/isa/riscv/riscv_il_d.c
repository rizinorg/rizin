// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "riscv_il_fd_common.h"

static const RzFloatFormat rz_riscv_il_fd_f32 = RZ_FLOAT_IEEE754_BIN_32;
static const RzFloatFormat rz_riscv_il_fd_f64 = RZ_FLOAT_IEEE754_BIN_64;

// D-extension entry points specialize the common core with the binary64 format.

RzILOpEffect *rz_riscv_lift_fld(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_load(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fsd(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_store(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fadd_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_add(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fsub_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_sub(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fmul_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_mul(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fdiv_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_div(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fsqrt_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_sqrt(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fmadd_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fmadd(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fmsub_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fmsub(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fnmadd_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fnmadd(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fnmsub_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fnmsub(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fsgnj_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fsgnj(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fsgnjn_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fsgnjn(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fsgnjx_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fsgnjx(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fmin_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fmin(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fmax_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fmax(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_feq_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_feq(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_flt_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_flt(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fle_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fle(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fclass_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fclass(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fcvt_w_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fcvt_w(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fcvt_wu_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fcvt_wu(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fcvt_l_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fcvt_l(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fcvt_lu_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fcvt_lu(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fcvt_d_w(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fcvt_from_w(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fcvt_d_wu(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fcvt_from_wu(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fcvt_d_l(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fcvt_from_l(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fcvt_d_lu(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fcvt_from_lu(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fmv_x_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fmv_to_x(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fmv_d_x(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fmv_from_x(rz_riscv_il_fd_f64,
		analysis, op, insn, current_addr, size);
}

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
