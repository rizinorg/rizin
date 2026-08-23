// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "riscv_il_fd_common.h"

static const RzFloatFormat rz_riscv_il_fd_f32 = RZ_FLOAT_IEEE754_BIN_32;

// F-extension entry points specialize the common core with the binary32 format.

RzILOpEffect *rz_riscv_lift_flw(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_load(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fsw(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_store(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fadd_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_add(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fsub_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_sub(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fmul_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_mul(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fdiv_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_div(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fsqrt_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_sqrt(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fmadd_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fmadd(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fmsub_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fmsub(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fnmadd_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fnmadd(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fnmsub_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fnmsub(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fsgnj_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fsgnj(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fsgnjn_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fsgnjn(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fsgnjx_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fsgnjx(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fmin_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fmin(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fmax_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fmax(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_feq_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_feq(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_flt_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_flt(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fle_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fle(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fclass_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fclass(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fcvt_w_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fcvt_w(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fcvt_wu_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fcvt_wu(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fcvt_l_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fcvt_l(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fcvt_lu_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fcvt_lu(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fcvt_s_w(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fcvt_from_w(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fcvt_s_wu(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fcvt_from_wu(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fcvt_s_l(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fcvt_from_l(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fcvt_s_lu(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fcvt_from_lu(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fmv_x_w(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fmv_to_x(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}

RzILOpEffect *rz_riscv_lift_fmv_w_x(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	return riscv_il_fd_lift_fmv_from_x(rz_riscv_il_fd_f32,
		analysis, op, insn, current_addr, size);
}
