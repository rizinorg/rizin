// SPDX-FileCopyrightText: 2021 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

// LLVM commit: bc5ac5f3ebb0bc4fc65cef7160c817ca3174a68e
// LLVM commit date: 2026-03-15 10:22:07 -0700 (ISO 8601 format)
// Date of code generation: 2026-03-23 17:45:56+01:00
//========================================
// The following code is generated.
// Do not edit. Repository of code generator:
// https://github.com/rizinorg/rz-hexagon

#include <rz_il/rz_il_opbuilder_begin.h>
#include "../hexagon_il.h"
#include <hexagon/hexagon.h>
#include <rz_il/rz_il_opcodes.h>

// Vd = vgetqfext(Vu.x,Rt)
RzILOpEffect *hex_il_op_v6_get_qfext(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vx |= vgetqfext(Vu.x,Rt)
RzILOpEffect *hex_il_op_v6_get_qfext_oracc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.x = vsetqfext(Vu,Rt)
RzILOpEffect *hex_il_op_v6_set_qfext(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd = vmemu(Rt+Ii)
RzILOpEffect *hex_il_op_v6_vl32ub_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd = vmemu(Rx++Ii)
RzILOpEffect *hex_il_op_v6_vl32ub_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd = vmemu(Rx++Mu)
RzILOpEffect *hex_il_op_v6_vl32ub_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd = vmem(Rt+Ii)
RzILOpEffect *hex_il_op_v6_vl32b_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.cur = vmem(Rt+Ii)
RzILOpEffect *hex_il_op_v6_vl32b_cur_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) Vd.cur = vmem(Rt+Ii)
RzILOpEffect *hex_il_op_v6_vl32b_cur_npred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) Vd.cur = vmem(Rx++Ii)
RzILOpEffect *hex_il_op_v6_vl32b_cur_npred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) Vd.cur = vmem(Rx++Mu)
RzILOpEffect *hex_il_op_v6_vl32b_cur_npred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.cur = vmem(Rx++Ii)
RzILOpEffect *hex_il_op_v6_vl32b_cur_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.cur = vmem(Rx++Mu)
RzILOpEffect *hex_il_op_v6_vl32b_cur_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) Vd.cur = vmem(Rt+Ii)
RzILOpEffect *hex_il_op_v6_vl32b_cur_pred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) Vd.cur = vmem(Rx++Ii)
RzILOpEffect *hex_il_op_v6_vl32b_cur_pred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) Vd.cur = vmem(Rx++Mu)
RzILOpEffect *hex_il_op_v6_vl32b_cur_pred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) Vd = vmem(Rt+Ii)
RzILOpEffect *hex_il_op_v6_vl32b_npred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) Vd = vmem(Rx++Ii)
RzILOpEffect *hex_il_op_v6_vl32b_npred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) Vd = vmem(Rx++Mu)
RzILOpEffect *hex_il_op_v6_vl32b_npred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd = vmem(Rt+Ii):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.cur = vmem(Rt+Ii):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_cur_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) Vd.cur = vmem(Rt+Ii):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_cur_npred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) Vd.cur = vmem(Rx++Ii):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_cur_npred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) Vd.cur = vmem(Rx++Mu):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_cur_npred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.cur = vmem(Rx++Ii):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_cur_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.cur = vmem(Rx++Mu):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_cur_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) Vd.cur = vmem(Rt+Ii):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_cur_pred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) Vd.cur = vmem(Rx++Ii):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_cur_pred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) Vd.cur = vmem(Rx++Mu):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_cur_pred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) Vd = vmem(Rt+Ii):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_npred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) Vd = vmem(Rx++Ii):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_npred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) Vd = vmem(Rx++Mu):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_npred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd = vmem(Rx++Ii):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd = vmem(Rx++Mu):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) Vd = vmem(Rt+Ii):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_pred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) Vd = vmem(Rx++Ii):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_pred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) Vd = vmem(Rx++Mu):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_pred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.tmp = vmem(Rt+Ii):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_tmp_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) Vd.tmp = vmem(Rt+Ii):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_tmp_npred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) Vd.tmp = vmem(Rx++Ii):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_tmp_npred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) Vd.tmp = vmem(Rx++Mu):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_tmp_npred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.tmp = vmem(Rx++Ii):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_tmp_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.tmp = vmem(Rx++Mu):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_tmp_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) Vd.tmp = vmem(Rt+Ii):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_tmp_pred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) Vd.tmp = vmem(Rx++Ii):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_tmp_pred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) Vd.tmp = vmem(Rx++Mu):nt
RzILOpEffect *hex_il_op_v6_vl32b_nt_tmp_pred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd = vmem(Rx++Ii)
RzILOpEffect *hex_il_op_v6_vl32b_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd = vmem(Rx++Mu)
RzILOpEffect *hex_il_op_v6_vl32b_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) Vd = vmem(Rt+Ii)
RzILOpEffect *hex_il_op_v6_vl32b_pred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) Vd = vmem(Rx++Ii)
RzILOpEffect *hex_il_op_v6_vl32b_pred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) Vd = vmem(Rx++Mu)
RzILOpEffect *hex_il_op_v6_vl32b_pred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.tmp = vmem(Rt+Ii)
RzILOpEffect *hex_il_op_v6_vl32b_tmp_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) Vd.tmp = vmem(Rt+Ii)
RzILOpEffect *hex_il_op_v6_vl32b_tmp_npred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) Vd.tmp = vmem(Rx++Ii)
RzILOpEffect *hex_il_op_v6_vl32b_tmp_npred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) Vd.tmp = vmem(Rx++Mu)
RzILOpEffect *hex_il_op_v6_vl32b_tmp_npred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.tmp = vmem(Rx++Ii)
RzILOpEffect *hex_il_op_v6_vl32b_tmp_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.tmp = vmem(Rx++Mu)
RzILOpEffect *hex_il_op_v6_vl32b_tmp_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) Vd.tmp = vmem(Rt+Ii)
RzILOpEffect *hex_il_op_v6_vl32b_tmp_pred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) Vd.tmp = vmem(Rx++Ii)
RzILOpEffect *hex_il_op_v6_vl32b_tmp_pred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) Vd.tmp = vmem(Rx++Mu)
RzILOpEffect *hex_il_op_v6_vl32b_tmp_pred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// vmemu(Rt+Ii) = Vs
RzILOpEffect *hex_il_op_v6_vs32ub_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) vmemu(Rt+Ii) = Vs
RzILOpEffect *hex_il_op_v6_vs32ub_npred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) vmemu(Rx++Ii) = Vs
RzILOpEffect *hex_il_op_v6_vs32ub_npred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) vmemu(Rx++Mu) = Vs
RzILOpEffect *hex_il_op_v6_vs32ub_npred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// vmemu(Rx++Ii) = Vs
RzILOpEffect *hex_il_op_v6_vs32ub_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// vmemu(Rx++Mu) = Vs
RzILOpEffect *hex_il_op_v6_vs32ub_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) vmemu(Rt+Ii) = Vs
RzILOpEffect *hex_il_op_v6_vs32ub_pred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) vmemu(Rx++Ii) = Vs
RzILOpEffect *hex_il_op_v6_vs32ub_pred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) vmemu(Rx++Mu) = Vs
RzILOpEffect *hex_il_op_v6_vs32ub_pred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// vmem(Rt+Ii) = Vs
RzILOpEffect *hex_il_op_v6_vs32b_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) vmem(Rt+Ii) = Vs
RzILOpEffect *hex_il_op_v6_vs32b_npred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) vmem(Rx++Ii) = Vs
RzILOpEffect *hex_il_op_v6_vs32b_npred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) vmem(Rx++Mu) = Vs
RzILOpEffect *hex_il_op_v6_vs32b_npred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Qv) vmem(Rt+Ii) = Vs
RzILOpEffect *hex_il_op_v6_vs32b_nqpred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Qv) vmem(Rx++Ii) = Vs
RzILOpEffect *hex_il_op_v6_vs32b_nqpred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Qv) vmem(Rx++Mu) = Vs
RzILOpEffect *hex_il_op_v6_vs32b_nqpred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// vmem(Rt+Ii):nt = Vs
RzILOpEffect *hex_il_op_v6_vs32b_nt_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) vmem(Rt+Ii):nt = Vs
RzILOpEffect *hex_il_op_v6_vs32b_nt_npred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) vmem(Rx++Ii):nt = Vs
RzILOpEffect *hex_il_op_v6_vs32b_nt_npred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) vmem(Rx++Mu):nt = Vs
RzILOpEffect *hex_il_op_v6_vs32b_nt_npred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Qv) vmem(Rt+Ii):nt = Vs
RzILOpEffect *hex_il_op_v6_vs32b_nt_nqpred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Qv) vmem(Rx++Ii):nt = Vs
RzILOpEffect *hex_il_op_v6_vs32b_nt_nqpred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Qv) vmem(Rx++Mu):nt = Vs
RzILOpEffect *hex_il_op_v6_vs32b_nt_nqpred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// vmem(Rx++Ii):nt = Vs
RzILOpEffect *hex_il_op_v6_vs32b_nt_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// vmem(Rx++Mu):nt = Vs
RzILOpEffect *hex_il_op_v6_vs32b_nt_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) vmem(Rt+Ii):nt = Vs
RzILOpEffect *hex_il_op_v6_vs32b_nt_pred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) vmem(Rx++Ii):nt = Vs
RzILOpEffect *hex_il_op_v6_vs32b_nt_pred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) vmem(Rx++Mu):nt = Vs
RzILOpEffect *hex_il_op_v6_vs32b_nt_pred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Qv) vmem(Rt+Ii):nt = Vs
RzILOpEffect *hex_il_op_v6_vs32b_nt_qpred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Qv) vmem(Rx++Ii):nt = Vs
RzILOpEffect *hex_il_op_v6_vs32b_nt_qpred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Qv) vmem(Rx++Mu):nt = Vs
RzILOpEffect *hex_il_op_v6_vs32b_nt_qpred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// vmem(Rx++Ii) = Vs
RzILOpEffect *hex_il_op_v6_vs32b_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// vmem(Rx++Mu) = Vs
RzILOpEffect *hex_il_op_v6_vs32b_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) vmem(Rt+Ii) = Vs
RzILOpEffect *hex_il_op_v6_vs32b_pred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) vmem(Rx++Ii) = Vs
RzILOpEffect *hex_il_op_v6_vs32b_pred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) vmem(Rx++Mu) = Vs
RzILOpEffect *hex_il_op_v6_vs32b_pred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Qv) vmem(Rt+Ii) = Vs
RzILOpEffect *hex_il_op_v6_vs32b_qpred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Qv) vmem(Rx++Ii) = Vs
RzILOpEffect *hex_il_op_v6_vs32b_qpred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Qv) vmem(Rx++Mu) = Vs
RzILOpEffect *hex_il_op_v6_vs32b_qpred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// vmem(Rt+Ii):scatter_release
RzILOpEffect *hex_il_op_v6_vs32b_srls_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// vmem(Rx++Ii):scatter_release
RzILOpEffect *hex_il_op_v6_vs32b_srls_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// vmem(Rx++Mu):scatter_release
RzILOpEffect *hex_il_op_v6_vs32b_srls_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.f8 = vabs(Vu.f8)
RzILOpEffect *hex_il_op_v6_vabs_f8(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.hf = vabs(Vu.hf)
RzILOpEffect *hex_il_op_v6_vabs_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf16 = vabs(Vu.hf)
RzILOpEffect *hex_il_op_v6_vabs_qf16_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf16 = vabs(Vu.qf16)
RzILOpEffect *hex_il_op_v6_vabs_qf16_qf16(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf32 = vabs(Vu.qf32)
RzILOpEffect *hex_il_op_v6_vabs_qf32_qf32(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf32 = vabs(Vu.sf)
RzILOpEffect *hex_il_op_v6_vabs_qf32_sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.sf = vabs(Vu.sf)
RzILOpEffect *hex_il_op_v6_vabs_sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf16 = vadd(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vadd_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdd.hf = vadd(Vu.f8,Vv.f8)
RzILOpEffect *hex_il_op_v6_vadd_hf_f8(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.hf = vadd(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vadd_hf_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf16 = vadd(Vu.qf16,Vv.qf16)
RzILOpEffect *hex_il_op_v6_vadd_qf16(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf16 = vadd(Vu.qf16,Vv.hf)
RzILOpEffect *hex_il_op_v6_vadd_qf16_mix(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf32 = vadd(Vu.qf32,Vv.qf32)
RzILOpEffect *hex_il_op_v6_vadd_qf32(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf32 = vadd(Vu.qf32,Vv.sf)
RzILOpEffect *hex_il_op_v6_vadd_qf32_mix(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf32 = vadd(Vu.sf,Vv.sf)
RzILOpEffect *hex_il_op_v6_vadd_sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdd.sf = vadd(Vu.bf,Vv.bf)
RzILOpEffect *hex_il_op_v6_vadd_sf_bf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdd.sf = vadd(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vadd_sf_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.sf = vadd(Vu.sf,Vv.sf)
RzILOpEffect *hex_il_op_v6_vadd_sf_sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd = valign4(Vu,Vv,Rt)
RzILOpEffect *hex_il_op_v6_valign4(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.w = vfmv(Vu.w)
RzILOpEffect *hex_il_op_v6_vassign_fp(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.bf = Vuu.qf32
RzILOpEffect *hex_il_op_v6_vconv_bf_qf32(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.f8 = Vu.qf16
RzILOpEffect *hex_il_op_v6_vconv_f8_qf16(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.h = Vu.hf
RzILOpEffect *hex_il_op_v6_vconv_h_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.h = Vu.hf:rnd
RzILOpEffect *hex_il_op_v6_vconv_h_hf_rnd(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.hf = Vu.h
RzILOpEffect *hex_il_op_v6_vconv_hf_h(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.hf = Vu.qf16
RzILOpEffect *hex_il_op_v6_vconv_hf_qf16(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.hf = Vuu.qf32
RzILOpEffect *hex_il_op_v6_vconv_hf_qf32(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdd.qf16 = Vu.f8
RzILOpEffect *hex_il_op_v6_vconv_qf16_f8(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf16 = Vu.hf
RzILOpEffect *hex_il_op_v6_vconv_qf16_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf16 = Vu.qf16
RzILOpEffect *hex_il_op_v6_vconv_qf16_qf16(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf32 = Vu.qf32
RzILOpEffect *hex_il_op_v6_vconv_qf32_qf32(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf32 = Vu.sf
RzILOpEffect *hex_il_op_v6_vconv_qf32_sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.sf = Vu.qf32
RzILOpEffect *hex_il_op_v6_vconv_sf_qf32(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.sf = Vu.w
RzILOpEffect *hex_il_op_v6_vconv_sf_w(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.w = Vu.sf
RzILOpEffect *hex_il_op_v6_vconv_w_sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.b = vcvt2(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vcvt2_b_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdd.hf = vcvt2(Vu.b)
RzILOpEffect *hex_il_op_v6_vcvt2_hf_b(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdd.hf = vcvt2(Vu.ub)
RzILOpEffect *hex_il_op_v6_vcvt2_hf_ub(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.ub = vcvt2(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vcvt2_ub_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.b = vcvt(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vcvt_b_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.bf = vcvt(Vu.sf,Vv.sf)
RzILOpEffect *hex_il_op_v6_vcvt_bf_sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.f8 = vcvt(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vcvt_f8_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.h = vcvt(Vu.hf)
RzILOpEffect *hex_il_op_v6_vcvt_h_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdd.hf = vcvt(Vu.b)
RzILOpEffect *hex_il_op_v6_vcvt_hf_b(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdd.hf = vcvt(Vu.f8)
RzILOpEffect *hex_il_op_v6_vcvt_hf_f8(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.hf = vcvt(Vu.h)
RzILOpEffect *hex_il_op_v6_vcvt_hf_h(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.hf = vcvt(Vu.sf,Vv.sf)
RzILOpEffect *hex_il_op_v6_vcvt_hf_sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdd.hf = vcvt(Vu.ub)
RzILOpEffect *hex_il_op_v6_vcvt_hf_ub(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.hf = vcvt(Vu.uh)
RzILOpEffect *hex_il_op_v6_vcvt_hf_uh(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdd.sf = vcvt(Vu.hf)
RzILOpEffect *hex_il_op_v6_vcvt_sf_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.ub = vcvt(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vcvt_ub_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.uh = vcvt(Vu.hf)
RzILOpEffect *hex_il_op_v6_vcvt_uh_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.sf = vdmpy(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vdmpy_sf_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vx.sf += vdmpy(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vdmpy_sf_hf_acc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Qd = vcmp.eq(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_veqhf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Qx &= vcmp.eq(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_veqhf_and(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Qx |= vcmp.eq(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_veqhf_or(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Qx ^= vcmp.eq(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_veqhf_xor(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Qd = vcmp.eq(Vu.sf,Vv.sf)
RzILOpEffect *hex_il_op_v6_veqsf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Qx &= vcmp.eq(Vu.sf,Vv.sf)
RzILOpEffect *hex_il_op_v6_veqsf_and(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Qx |= vcmp.eq(Vu.sf,Vv.sf)
RzILOpEffect *hex_il_op_v6_veqsf_or(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Qx ^= vcmp.eq(Vu.sf,Vv.sf)
RzILOpEffect *hex_il_op_v6_veqsf_xor(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.f8 = vfmax(Vu.f8,Vv.f8)
RzILOpEffect *hex_il_op_v6_vfmax_f8(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.hf = vfmax(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vfmax_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.sf = vfmax(Vu.sf,Vv.sf)
RzILOpEffect *hex_il_op_v6_vfmax_sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.f8 = vfmin(Vu.f8,Vv.f8)
RzILOpEffect *hex_il_op_v6_vfmin_f8(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.hf = vfmin(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vfmin_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.sf = vfmin(Vu.sf,Vv.sf)
RzILOpEffect *hex_il_op_v6_vfmin_sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.f8 = vfneg(Vu.f8)
RzILOpEffect *hex_il_op_v6_vfneg_f8(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.hf = vfneg(Vu.hf)
RzILOpEffect *hex_il_op_v6_vfneg_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.sf = vfneg(Vu.sf)
RzILOpEffect *hex_il_op_v6_vfneg_sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Qd = vcmp.gt(Vu.bf,Vv.bf)
RzILOpEffect *hex_il_op_v6_vgtbf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Qx &= vcmp.gt(Vu.bf,Vv.bf)
RzILOpEffect *hex_il_op_v6_vgtbf_and(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Qx |= vcmp.gt(Vu.bf,Vv.bf)
RzILOpEffect *hex_il_op_v6_vgtbf_or(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Qx ^= vcmp.gt(Vu.bf,Vv.bf)
RzILOpEffect *hex_il_op_v6_vgtbf_xor(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Qd = vcmp.gt(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vgthf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Qx &= vcmp.gt(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vgthf_and(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Qx |= vcmp.gt(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vgthf_or(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Qx ^= vcmp.gt(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vgthf_xor(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Qd = vcmp.gt(Vu.sf,Vv.sf)
RzILOpEffect *hex_il_op_v6_vgtsf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Qx &= vcmp.gt(Vu.sf,Vv.sf)
RzILOpEffect *hex_il_op_v6_vgtsf_and(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Qx |= vcmp.gt(Vu.sf,Vv.sf)
RzILOpEffect *hex_il_op_v6_vgtsf_or(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Qx ^= vcmp.gt(Vu.sf,Vv.sf)
RzILOpEffect *hex_il_op_v6_vgtsf_xor(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.w = vilog2(Vu.hf)
RzILOpEffect *hex_il_op_v6_vilog2_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.w = vilog2(Vu.qf16)
RzILOpEffect *hex_il_op_v6_vilog2_qf16(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.w = vilog2(Vu.qf32)
RzILOpEffect *hex_il_op_v6_vilog2_qf32(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.w = vilog2(Vu.sf)
RzILOpEffect *hex_il_op_v6_vilog2_sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.bf = vmax(Vu.bf,Vv.bf)
RzILOpEffect *hex_il_op_v6_vmax_bf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.hf = vmax(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vmax_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.sf = vmax(Vu.sf,Vv.sf)
RzILOpEffect *hex_il_op_v6_vmax_sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd = vmerge(Vu.x,Vv.w)
RzILOpEffect *hex_il_op_v6_vmerge_qf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.bf = vmin(Vu.bf,Vv.bf)
RzILOpEffect *hex_il_op_v6_vmin_bf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.hf = vmin(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vmin_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.sf = vmin(Vu.sf,Vv.sf)
RzILOpEffect *hex_il_op_v6_vmin_sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdd.hf = vmpy(Vu.f8,Vv.f8)
RzILOpEffect *hex_il_op_v6_vmpy_hf_f8(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vxx.hf += vmpy(Vu.f8,Vv.f8)
RzILOpEffect *hex_il_op_v6_vmpy_hf_f8_acc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.hf = vmpy(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vmpy_hf_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vx.hf += vmpy(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vmpy_hf_hf_acc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf16 = vmpy(Vu.qf16,Vv.qf16)
RzILOpEffect *hex_il_op_v6_vmpy_qf16(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf16 = vmpy(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vmpy_qf16_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf16 = vmpy(Vu.qf16,Vv.hf)
RzILOpEffect *hex_il_op_v6_vmpy_qf16_mix_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf32 = vmpy(Vu.qf32,Vv.qf32)
RzILOpEffect *hex_il_op_v6_vmpy_qf32(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdd.qf32 = vmpy(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vmpy_qf32_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdd.qf32 = vmpy(Vu.qf16,Vv.hf)
RzILOpEffect *hex_il_op_v6_vmpy_qf32_mix_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdd.qf32 = vmpy(Vu.qf16,Vv.qf16)
RzILOpEffect *hex_il_op_v6_vmpy_qf32_qf16(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf32 = vmpy(Vu.sf,Vv.sf)
RzILOpEffect *hex_il_op_v6_vmpy_qf32_sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf16 = vmpy(Vu.hf,Rt.hf)
RzILOpEffect *hex_il_op_v6_vmpy_rt_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf16 = vmpy(Vu.qf16,Rt.hf)
RzILOpEffect *hex_il_op_v6_vmpy_rt_qf16(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf32 = vmpy(Vu.sf,Rt.sf)
RzILOpEffect *hex_il_op_v6_vmpy_rt_sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdd.sf = vmpy(Vu.bf,Vv.bf)
RzILOpEffect *hex_il_op_v6_vmpy_sf_bf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vxx.sf += vmpy(Vu.bf,Vv.bf)
RzILOpEffect *hex_il_op_v6_vmpy_sf_bf_acc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdd.sf = vmpy(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vmpy_sf_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vxx.sf += vmpy(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vmpy_sf_hf_acc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.sf = vmpy(Vu.sf,Vv.sf)
RzILOpEffect *hex_il_op_v6_vmpy_sf_sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf16 = vneg(Vu.hf)
RzILOpEffect *hex_il_op_v6_vneg_qf16_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf16 = vneg(Vu.qf16)
RzILOpEffect *hex_il_op_v6_vneg_qf16_qf16(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf32 = vneg(Vu.qf32)
RzILOpEffect *hex_il_op_v6_vneg_qf32_qf32(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf32 = vneg(Vu.sf)
RzILOpEffect *hex_il_op_v6_vneg_qf32_sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdd.w = vrmpy(Vu.b,Rtt.ub)
RzILOpEffect *hex_il_op_v6_vrmpybub_rtt(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vxx.w += vrmpy(Vu.b,Rtt.ub)
RzILOpEffect *hex_il_op_v6_vrmpybub_rtt_acc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdd.uw = vrmpy(Vu.ub,Rtt.ub)
RzILOpEffect *hex_il_op_v6_vrmpyub_rtt(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vxx.uw += vrmpy(Vu.ub,Rtt.ub)
RzILOpEffect *hex_il_op_v6_vrmpyub_rtt_acc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdddd.w = vrmpyz(Vu.b,Rt.b)
RzILOpEffect *hex_il_op_v6_vrmpyzbb_rt(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vyyyy.w += vrmpyz(Vu.b,Rt.b)
RzILOpEffect *hex_il_op_v6_vrmpyzbb_rt_acc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdddd.w = vrmpyz(Vu.b,Rx.b++)
RzILOpEffect *hex_il_op_v6_vrmpyzbb_rx(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vyyyy.w += vrmpyz(Vu.b,Rx.b++)
RzILOpEffect *hex_il_op_v6_vrmpyzbb_rx_acc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdddd.w = vrmpyz(Vu.b,Rt.ub)
RzILOpEffect *hex_il_op_v6_vrmpyzbub_rt(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vyyyy.w += vrmpyz(Vu.b,Rt.ub)
RzILOpEffect *hex_il_op_v6_vrmpyzbub_rt_acc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdddd.w = vrmpyz(Vu.b,Rx.ub++)
RzILOpEffect *hex_il_op_v6_vrmpyzbub_rx(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vyyyy.w += vrmpyz(Vu.b,Rx.ub++)
RzILOpEffect *hex_il_op_v6_vrmpyzbub_rx_acc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdddd.w = vr16mpyz(Vu.c,Rt.b)
RzILOpEffect *hex_il_op_v6_vrmpyzcb_rt(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vyyyy.w += vr16mpyz(Vu.c,Rt.b)
RzILOpEffect *hex_il_op_v6_vrmpyzcb_rt_acc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdddd.w = vr16mpyz(Vu.c,Rx.b++)
RzILOpEffect *hex_il_op_v6_vrmpyzcb_rx(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vyyyy.w += vr16mpyz(Vu.c,Rx.b++)
RzILOpEffect *hex_il_op_v6_vrmpyzcb_rx_acc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdddd.w = vr16mpyzs(Vu.c,Rt.b)
RzILOpEffect *hex_il_op_v6_vrmpyzcbs_rt(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vyyyy.w += vr16mpyzs(Vu.c,Rt.b)
RzILOpEffect *hex_il_op_v6_vrmpyzcbs_rt_acc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdddd.w = vr16mpyzs(Vu.c,Rx.b++)
RzILOpEffect *hex_il_op_v6_vrmpyzcbs_rx(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vyyyy.w += vr16mpyzs(Vu.c,Rx.b++)
RzILOpEffect *hex_il_op_v6_vrmpyzcbs_rx_acc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdddd.w = vr8mpyz(Vu.n,Rt.b)
RzILOpEffect *hex_il_op_v6_vrmpyznb_rt(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vyyyy.w += vr8mpyz(Vu.n,Rt.b)
RzILOpEffect *hex_il_op_v6_vrmpyznb_rt_acc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdddd.w = vr8mpyz(Vu.n,Rx.b++)
RzILOpEffect *hex_il_op_v6_vrmpyznb_rx(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vyyyy.w += vr8mpyz(Vu.n,Rx.b++)
RzILOpEffect *hex_il_op_v6_vrmpyznb_rx_acc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf16 = vsub(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vsub_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdd.hf = vsub(Vu.f8,Vv.f8)
RzILOpEffect *hex_il_op_v6_vsub_hf_f8(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.hf = vsub(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vsub_hf_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf16 = vsub(Vu.hf,Vv.qf16)
RzILOpEffect *hex_il_op_v6_vsub_hf_mix(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf16 = vsub(Vu.qf16,Vv.qf16)
RzILOpEffect *hex_il_op_v6_vsub_qf16(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf16 = vsub(Vu.qf16,Vv.hf)
RzILOpEffect *hex_il_op_v6_vsub_qf16_mix(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf32 = vsub(Vu.qf32,Vv.qf32)
RzILOpEffect *hex_il_op_v6_vsub_qf32(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf32 = vsub(Vu.qf32,Vv.sf)
RzILOpEffect *hex_il_op_v6_vsub_qf32_mix(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf32 = vsub(Vu.sf,Vv.sf)
RzILOpEffect *hex_il_op_v6_vsub_sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdd.sf = vsub(Vu.bf,Vv.bf)
RzILOpEffect *hex_il_op_v6_vsub_sf_bf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vdd.sf = vsub(Vu.hf,Vv.hf)
RzILOpEffect *hex_il_op_v6_vsub_sf_hf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.qf32 = vsub(Vu.sf,Vv.qf32)
RzILOpEffect *hex_il_op_v6_vsub_sf_mix(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd.sf = vsub(Vu.sf,Vv.sf)
RzILOpEffect *hex_il_op_v6_vsub_sf_sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// z = vmem(Rt+Ii)
RzILOpEffect *hex_il_op_v6_zld_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// z = vmem(Rx++Ii)
RzILOpEffect *hex_il_op_v6_zld_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// z = vmem(Rx++Mu)
RzILOpEffect *hex_il_op_v6_zld_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) z = vmem(Rt+Ii)
RzILOpEffect *hex_il_op_v6_zld_pred_ai(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) z = vmem(Rx++Ii)
RzILOpEffect *hex_il_op_v6_zld_pred_pi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (Pv) z = vmem(Rx++Mu)
RzILOpEffect *hex_il_op_v6_zld_pred_ppu(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Vd = zextract(Rt)
RzILOpEffect *hex_il_op_v6_zextract(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

#include <rz_il/rz_il_opbuilder_end.h>