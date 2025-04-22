// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file fp.c
 * RzIL implementation of MIPS floating point math/load/store/branch
 **/

static RzILOpEffect *mips_il_abs_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Absolute Value
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_add_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Add
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_bc1f(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Branch on Floating Point False
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_bc1t(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Branch on Floating Point True
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_c_cond_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Compare
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_ceil_l_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Fixed Point Ceiling Convert to Long Fixed Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_ceil_w_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Ceiling Convert to Word Fixed Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_class_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Scalar Floating-Point Class Mask
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_cmp_condn_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Compare Setting Mask | CMP.condn.fmt
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_cfc1(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Move Control Word From Floating Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_ctc1(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Move Control Word to Floating Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_cvt_d_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Convert to Double Floating Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_cvt_l_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Convert to Long Fixed Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_cvt_ps_s(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Convert Pair to Paired Single
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_cvt_s_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Convert to Single Floating Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_cvt_s_pl(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Convert Pair Lower to Single Floating Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_cvt_s_pu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Convert Pair Upper to Single Floating Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_cvt_w_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Convert to Word Fixed Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_div_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Divide
	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);
	// TODO: rounding mode is defined in FCSR register
	return SETG(rd, FDIV(RZ_FLOAT_RMODE_RNE, rs, rt));
}

static RzILOpEffect *mips_il_floor_l_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Floor Convert to Long Fixed Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_floor_w_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Floor Convert to Word Fixed Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_ldc1(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Load Doubleword to Floating Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_ldxc1(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Load Doubleword Indexed to Floating Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_luxc1(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Load Doubleword Indexed Unaligned to Floating Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_lwc1(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Load Word to Floating Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_lwxc1(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Load Word Indexed to Floating Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_madd_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Multiply Add
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_maddf_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Fused Multiply Add
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_max_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Maximum
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_maxa_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Value with Maximum Absolute Value
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_min_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Minimum
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_mina_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Value with Minimum Absolute Value
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_mfc1(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Move Word From Floating Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_mfhc1(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Move Word From High Half of Floating Point Register
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_mov_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Move
	// TODO: handle double
	return SETG(REG(0), MIPS_REG(1));
}

static RzILOpEffect *mips_il_movf(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Move Conditional on Floating Point False
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_movf_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Move Conditional on Floating Point False
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_movn_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Move Conditional on Not Zero
	// TODO: handle double
	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);
	return BRANCH(IS_ZERO(rt), NOP(), SETG(rd, rs));
}

static RzILOpEffect *mips_il_movt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Move Conditional on Floating Point True
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_movt_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Move Conditional on Floating Point True
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_movz_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Move Conditional on Zero
	// TODO: handle double
	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);
	return BRANCH(IS_ZERO(rt), SETG(rd, rs), NOP());
}

static RzILOpEffect *mips_il_msub_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Multiply Subtract
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_msubf_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Fused Multiply Subtract
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_mtc1(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Move Word to Floating Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_mthc1(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Move to High Floating Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_mul_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Multiply
	// TODO: handle double
	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);

	return SETG(rd, MUL(rs, rt));
}

static RzILOpEffect *mips_il_neg_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Negate
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_nmadd_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Negative Multiply Add
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_nmsub_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Negative Multiply Subtract
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_pll_ps(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Pair Lower Lower
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_plu_ps(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Pair Lower Upper
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_pul_ps(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Pair Upper Lower
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_puu_ps(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Pair Upper Upper
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_recip_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Reciprocal Approximation
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_rint_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Scalar floating-point round to integer
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_round_l_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Round to Long Fixed Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_round_w_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Round to Word Fixed Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_rsqrt_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Reciprocal Square Root Approximation
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_sdc1(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Store Doubleword from Floating Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_sdxc1(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Store Doubleword Indexed from Floating Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_sel_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Select
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_seleqz_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Select if condition Equal to Zero, Else 0.0
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_selneqz_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Select if condition is Not Equal to Zero, Else 0.0
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_sqrt_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Square Root
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_sub_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Subtract
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_suxc1(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Store Doubleword Indexed Unaligned from Floating Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_swc1(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Store Word from Floating Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_swxc1(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Store Word Indexed from Floating Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_trunc_l_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Truncate to Long Fixed Point
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_trunc_w_fmt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Floating Point Truncate to Word Fixed Point
	NOT_IMPLEMENTED;
}
