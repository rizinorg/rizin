// SPDX-FileCopyrightText: 2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "c166/c166_il.h"
#include "c166_common.h"

#include <rz_il/rz_il_opbuilder_begin.h>

/**
 * All registers available as global IL variables
 */
static const char *c166_global_registers[] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9",
	"r10", "r11", "r12", "r13", "r14", "r15",
	"IP",
	"DPP0", "DPP1", "DPP2", "DPP3",
	"SP",
	"CSP", "SGTDIS",
	"e", "z", "v", "c", "n", "usr0", "usr1",
	"BUSCON0", "SYSCON",
	"PSW", "P8",
	NULL
};

char *get_dpp(const ut16 addr) {
	switch (addr) {
	case REG_DPP0:
		return "DPP0";
	case REG_DPP1:
		return "DPP1";
	case REG_DPP2:
		return "DPP2";
	case REG_DPP3:
		return "DPP3";
	default:
		return NULL;
	}
}

RzILOpBitVector *DPP_val(const ut16 DPP_addr) {
	const char *DPP_src = get_dpp(DPP_addr);
	return SHIFTL0(UNSIGNED(16, VARG(DPP_src)), U16(14));
}

RzILOpBitVector *read_DPP_mem(const ut16 DPP_addr, const ut16 mem) {
	return LOGOR(DPP_val(DPP_addr), U16(mem & 0x3FFF));
}

static RzILOpBool *check_condition(const ut8 condition) {
	RzILOpBool *cond = NULL;
	switch (condition) {
	case C166_CC_UC:
		cond = IL_TRUE;
		break;
	case C166_CC_EQ:
		cond = VARG("z");
		break;
	case C166_CC_NE:
		cond = INV(VARG("z"));
		break;
	case C166_CC_N:
		cond = VARG("n");
		break;
	case C166_CC_NN:
		cond = INV(VARG("n"));
		break;
	case C166_CC_C:
		cond = VARG("c");
		break;
	case C166_CC_NC:
		cond = INV(VARG("c"));
		break;
	case C166_CC_V:
		cond = VARG("v");
		break;
	case C166_CC_NV:
		cond = INV(VARG("v"));
		break;
	case C166_CC_NET:
		///< cc_NET (Z∨E) = 0 Not equal AND not end of table
		cond = INV(AND(VARG("z"), VARG("e")));
		break;
	case C166_CC_SGT:
		///< cc_SGT (Z∨(N⊕V)) = 0 Signed greater than
		cond = INV(AND(VARG("z"), OR(VARG("n"), VARG("v"))));
		break;
	case C166_CC_SLE:
		///< cc_SLE (Z∨(N⊕V)) = 1 Signed less than or equal
		cond = AND(VARG("z"), OR(VARG("n"), VARG("v")));
		break;
	case C166_CC_SLT:
		///< cc_SLT (N⊕V) = 1 Signed less than
		cond = OR(VARG("n"), VARG("v"));
		break;
	case C166_CC_SGE:
		///< cc_SGE (N⊕V) = 0 Signed greater than or equal
		cond = INV(OR(VARG("n"), VARG("v")));
		break;
	case C166_CC_UGT:
		///< cc_UGT (Z∨C) = 0 Unsigned greater than
		cond = INV(AND(VARG("z"), VARG("c")));
		break;
	case C166_CC_ULE:
		///< cc_ULE (Z∨C) = 1 Unsigned less than or equal
		cond = AND(VARG("z"), VARG("c"));
		break;
	case C166_CC_NUSR0:
		///< USR-bit 0 is cleared (*)
		cond = INV(VARG("usr0"));
		break;
	case C166_CC_NUSR1:
		///< USR-bit 1 is cleared (*)
		cond = INV(VARG("usr1"));
		break;
	case C166_CC_USR0:
		///< USR-bit 0 is set 1
		cond = VARG("usr0");
		break;
	case C166_CC_USR1:
		///< USR-bit 1 is set 1
		cond = VARG("usr1");
		break;
	default:
		rz_warn_if_reached();
	}
	return cond;
}

RzILOpEffect *bfld_flags_seq(RzILOpBitVector *result) {
	return SEQ5(E_FALSE, SET_DZ(result), V_FALSE, C_FALSE, SET_DN(result));
}

const char *c166_instr_name(ut8 instr);
static RzILOpEffect *c166_il_unk(void) {
#if RZ_DEBUG
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const char *op_name = c166_instr_name(op->id);
	RZ_LOG_DEBUG("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_unk %s\n", op->id, pc, IP, op_name);
#endif
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_lifted_nop(void) {
#if RZ_DEBUG
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const char *op_name = c166_instr_name(op->id);
	RZ_LOG_DEBUG("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_lifted_nop %s\n", op->id, pc, IP, op_name);
#endif
	return rz_il_op_new_nop();
}

#define CHECK_STATE \
	const C166State *state = (C166State *)analysis->plugin_data; \
	if (!state) { \
		RZ_LOG_FATAL("C166State was NULL."); \
		return rz_il_op_new_nop(); \
	}

static RzILOpEffect *c166_il_add_rwn_rwm(const ut8 *buf) {
	const ut8 m = L_NIB(buf[1]);
	const ut8 n = H_NIB(buf[1]);
	const char *dst = c166_global_registers[n];
	const char *src = c166_global_registers[m];
	return SEQ8(
		SETL("val", VARG(src)),
		SETL("res", ADD(VARG(dst), VARL("val"))),
		SETG(dst, VARL("res")),
		SET_E(VARL("val")),
		SET_Z(VARL("res")),
		V_FALSE,
		SET_C(VARL("res")),
		SET_N(VARL("res")));
}

static RzILOpEffect *c166_il_clr_set_bitoff(const RzAnalysis *analysis, const ut8 *buf, const bool set) {
	const ut8 bit = H_NIB(buf[0]);
	const ut8 bitoff = buf[1];
	ut64 addr = 0;

	if (IS_GPR(bitoff)) {
		const char *dst = c166_rw[L_NIB(bitoff)];
		RzILOpBitVector *res = set ? SET_BIT16(VARL("reg"), bit) : CLR_BIT16(VARL("reg"), bit);
		return SEQ4(
			SETL("reg", VARG(dst)),
			SETL("bit", NON_ZERO(GET_BIT16(VARL("reg"), bit))),
			BRANCH(INV(VARL("bit")),
				SETG(dst, res),
				NOP()),
			SEQ5(
				E_FALSE,
				SETG("z", INV(VARL("bit"))),
				V_FALSE,
				C_FALSE,
				SETG("n", VARL("bit"))));
	}

	if (IS_RAM(bitoff)) {
		addr = RAM_B_ADDR(bitoff);
	}

	if (IS_bSFR(bitoff)) {
		CHECK_STATE;
		addr = state->ext.esfr ? ESFR_B_ADDR(bitoff) : SFR_B_ADDR(bitoff);
	}

	RzILOpBitVector *res = set ? SET_BIT16(VARL("src"), bit) : CLR_BIT16(VARL("src"), bit);
	return SEQ4(
		SETL("src", LOADW(16, U32(addr))),
		SETL("bit", NON_ZERO(GET_BIT16(VARL("src"), bit))),
		BRANCH(INV(VARL("bit")),
			STOREW(U32(addr), res),
			NOP()),
		SEQ5(
			E_FALSE,
			SETG("z", INV(VARL("bit"))),
			V_FALSE,
			C_FALSE,
			SETG("n", VARL("bit"))));
}

static RzILOpEffect *c166_il_xorb_rbn_rbm(const ut8 *buf) {
	const ut8 n = H_NIB(buf[1]);
	const ut8 m = L_NIB(buf[1]);
	const char *src = c166_get_word_reg_name(m);
	const char *dst = c166_get_word_reg_name(n);
	return SEQN(5,
		SETL("op1", READ_RL(VARG(src))),
		SETL("op2", READ_RL(VARG(dst))),
		SETL("op2", LOGXOR(VARL("op1"), VARL("op2"))),
		WRITE_RL(dst, UNSIGNED(16, VARL("op2"))),
		SEQ5(
			SET_E(VARL("op2")),
			SET_Z(VARL("op2")),
			V_FALSE,
			C_FALSE,
			SET_N(VARL("op2"))));
}
static RzILOpEffect *c166_il_xor_reg_mem(void) {
#if RZ_DEBUG
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_xor_reg_mem\n", op->id, pc, IP);
#endif
	return rz_il_op_new_nop();
}
static RzILOpEffect *c166_il_shl_rwn_data4(void) {
#if RZ_DEBUG
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_shl_rwn_data4\n", op->id, pc, IP);
#endif
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_div_rwn(void) {
#if RZ_DEBUG
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_div_rwn\n", op->id, pc, IP);
#endif
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_cmpb_rbn_rbm(const RzAnalysis *analysis, const ut8 *buf, const RzAnalysisOp *op) {
	const ut8 reg = buf[1];
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_cmpb_rbn_rbm %s, %s\n",
		op->id, op->addr, IP, c166_rb[H_NIB(reg)], c166_rb[L_NIB(reg)]);
	const char *op1 = c166_get_word_reg_name(H_NIB(reg));
	const char *op2 = c166_get_word_reg_name(L_NIB(reg));
	return SEQN(8,
		SETL("op1", READ_RL8(VARG(op1))),
		SETL("op2", READ_RH8(VARG(op2))),
		SETL("res",
			ITE(
				ULT(VARL("op1"), VARL("op2")),
				SUB(UNSIGNED(16, VARL("op1")), UNSIGNED(16, VARL("op2"))),
				UNSIGNED(16, SUB(VARL("op1"), VARL("op2"))))),
		SET_E8(VARL("op2")),
		SETG("z", EQ(VARL("op1"), VARL("op2"))),
		SETG("c", ULT(VARL("op1"), VARL("op2"))),
		SETG("v", EQ(VARL("res"), U16(0xFF))),
		SET_N(UNSIGNED(8, VARL("res"))));
}

static RzILOpEffect *c166_il_cmpb_reg_data8(const ut8 *buf) {
	const ut8 reg = buf[1];
	const ut16 data = rz_read_at_le16(buf, 2);
	const char *dst = c166_get_word_reg_name(L_NIB(reg));

	return SEQN(8,
		SETL("op1", READ_RL8(VARG(dst))),
		SETL("op2", U8(data & 0xFF)),
		SETL("res",
			ITE(
				ULT(VARL("op1"), VARL("op2")),
				SUB(UNSIGNED(16, VARL("op1")), UNSIGNED(16, VARL("op2"))),
				UNSIGNED(16, SUB(VARL("op1"), VARL("op2"))))),
		SET_E8(VARL("op2")),
		SETG("z", EQ(VARL("op1"), VARL("op2"))),
		SETG("c", ULT(VARL("op1"), VARL("op2"))),
		SETG("v", EQ(VARL("res"), U16(0xFF))),
		SET_N(UNSIGNED(8, VARL("res"))));
}

static RzILOpEffect *c166_il_cmp_rwn_x(void) {
#if RZ_DEBUG
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_cmp_rwn_x nop\n", op->id, pc, IP);
#endif
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_cmp_reg_mem(const RzAnalysis *analysis, const ut8 *buf, const RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const ut8 reg = buf[1];
	const ut16 mem = rz_read_at_le16(buf, 2);

	const st32 i = (mem >> 14) & 0b11;
	const ut16 DPP_addr = SFR_ADDR(i);

	if (IS_GPR(reg)) {
		// Short ‘reg’ addresses from F0 to FF always specify GPRs.
		const char *dst = c166_rw[L_NIB(reg)];
		printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_cmp_reg_mem %s, 0x%04x:0x%04x\n",
			op->id, op->addr, IP, dst, DPP_addr, mem & 0x3FFF);
		return SEQN(5,
			SETL("op1_val", VARG(dst)),
			SETL("dpp_val", read_DPP_mem(DPP_addr, mem)),
			SETL("op2_val", LOADW(16, UNSIGNED(32, VARL("dpp_val")))),
			SETL("res",
				ITE(
					ULT(VARL("op1_val"), VARL("op2_val")),
					SUB(UNSIGNED(16, VARL("op1_val")), UNSIGNED(16, VARL("op2_val"))),
					UNSIGNED(16, SUB(VARL("op1_val"), VARL("op2_val"))))),
			SEQ5(
				SET_E(VARL("op2_val")),
				SETG("z", EQ(VARL("op1_val"), VARL("op2_val"))),
				SETG("v", EQ(VARL("res"), U16(0xFFFF))),
				SETG("c", ULT(VARL("op1_val"), VARL("op2_val"))),
				SET_N(VARL("res"))));
	}
	CHECK_STATE;
	const ut16 base_addr = state->ext.esfr ? BASE_ESFR_ADDR : BASE_SFR_ADDR;
	const ut16 addr = base_addr + (2 * reg);

	printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_cmp_reg_mem %04x, 0x%04x:0x%04x\n",
		op->id, op->addr, IP, addr, DPP_addr, mem & 0x3FFF);
	return SEQN(4,
		SETL("op1_val", LOADW(16, U32(addr))),
		SETL("dpp_val", read_DPP_mem(DPP_addr, mem)),
		SETL("op2_val", LOADW(16, UNSIGNED(32, VARL("dpp_val")))),
		SETL("res",
			ITE(
				ULT(VARL("dst"), VARL("op2_val")),
				SUB(UNSIGNED(16, VARL("op1_val")), UNSIGNED(16, VARL("op2_val"))),
				UNSIGNED(16, SUB(VARL("op1_val"), VARL("op2_val"))))),
		SEQ5(
			SET_E(VARL("op2_val")),
			SETG("z", EQ(VARL("op1_val"), VARL("op2_val"))),
			SETG("v", EQ(VARL("res"), U16(0xFFFF))),
			SETG("c", ULT(VARL("op1_val"), VARL("op2_val"))),
			SET_N(VARL("res"))));
	// return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_cmpb_rbn_x(const RzAnalysis *analysis, const ut8 *buf, const RzAnalysisOp *op) {
	const ut8 reg = buf[1];
	const ut8 op1 = L_NIB(reg);
	const char *r = c166_rb[H_NIB(reg)];

	if ((op1 & 0b1100) == 0b1100) {
		///< [Rb+]
		ut64 IP = rz_reg_getv(analysis->reg, "IP");
		printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_cmpb_rbn_x %s, [%s+]\n",
			op->id, op->addr, IP, r, c166_rw[op1 & 0b11]);
		return rz_il_op_new_nop();
	} else if ((op1 & 0b1000) == 0b1000) {
		///< [Rb]
		ut64 IP = rz_reg_getv(analysis->reg, "IP");
		printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_cmpb_rbn_x %s, [%s]\n",
			op->id, op->addr, IP, r, c166_rw[op1 & 0b11]);
		return rz_il_op_new_nop();
	} else {
		///< #data3
		const char *dst = c166_get_word_reg_name(H_NIB(reg));
		return SEQN(8,
			SETL("op1", READ_RL8(VARG(dst))),
			SETL("op2", U8(op1 & 0x7)),
			SETL("res",
				ITE(
					ULT(VARL("op1"), VARL("op2")),
					SUB(UNSIGNED(16, VARL("op1")), UNSIGNED(16, VARL("op2"))),
					UNSIGNED(16, SUB(VARL("op1"), VARL("op2"))))),
			SET_E8(VARL("op2")),
			SETG("z", EQ(VARL("op1"), VARL("op2"))),
			SETG("c", ULT(VARL("op1"), VARL("op2"))),
			SETG("v", EQ(VARL("res"), U16(0xFF))),
			SET_N(UNSIGNED(8, VARL("res"))));
	}
}

static RzILOpEffect *c166_il_mov_rwn_orwm(const RzAnalysis *analysis, const ut8 *buf, const RzAnalysisOp *op) {
	CHECK_STATE;
	const ut8 reg = buf[1];
	const char *src = c166_global_registers[L_NIB(reg)];
	const char *dst = c166_global_registers[H_NIB(reg)];

	if (state->ext.esfr && state->ext.mode == C166_EXT_MODE_REG) {
		const char *ext_reg_name = c166_global_registers[state->ext.value];
		return SEQN(7,
			SETL("seg", UNSIGNED(32, VARG(ext_reg_name))),
			SETL("seg", SHIFTL0(VARL("seg"), U16(16))),
			SETL("src_op", VARG(src)),
			SETL("addr", LOGOR(VARL("seg"), UNSIGNED(32, VARL("src_op")))),
			SETL("load", LOADW(16, VARL("addr"))),
			SETG(dst, UNSIGNED(16, VARL("load"))),
			SEQ3(
				SET_E(VARL("load")),
				SET_Z(VARL("load")),
				SET_N(VARL("load"))));
	}
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_mov_rwn_orwm unk\n", op->id, op->addr, IP);
	return rz_il_op_new_nop();
}

/**
 * (count) ← 0
 * DO WHILE ((count) <8)
 *	IF op2[(count)] = 1
 *		(op1[(count)]) ← op3[(count)]
 *	ENDIF
 * (count) ← (count) + 1
 * END WHILE
 *
 */
static RzILOpEffect *c166_il_bfldl_bitoff_x(RzAnalysis *analysis, const ut8 *buf) {
	const ut8 bitoff = buf[1];
	const ut8 mask8 = buf[2]; // #mask8  ##
	const ut8 data8 = buf[3]; // #data8  @@
	if (IS_RAM(bitoff)) {
		const ut16 addr = RAM_B_ADDR(bitoff);
		RzILOpBitVector *load = LOAD(U16(addr));
		RzILOpEffect *bfld = STORE(U16(addr), load);
		return SEQ2(bfld_flags_seq(load), bfld);
	}
	if (IS_bSFR(bitoff)) {
		CHECK_STATE;
		const ut16 addr = state->ext.esfr ? ESFR_B_ADDR(bitoff) : SFR_B_ADDR(bitoff);
		const RzPlatformTarget *arch_target = rz_analysis_get_arch_target(analysis);
		const char *resolved = rz_platform_profile_resolve_mmio(arch_target->profile, addr);
		if (!resolved) {
			return rz_il_op_new_nop();
		}

		RzILOpBitVector *val = UNSIGNED(16, LOGAND(U8(data8), U8(mask8)));
		RzILOpPure *src = VARG(resolved);
		RzILOpBitVector *result = LOGOR(src, val);
		RzILOpEffect *bfld = SETG(resolved, result);
		return SEQ2(bfld_flags_seq(result), bfld);
	}

	return bfld_flags_seq(U16(buf[3]));
}

static RzILOpEffect *c166_il_bfldh_bitoff_x(RzAnalysis *analysis, const ut8 *buf) {
	const ut8 bitoff = buf[1];
	const ut8 mask8 = buf[3]; // #mask8  ##
	const ut8 data8 = buf[2]; // #data8  @@
	if (IS_GPR(bitoff)) {
		const RzILOpPure *dst = VARG(c166_rw[L_NIB(bitoff)]);
		(void)dst;
	}
	if (IS_bSFR(bitoff)) {
		CHECK_STATE;
		const ut16 addr = state->ext.esfr ? ESFR_B_ADDR(bitoff) : SFR_B_ADDR(bitoff);
		const RzPlatformTarget *arch_target = rz_analysis_get_arch_target(analysis);
		const char *resolved = rz_platform_profile_resolve_mmio(arch_target->profile, addr);
		if (!resolved) {
			return rz_il_op_new_nop();
		}
		return SEQ6(
			SETL("mask", U16(~(mask8 << 8))),
			SETL("tval", LOGAND(VARG(resolved), VARL("mask"))),
			SETL("tval2", LOGAND(U16(data8 << 8), VARL("mask"))),
			SETL("result", LOGOR(VARL("tval"), VARL("tval2"))),
			SETG(resolved, VARL("result")),
			SEQ5(
				E_FALSE,
				SET_Z(VARL("result")),
				V_FALSE,
				C_FALSE,
				SET_N(VARL("result"))));
	}
	return SEQ5(
		E_FALSE,
		SET_Z(U16(buf[3])),
		V_FALSE,
		C_FALSE,
		SET_N(U16(buf[3])));
}

static RzILOpEffect *c166_il_movb_rbn_oRwm(const RzAnalysis *analysis, const ut8 *buf) {
	CHECK_STATE;
	const ut8 n = H_NIB(buf[1]);
	const ut8 m = L_NIB(buf[1]);
	if (state->ext.esfr && state->ext.mode == C166_EXT_MODE_REG) {
		const char *ext_reg_name = c166_global_registers[state->ext.value];
		const char *src = c166_rw[m];
		const char *dst = c166_get_word_reg_name(n);
		const ut8 reg_offset = c166_get_byte_offset(n);
		return SEQN(8,
			SETL("seg", UNSIGNED(32, VARG(ext_reg_name))),
			SETL("seg", SHIFTL0(VARL("seg"), U16(16))),
			SETL("src_op", VARG(src)),
			SETL("addr", LOGOR(VARL("seg"), UNSIGNED(32, VARL("src_op")))),
			SETL("load", LOADW(16, VARL("addr"))),
			SETL("reg_offset", U8(reg_offset)),
			WRITE_RL(dst, UNSIGNED(16, VARL("load"))),
			SEQ3(
				SET_E(VARL("load")),
				SET_Z(VARL("load")),
				SET_N(VARL("src_op"))));
	}
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_jnb_bitaddr_rel(const RzAnalysis *analysis, const ut8 *buf, const RzAnalysisOp *op) {
	const ut8 qq = buf[1];
	const ut8 rr = buf[2];
	const ut8 op3 = buf[3];
	const ut8 q = H_NIB(op3);
	const char *reg = NULL;
	const ut32 addr = (ut32)op->addr + C166_BYTESIZE_4 + (2 * (st8)rr);
	RzILOpBitVector *_iar = NULL;
	RzILOpBitVector *mask = U16(1 << q);

	if (IS_GPR(qq)) {
		reg = c166_rw[L_NIB(qq)];
		_iar = LOGAND(VARG(reg), mask);
	}
	if (IS_bSFR(qq)) {
		CHECK_STATE;
		const ut16 bitaddr = state->ext.esfr ? ESFR_B_ADDR(qq) : SFR_B_ADDR(qq);
		_iar = LOGAND(LOADW(16, U32(bitaddr)), mask);
	}
	_iar = SHIFTR0(_iar, U16(q));
	return BRANCH(IS_ZERO(_iar), JMP(U32(addr)), NOP());
}

static RzILOpEffect *c166_il_and_reg_data16(const RzAnalysis *analysis, const ut8 *buf) {
	const ut8 reg = buf[1];
	const ut16 data = rz_read_at_le16(buf, 2);
	const char *op1 = c166_rw[L_NIB(reg)];

	if (IS_GPR(reg)) {
		// Short ‘reg’ addresses from F0 to FF always specify GPRs.
		return SEQ7(
			SETL("res", LOGAND(VARG(op1), U16(data))),
			SET_E(U16(data)),
			SET_Z(VARL("res")),
			V_FALSE,
			C_FALSE,
			SET_N(VARL("res")),
			SETG(op1, VARL("res")));
	}
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_jb_bitaddr_rel(const RzAnalysis *analysis, const ut8 *buf, const RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const ut8 qq = buf[1];
	const ut8 rr = buf[2];
	const ut8 op3 = buf[3];
	const ut8 q = H_NIB(op3);
	const char *reg = NULL;
	const ut32 addr = op->addr + C166_BYTESIZE_4 + (2 * ((st8)rr));
	if (IS_GPR(qq)) {
		reg = c166_rw[L_NIB(qq)];
	}
	if (IS_RAM(qq)) {
		printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_jb_bitaddr_rel 0x%04x.%i, 0x%06x\n",
			op->id, op->addr, IP, RAM_B_ADDR(qq), q, addr);
	}
	if (IS_bSFR(qq)) {
		CHECK_STATE;
		const ut16 bitaddr = state->ext.esfr ? ESFR_B_ADDR(qq) : SFR_B_ADDR(qq);
		printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_jb_bitaddr_rel 0x%04x.%i, 0x%06x  new_IP: [0x%06x]\n",
			op->id, op->addr, IP, bitaddr, q, addr, addr);
	}
	RzILOpBitVector *mask = U16(1 << q);

	RzILOpBitVector *_iar = LOGAND(VARG(reg), mask);
	_iar = SHIFTR0(_iar, U16(q));

	RzILOpBool *cond = NON_ZERO(_iar);
	return BRANCH(cond, JMP(U32(addr)), NOP());
}

static RzILOpEffect *c166_il_or_reg_data16(const RzAnalysis *analysis, const ut8 *buf) {
	const ut8 reg = buf[1];
	const ut16 data = rz_read_at_le16(buf, 2);
	const char *op1 = NULL;
	CHECK_STATE;
	if (IS_GPR(reg)) {
		// Short ‘reg’ addresses from F0 to FF always specify GPRs.
		op1 = c166_rw[L_NIB(reg)];
		RzILOpBitVector *val = LOGOR(VARG(op1), U16(data));
		return SEQ6(
			SET_E(U16(data)),
			SET_DZ(val),
			V_FALSE,
			C_FALSE,
			SET_DN(val),
			SETG(op1, val));
	}
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_or_rwn_x(void) {
#if RZ_DEBUG
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_or_rwn_x\n", op->id, pc, IP);
#endif
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_orb_rbn_x(void) {
#if RZ_DEBUG
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_orb_rbn_x nop\n", op->id, pc, IP);
#endif
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_bmovn_bitaddr_bitaddr(void) {
#if RZ_DEBUG
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_bmovn_bitaddr_bitaddr nop\n", op->id, pc, IP);
#endif
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_cmp_rwn_rwm(void) {
#if RZ_DEBUG
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	RZ_LOG_DEBUG("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_cmp_rwn_rwm nop\n", op->id, pc, IP);
#endif
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_addc_rwn_x(const RzAnalysis *analysis, const ut8 *buf, const RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const ut8 reg = L_NIB(buf[1]);
	const char *src = c166_global_registers[H_NIB(buf[1])];
	RzILOpBitVector *val = NULL;
	RzILOpEffect *add = NULL;
	if ((reg & 0b1100) == 0b1100) {
		printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_addc_rwn_x r%i, [r%i+]\n",
			op->id, op->addr, IP, H_NIB(reg), reg & 0b1);
	} else if ((reg & 0b1000) == 0b1000) {
		printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_addc_rwn_x r%i, [r%i]\n",
			op->id, op->addr, IP, H_NIB(reg), reg & 0b11);
	} else {
		val = ADD(VARG(src), U16(L_NIB(reg)));
		add = SETG(src, val);
	}
	RzILOpEffect *e = SETG("e", ITE(EQ(VARG(src), S16(0x8000)), IL_TRUE, IL_FALSE));
	RzILOpEffect *z = SETG("z", ITE(IS_ZERO(DUP(val)), IL_TRUE, IL_FALSE));
	RzILOpEffect *v = SETG("v", IL_FALSE);
	RzILOpEffect *c = SETG("c", IL_FALSE);
	RzILOpEffect *n = SETG("n", MSB(DUP(val)));

	RzILOpEffect *add_flags_seq = SEQ5(e, z, v, c, n);
	return SEQ2(add, add_flags_seq);
}

static RzILOpEffect *c166_il_sub_rwn_x(const ut8 *buf) {
	const ut8 reg = L_NIB(buf[1]);
	const char *src = c166_global_registers[H_NIB(buf[1])];

	if ((reg & 0b1100) == 0b1100) { ///< n:11ii - SUB Rwn, [Rwi+]
		const char *op2 = c166_global_registers[reg & 0b11];
		return SEQN(7,
			SETL("op1", VARG(src)),
			SETL("addr", UNSIGNED(32, VARG(op2))),
			SETL("op2", LOADW(16, VARL("addr"))),
			SETL("res", SUB(VARL("op1"), VARL("op2"))),
			SETG(src, VARL("res")),
			SETG(op2, ADD(VARL("op2"), U16(2))),
			SEQ5(
				SET_E(VARL("op2")),
				SET_Z(VARL("res")),
				SETG("c", UGE(VARL("op1"), VARL("op2"))),
				V_FALSE,
				SET_N(VARL("res"))));
	} else if ((reg & 0b1000) == 0b1000) { ///< n:10ii - SUB Rwn, [Rwi]
		const char *op2 = c166_global_registers[reg & 0b11];
		return SEQN(6,
			SETL("op1", VARG(src)),
			SETL("addr", UNSIGNED(32, VARG(op2))),
			SETL("op2", LOADW(16, VARL("addr"))),
			SETL("res", SUB(VARL("op1"), VARL("op2"))),
			SETG(src, VARL("res")),
			SEQ5(
				SET_E(VARL("op2")),
				SET_Z(VARL("res")),
				SETG("c", UGE(VARL("op1"), VARL("op2"))),
				V_FALSE,
				SET_N(VARL("res"))));
	} else {
		const ut8 data = L_NIB(reg) & 0x7; ///< n:0### - SUB Rwn, #data3
		RzILOpEffect *sub = SEQ3(
			SETL("val", VARG(src)),
			SETL("val", SUB(VARL("val"), U16(data))),
			SETG(src, VARL("val")));

		RzILOpEffect *sub_flags_seq = SEQ5(
			SET_E(U16(data)),
			SET_Z(VARL("val")),
			V_FALSE,
			SET_C(VARL("val")),
			SET_N(VARL("val")));
		return SEQ2(sub, sub_flags_seq);
	}
}

static RzILOpEffect *c166_il_movb_orwm_rbn(const RzAnalysis *analysis, const ut8 *buf) {
	CHECK_STATE;
	const ut8 n = H_NIB(buf[1]);
	const ut8 m = L_NIB(buf[1]);
	const char *src = c166_get_word_reg_name(n);
	const ut8 reg_offset = c166_get_byte_offset(n);
	if (state->ext.esfr && state->ext.mode == C166_EXT_MODE_REG) {
		const char *dst = c166_rw[m];
		return SEQN(7,
			SETL("addr", UNSIGNED(32, VARG(dst))),
			SETL("val", VARG(src)),
			SETL("reg_offset", U8(reg_offset)),
			SETL("val",
				ITE(NON_ZERO(VARL("reg_offset")),
					SHIFTL0(VARL("val"), VARL("reg_offset")),
					VARL("val"))),
			STORE(VARL("addr"), UNSIGNED(8, VARL("val"))),
			SETL("src_op", U8(n)),
			SEQ3(
				SET_E8(UNSIGNED(8, VARL("val"))),
				SET_Z(VARL("val")),
				SET_N(VARL("src_op"))));
	}
	const char *dst = c166_global_registers[m];
	return SEQN(7,
		SETL("addr", UNSIGNED(32, VARG(dst))),
		SETL("val", VARG(src)),
		SETL("reg_offset", U8(reg_offset)),
		SETL("val",
			ITE(NON_ZERO(VARL("reg_offset")),
				LOGAND(VARL("val"), U16(0xFF)),
				VARL("val"))),
		STORE(VARL("addr"), UNSIGNED(8, VARL("val"))),
		SETL("src_op", U8(n)),
		SEQ3(
			SET_E8(UNSIGNED(8, VARL("val"))),
			SET_Z(VARL("val")),
			SET_N(VARL("src_op"))));
}

static RzILOpEffect *c166_il_movbz_rwn_rbm(const ut8 *buf) {
	const ut8 m = H_NIB(buf[1]);
	const ut8 n = L_NIB(buf[1]);

	const char *dst = c166_global_registers[n];
	const char *src = c166_get_word_reg_name(m);

	return SEQN(3,
		SETL("val", READ_RL(VARG(src))),
		SETG(dst, VARL("val")),
		SEQ3(E_FALSE, SET_Z(VARL("val")), N_FALSE));
}

static RzILOpEffect *c166_il_mov_orwm_rwn(void) {
#if RZ_DEBUG
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_mov_orwm_rwn\n", op->id, pc, IP);
#endif
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_cpl_rwn(const ut8 *buf) {
	const ut8 reg = buf[1];
	const ut8 n = H_NIB(reg);
	const char *dst = c166_global_registers[n];
	return SEQN(4,
		SETL("val", VARG(dst)),
		SETL("res", LOGNOT(VARL("val"))),
		SETG(dst, VARL("res")),
		SEQ5(
			SET_E(VARL("val")),
			SET_Z(VARL("res")),
			V_FALSE,
			C_FALSE,
			SET_N(VARL("res"))));
}

static RzILOpEffect *c166_il_shr_rwn_data4(void) {
#if RZ_DEBUG
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_shr_rwn_data4\n", op->id, pc, IP);
#endif
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_and_rwn_x(void) {
#if RZ_DEBUG
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_and_rwn_x nop\n", op->id, pc, IP);
#endif
	return rz_il_op_new_nop();
}
static RzILOpEffect *c166_il_divl_rwn(void) {
#if RZ_DEBUG
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_divl_rwn\n", op->id, pc, IP);
#endif
	return rz_il_op_new_nop();
}
static RzILOpEffect *c166_il_shl_rwn_rwm(void) {
#if RZ_DEBUG
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_shl_rwn_rwm\n", op->id, pc, IP);
#endif
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_add_rwn_x(const RzAnalysis *analysis, const ut8 *buf, const RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	// 08 n:11ii
	const ut8 reg = L_NIB(buf[1]);
	const ut8 n = H_NIB(buf[1]);
	const char *dst = c166_global_registers[n];
	RzILOpBitVector *val = NULL;
	RzILOpEffect *add = NULL;
	RzILOpEffect *op1 = SETL("op1", VARG(dst));
	RzILOpEffect *e = NULL;
	if ((reg & 0b1100) == 0b1100) {
		printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_add_rwn_x r%i, [r%i+]\n",
			op->id, op->addr, IP, H_NIB(reg), reg & 0b1);
		e = SET_DE(VARL("op1"));
	} else if ((reg & 0b1000) == 0b1000) {
		printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_add_rwn_x r%i, [r%i]\n",
			op->id, op->addr, IP, H_NIB(reg), reg & 0b11);
		e = SET_DE(VARL("op1"));
	} else {
		val = ADD(VARL("op1"), U16(reg & 0x7));
		add = SETG(dst, val);
		e = SET_E(U16(reg & 0x7));
	}

	RzILOpEffect *add_flags_seq = SEQ5(e, SET_DZ(val), V_FALSE, C_FALSE, SET_DN(val));
	return SEQ3(op1, add, add_flags_seq);
}
static RzILOpEffect *c166_il_addb_rbn_x(const ut8 *buf) {
	const ut8 reg = L_NIB(buf[1]);
	const ut8 n = H_NIB(buf[1]);
	const char *dst = c166_get_word_reg_name(n);
	RzILOpBitVector *val = NULL;
	RzILOpEffect *add = NULL;
	RzILOpEffect *op1 = SETL("op1", VARG(dst));
	RzILOpEffect *e = NULL;
	if ((reg & 0b1100) == 0b1100) {
		e = SET_DE(VARL("op1"));
	} else if ((reg & 0b1000) == 0b1000) {
		e = SET_DE(VARL("op1"));
	} else {
		val = ADD(READ_RL(VARL("op1")), U16(reg & 0x7));
		add = WRITE_RL(dst, val);
		e = SET_E(U16(reg & 0x7));
	}

	RzILOpEffect *add_flags_seq = SEQ5(e, SET_DZ(val), V_FALSE, C_FALSE, SET_DN(val));
	return SEQ3(op1, add, add_flags_seq);
}

static RzILOpEffect *c166_il_add_reg_data16(const RzAnalysis *analysis, const ut8 *buf, const RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const ut8 reg = buf[1];
	const ut16 data = rz_read_at_le16(buf, 2);
	if (IS_GPR(reg)) {
		// Short ‘reg’ addresses from F0 to FF always specify GPRs.
		const char *dst = c166_global_registers[L_NIB(reg)];
		RzILOpBitVector *val = ADD(VARL("op1"), U16(data));
		return SEQ3(
			SETL("op1", VARG(dst)),
			SETG(dst, val),
			SEQ5(
				SET_E(U16(data)),
				SET_DZ(val),
				V_FALSE,
				C_FALSE,
				SET_DN(val)));
	}
	CHECK_STATE;
	const ut16 addr = state->ext.esfr ? ESFR_ADDR(reg) : SFR_ADDR(reg);
	printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_add_reg_data16 0x%04x, #0x%04x\n",
		op->id, op->addr, IP, addr, data);
	return rz_il_op_new_nop();
}

/*
 * (IP) ← ((SP))
 * (SP) ← (SP) + 2
 * IF (CPUCON1.SGTDIS = 0) THEN
 *	(CSP) ← ((SP))
 * END IF
 * (SP) ← (SP) + 2
 */
static RzILOpEffect *c166_il_rets(void) {
	return SEQN(6,
		SETL("SP", VARG("SP")),
		SETL("addr", SP_GET_VAL16),
		SETL("SP", SP_INC),
		BRANCH(INV(VARG("SGTDIS")),
			SETG("CSP", SP_GET_VAL8),
			NOP()),
		SETG("SP", SP_INC),
		JMP(UNSIGNED(32, VARL("addr"))));
}

/*
 *	(IP) ← ((SP))
 *	(SP) ← (SP) + 2
 *	(tmp) ← ((SP))
 *	(SP) ← (SP) + 2
 *	(op1) ← (tmp)
 *
 */
static RzILOpEffect *c166_il_retp(RzAnalysis *analysis, const ut8 *buf, const RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const ut8 reg = buf[1];
	if (IS_GPR(reg)) {
		// Short ‘reg’ addresses from F0 to FF always specify GPRs.
		printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_retp %s\n",
			op->id, op->addr, IP, c166_rw[L_NIB(reg)]);
		return rz_il_op_new_nop();
	}
	CHECK_STATE;
	const ut16 op1 = state->ext.esfr ? ESFR_ADDR(reg) : SFR_ADDR(reg);

	const RzPlatformTarget *arch_target = rz_analysis_get_arch_target(analysis);
	const char *resolved = rz_platform_profile_resolve_mmio(arch_target->profile, op1);
	if (!resolved) {
		RZ_LOG_DEBUG("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_retp 0x%04x\n",
			op->id, op->addr, IP, op1);
		return SEQN(7,
			SETL("SP", VARG("SP")),
			SETL("ip", SP_GET_VAL16),
			SETL("SP", SP_INC),
			STOREW(U32(op1), SP_GET_VAL16),
			SETL("SP", SP_INC),
			SETG("SP", VARL("SP")),
			JMP(UNSIGNED(32, VARL("ip"))));
	}

	return SEQN(7,
		SETL("SP", VARG("SP")),
		SETL("ip", SP_GET_VAL16),
		SETL("SP", SP_INC),
		SETG(resolved, SP_GET_VAL16),
		SETL("SP", SP_INC),
		SETG("SP", VARL("SP")),
		JMP(UNSIGNED(32, VARL("ip"))));
}

/*
 *	(IP) ← ((SP))
 *	(SP) ← (SP) + 2
 *	IF (CPUCON1.SGTDIS = 0) THEN
 *		(CSP) ← ((SP))
 *		(SP) ← (SP) + 2
 *	END IF
 *	(PSW) ← ((SP))
 *	(SP) ← (SP) + 2
 *
 */
static RzILOpEffect *c166_il_reti(void) {
	return SEQN(8,
		SETL("SP", VARG("SP")),
		SETL("addr", SP_GET_VAL16),
		SETL("SP", SP_INC),
		BRANCH(INV(VARG("SGTDIS")),
			SEQ2(
				SETG("CSP", SP_GET_VAL8),
				SETL("SP", SP_INC)),
			NOP()),
		SETG("PSW", SP_GET_VAL16),
		SETL("SP", SP_INC),
		SETG("SP", VARL("SP")),
		JMP(UNSIGNED(32, VARL("addr"))));
}

/*
 *	(IP) ← ((SP))
 *	(SP) ← (SP) + 2
 *
 */
static RzILOpEffect *c166_il_ret(void) {
	return SEQN(4,
		SETL("SP", VARG("SP")),
		SETL("ip", SP_GET_VAL16),
		SETG("SP", SP_INC),
		JMP(UNSIGNED(32, VARL("ip"))));
}

static RzILOpEffect *c166_il_or_rwn_rwm(const ut8 *buf) {
	const ut8 reg = buf[1];
	const ut8 op1 = H_NIB(reg);
	const ut8 op2 = L_NIB(reg);
	const char *src = c166_global_registers[op2];
	const char *dst = c166_global_registers[op1];
	return SEQN(5,
		SETL("op1", VARG(dst)),
		SETL("op2", VARG(src)),
		SETL("res", LOGOR(VARL("op1"), VARL("op2"))),
		SETG(dst, VARL("res")),
		SEQ5(
			SET_E(VARL("op2")),
			SETG("z", ITE(IS_ZERO(U16(op2)), IL_TRUE, IL_FALSE)),
			V_FALSE,
			C_FALSE,
			SET_N(VARL("res"))));
}

static RzILOpEffect *c166_il_push_reg(RzAnalysis *analysis, const ut8 *buf, const RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const ut8 reg = buf[1];
	if (IS_GPR(reg)) {
		// Short ‘reg’ addresses from F0 to FF always specify GPRs.
		printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_push_reg %s\n",
			op->id, op->addr, IP, c166_rw[L_NIB(reg)]);
		return SEQ5(
			SETL("reg_val", VARG(c166_rw[L_NIB(reg)])),
			SETL("SP", VARG("SP")),
			SETL("SP", SP_DEC),
			SETL("addr", UNSIGNED(32, VARL("SP"))),
			STORE(VARL("addr"), VARL("reg_val")));
	}
	CHECK_STATE;
	const ut16 addr = state->ext.esfr ? ESFR_ADDR(reg) : SFR_ADDR(reg);

	const RzPlatformTarget *arch_target = rz_analysis_get_arch_target(analysis);
	const char *resolved = rz_platform_profile_resolve_mmio(arch_target->profile, addr);
	if (!resolved) {

		printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_push_reg 0x%04x\n",
			op->id, op->addr, IP, addr);
		return rz_il_op_new_nop();
	}
	return SEQ6(
		SETL("reg_val", VARG(resolved)),
		SETL("SP", VARG("SP")),
		SETL("SP", SP_DEC),
		SETG("SP", VARL("SP")),
		SETL("addr", UNSIGNED(32, VARL("SP"))),
		STOREW(VARL("addr"), VARL("reg_val")));
}

static RzILOpEffect *c166_il_movb_rbn_rbm(void) {
#if RZ_DEBUG
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_movb_rbn_rbm\n", op->id, pc, IP);
#endif
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_movb_rbn_orwm_data16(const RzAnalysis *analysis, const ut8 *buf) {
	CHECK_STATE;
	const ut16 mem = rz_read_at_le16(buf, 2);
	const ut8 n = H_NIB(buf[1]);
	const ut8 m = L_NIB(buf[1]);

	if (state->ext.mode == C166_EXT_MODE_PAGE) {
		const ut32 seg = ((ut32)(state->ext.value & 0xFF));
		const char *dst = c166_get_word_reg_name(n);
		return SEQ5(
			SETL("addr", U16((seg << 14) + mem)),
			SETL("addr", ADD(VARL("addr"), VARG(c166_rw[m]))),
			SETL("load", LOADW(8, UNSIGNED(32, VARL("addr")))),
			WRITE_RL(dst, UNSIGNED(16, VARL("load"))),
			SEQ3(
				SET_E8(VARL("load")),
				SET_Z(VARL("load")),
				SET_N(VARL("load"))) // ??
		);
	}
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_mov_mem_reg(const RzAnalysis *analysis, const ut8 *buf, const RzAnalysisOp *op) {
	const ut8 reg = buf[1];
	const ut16 mem = rz_read_at_le16(buf, 2);

	CHECK_STATE;
	if (state->ext.mode == C166_EXT_MODE_REG || state->ext.mode == C166_EXT_MODE_NONE) {
		const ut8 i = mem >> 14;
		const char *src = c166_global_registers[L_NIB(reg)];
		const ut16 DPP_addr = SFR_ADDR(i);
		return SEQ5(
			SETL("src", VARG(src)),
			SET_E(VARL("src")),
			SET_Z(VARL("src")),
			SET_N(VARL("src")),
			STORE(U32(DPP_addr), UNSIGNED(8, VARL("src"))));
	}
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_mov_mem_reg unk\n", op->id, op->addr, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_movb_reg_mem(const RzAnalysis *analysis, const ut8 *buf, const RzAnalysisOp *op) {
	const ut8 reg = buf[1];
	const ut16 mem = rz_read_at_le16(buf, 2);

	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const st32 i = (mem >> 14) & 0b11;
	const ut16 DPP_addr = SFR_ADDR(i);

	if (IS_GPR(reg)) {
		// Short ‘reg’ addresses from F0 to FF always specify GPRs.
		const char *dst = c166_get_word_reg_name(L_NIB(reg));
		const bool hi_low = L_NIB(reg) & 1;

		return SEQN(4,
			SETL("dpp_val", read_DPP_mem(DPP_addr, mem)),
			SETL("val", LOADW(8, UNSIGNED(32, VARL("dpp_val")))),
			WRITE_RB(dst, hi_low, UNSIGNED(16, VARL("val"))),
			SEQ3(
				SET_E(VARL("val")),
				SET_Z(VARL("val")),
				SET_N(VARL("val"))));
	}
	CHECK_STATE;
	const ut16 reg_addr = state->ext.esfr ? ESFR_ADDR(reg) : SFR_ADDR(reg);
	printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_movb_reg_mem 0x%04x, 0x%04x:0x%04x\n",
		op->id, op->addr, IP, reg_addr, DPP_addr, mem & 0x3FFF);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_add_reg_mem(const RzAnalysis *analysis, const ut8 *buf, const RzAnalysisOp *op) {
	const ut8 reg = buf[1];
	const ut16 mem = rz_read_at_le16(buf, 2);

	const st32 i = (mem >> 14) & 0b11;
	const ut16 DPP_addr = SFR_ADDR(i);
	if (IS_GPR(reg)) {
		// Short ‘reg’ addresses from F0 to FF always specify GPRs.
		const char *dst = c166_rw[L_NIB(reg)];
		// printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_add_reg_mem %s, 0x%04x:0x%04x\n",
		// 		op->id, op->addr, IP, dst, DPP_addr, mem & 0x3FFF);
		return SEQN(4,
			SETL("dpp_val", read_DPP_mem(DPP_addr, mem)),
			SETL("dst", VARG(dst)),
			SETL("dst", ADD(VARL("dst"), VARL("dpp_val"))),
			SEQ3(
				SET_E(VARL("dpp_val")),
				SET_Z(VARL("dst")),
				SET_N(VARL("dst"))));
	}
	CHECK_STATE;
	const ut16 reg_addr = state->ext.esfr ? ESFR_ADDR(reg) : SFR_ADDR(reg);
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "] c166_il_add_reg_mem 0x%04x, 0x%04x:0x%04x\n",
		op->id, op->addr, IP, reg_addr, DPP_addr, mem & 0x3FFF);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_movb_orwm_data16_rbn(const RzAnalysis *analysis, const ut8 *buf) {
	CHECK_STATE;
	const ut16 mem = rz_read_at_le16(buf, 2);
	const ut8 n = H_NIB(buf[1]);
	const ut8 m = L_NIB(buf[1]);

	if (state->ext.mode == C166_EXT_MODE_PAGE) {
		const ut32 seg = (ut32)(state->ext.value & 0xFF);
		const char *dst = c166_get_word_reg_name(n);
		return SEQ3(
			SETL("addr", U16((seg << 14) + mem)),
			SETL("addr", ADD(VARL("addr"), VARG(c166_rw[m]))),
			STORE(UNSIGNED(32, VARL("addr")), UNSIGNED(8, READ_RL(VARG(dst)))));
	}
	return SEQ2(
		SETL("addr", UNSIGNED(32, ADD(VARG(c166_rw[m]), U16(mem)))),
		SETG(c166_rw[m], LOADW(16, VARL("addr"))));
}

static RzILOpEffect *c166_il_mov_rwn_rwm(const ut8 *buf) {
	const ut8 reg = buf[1];
	const char *dst = c166_global_registers[H_NIB(reg)];
	const char *src = c166_global_registers[L_NIB(reg)];
	return SEQ5(
		SETL("src", VARG(src)),
		SETG(dst, VARL("src")),
		SET_E(VARL("src")),
		SET_Z(VARL("src")),
		SET_N(VARL("src")));
}

static RzILOpEffect *c166_il_mov_rwn_orwmp(const RzAnalysis *analysis, const ut8 *buf) {
	CHECK_STATE;
	const ut8 reg = buf[1];
	const char *src = c166_global_registers[L_NIB(reg)];
	const char *dst = c166_global_registers[H_NIB(reg)];
	if (state->ext.esfr && state->ext.mode == C166_EXT_MODE_REG) {
		const char *ext_reg_name = c166_global_registers[state->ext.value];

		return SEQN(8,
			SETL("seg", UNSIGNED(32, VARG(ext_reg_name))),
			SETL("seg", SHIFTL0(VARL("seg"), U16(16))),
			SETL("src_op", VARG(src)),
			SETL("addr", LOGOR(VARL("seg"), UNSIGNED(32, VARL("src_op")))),
			SETL("load", LOADW(16, VARL("addr"))),
			SETG(dst, UNSIGNED(16, VARL("load"))),
			SETG(src, ADD(VARL("src_op"), U16(2))),
			SEQ3(
				SET_E(VARL("load")),
				SET_Z(VARL("load")),
				SET_N(VARL("load"))));
	}

	return SEQ7(
		SETL("val", VARG(c166_global_registers[L_NIB(reg)])),
		SETL("addr", UNSIGNED(32, VARG(src))),
		SETL("src_op", LOAD(VARL("addr"))),
		SETG(dst, UNSIGNED(16, VARL("src_op"))),
		SETL("add", ADD(VARG(src), U16(2))),
		SETG(src, VARL("add")),
		SEQ3(
			SET_E(VARL("val")),
			SET_Z(VARL("val")),
			SET_N(VARL("val"))));
}

static RzILOpEffect *c166_il_mov_rwn_data4(const ut8 *buf) {
	const ut8 reg = L_NIB(buf[1]);
	const ut8 data = H_NIB(buf[1]);
	return SEQN(3,
		SETL("val", U8(data)),
		SETG(c166_global_registers[reg], U16(data)),
		SEQ3(
			SET_E8(VARL("val")),
			SET_Z(VARL("val")),
			SET_N(VARL("val"))));
}

static RzILOpEffect *c166_il_mov_reg_data16(RzAnalysis *analysis, const ut8 *buf, const RzAnalysisOp *op) {
	const ut16 data = rz_read_at_le16(buf, 2);
	const ut8 reg = buf[1];
	RzILOpEffect *flags = SEQ3(
		SET_E(U16(data)),
		SET_Z(U16(data)),
		SET_N(U16(data)));

#ifdef C166_DUPLICATE_REG_OPERATIONS
	const ut8 SGTDIS = (ut8)rz_reg_getv(analysis->reg, "SGTDIS");
	if (SGTDIS == 0) {
		rz_reg_setv(analysis->reg, "CSP", seg);
	}
	// rz_reg_setv(analysis->reg, "IP", (((ut32)seg) << 16) | caddr);
	// rz_reg_setv(analysis->reg, c166_global_registers[L_NIB(reg)], (ut32)data);
#endif

	if (IS_GPR(reg)) {
#ifdef C166_DUPLICATE_REG_OPERATIONS
		rz_reg_setv(analysis->reg, c166_global_registers[L_NIB(reg)], (ut32)data);
#endif
		return SEQ2(SETG(c166_global_registers[L_NIB(reg)], U16(data)), flags);
	}
	const ut16 addr = SFR_ADDR(reg);

	const RzPlatformTarget *arch_target = rz_analysis_get_arch_target(analysis);
	const char *resolved = rz_platform_profile_resolve_mmio(arch_target->profile, addr);
	if (resolved) {
		switch (addr) {
		case 0xfe14: ///< "STKOV"
#ifdef C166_DUPLICATE_REG_OPERATIONS
			rz_reg_setv(analysis->reg, "r2", (ut32)data);
#endif
			return SEQ2(SETG("r2", U16(data)), flags);
		case 0xfe16: ///< "STKUN"
#ifdef C166_DUPLICATE_REG_OPERATIONS
			rz_reg_setv(analysis->reg, "r2", (ut32)data);
#endif
			return SEQ2(SETG("r3", U16(data)), flags);
		case 0xfe10: ///< "CP"
#ifdef C166_DUPLICATE_REG_OPERATIONS
			rz_reg_setv(analysis->reg, "r0", (ut32)data);
#endif
			return SEQ2(SETG("r0", U16(data)), flags);
		case 0xfe00: ///< "DPP0"
#ifdef C166_DUPLICATE_REG_OPERATIONS
			rz_reg_setv(analysis->reg, "DPP0", (ut32)data);
#endif
			return SEQ2(SETG("DPP0", UN(10, data)), flags);
		case 0xfe02: ///< "DPP1"
#ifdef C166_DUPLICATE_REG_OPERATIONS
			rz_reg_setv(analysis->reg, "DPP1", (ut32)data);
#endif
			return SEQ2(SETG("DPP1", UN(10, data)), flags);
		case 0xfe04: ///< "DPP2"
#ifdef C166_DUPLICATE_REG_OPERATIONS
			rz_reg_setv(analysis->reg, "DPP2", (ut32)data);
#endif
			return SEQ2(SETG("DPP2", UN(10, data)), flags);
		case 0xfe06: ///< "DPP3"
#ifdef C166_DUPLICATE_REG_OPERATIONS
			rz_reg_setv(analysis->reg, "DPP3", (ut32)data);
#endif
			return SEQ2(SETG("DPP3", UN(10, data)), flags);
		default:
			return SEQ2(SETG(resolved, U16(data)), flags);
		}
	}
	printf("--------------[0x%06" PFMT64x "] [%d] `%s`, 0x%04x\n",
		op->addr,
		L_NIB(reg),
		c166_global_registers[L_NIB(reg)],
		data);
	return flags;
}

static RzILOpEffect *c166_il_movb_rbn_data4(const RzAnalysis *analysis, const ut8 *buf) {
	CHECK_STATE;
	const ut8 data4 = H_NIB(buf[1]);
	const ut8 n = L_NIB(buf[1]);
	if (state->ext.esfr && state->ext.mode == C166_EXT_MODE_REG) {
		return rz_il_op_new_nop();
	}
	const char *dst = c166_get_word_reg_name(n);
	return SEQN(3,
		SETL("val", U16(data4)),
		WRITE_RL(dst, VARL("val")),
		SEQ3(
			SET_E(VARL("val")),
			SET_Z(VARL("val")),
			SET_N(VARL("val"))));
}

static RzILOpEffect *c166_il_mov_rwn_orwm_data16(void) {
#if RZ_DEBUG
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06" PFMT64x "] IP: [0x%06" PFMT64x "" PFMT64x "] c166_il_mov_rwn_orwm_data16\n", op->id, pc, IP);
#endif
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_extp_or_exts_pag10_or_seg8_irang2(void) {
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_jbc_bitaddr_rel(const ut8 *buf, const RzAnalysisOp *op) {
	const ut64 new_IP = op->addr + op->size + (2 * ((st8)buf[2]));
	const ut8 bitoff = buf[1];
	const ut8 bit_index = H_NIB(buf[3]);
	const char *reg = NULL;
	if (bitoff >= 0xF0) {
		reg = c166_rw[L_NIB(bitoff)];
	}
	return SEQN(11,
		SETL("mask", U16(1 << bit_index)),
		SETL("reg", VARG(reg)),
		SETL("_iar", LOGAND(VARL("reg"), VARL("mask"))),
		SETL("_iar", SHIFTR0(VARL("_iar"), U16(bit_index))),
		SETL("cond", NON_ZERO(VARL("_iar"))),
		SETG("e", IL_FALSE),
		SETG("z", INV(VARL("cond"))),
		SETG("v", IL_FALSE),
		SETG("c", IL_FALSE),
		SETG("n", VARL("cond")),
		BRANCH(VARL("cond"),
			SEQ2(
				SETG(reg, CLR_BIT16(VARL("reg"), bit_index)), ///< clear_bit
				JMP(U32(new_IP))), ///< jump
			NOP()));
}

static RzILOpEffect *c166_il_jmpr_rel(const ut8 *buf, const RzAnalysisOp *op) {
	const ut8 condition = (buf[0] & 0xf0) >> 4;
	const ut64 new_IP = op->addr + op->size + (2 * (st8)buf[1]);
	if (condition > 0xF) {
		rz_warn_if_reached();
		return rz_il_op_new_nop();
	}
	RzILOpBool *cond = check_condition(condition << 1);
	return BRANCH(cond, JMP(U32(new_IP)), NOP());
}

/**
 *
 * (SP) ← (SP) - 2
 * ((SP)) ← (CSP)
 * (SP) ← (SP) - 2
 * ((SP)) ← (IP)
 * IF (CPUCON1.SGTDIS = 0) THEN
 *	(CSP) ← op1
 * END IF
 * (IP) ← op2
 *
 */
static RzILOpEffect *c166_il_calls_seg_caddr(const ut8 *buf, const RzAnalysisOp *op) {
	const ut8 seg = buf[1];
	const ut16 caddr = rz_read_at_le16(buf, 2);
	const ut32 to_addr = (((ut32)seg) << 16) | caddr;
	RzILOpBitVector *_loc = UN(C166_ADDR_SIZE, to_addr);
	return SEQ8(
		SETL("SP", SUB(VARG("SP"), U16(2))),
		SETL("CSP", VARG("CSP")),
		STORE(UNSIGNED(32, VARL("SP")), UNSIGNED(8, VARL("CSP"))),
		SETL("SP", SUB(VARL("SP"), U16(2))),
		STOREW(UNSIGNED(32, VARL("SP")), U16(op->addr + C166_BYTESIZE_4)),
		SETG("SP", VARL("SP")),
		SETG("CSP", ITE(INV(VARG("SGTDIS")), U8(seg), U8(0))),
		JMP(_loc));
}

/**
 *
 * IF (op1) THEN
 *	(SP) ← (SP) - 2
 *	((SP)) ← (IP)
 *	(IP) ← op2
 * ELSE
 *	next instruction
 * END IF
 */
static RzILOpEffect *c166_il_calli_cc_rwn(const ut8 *buf, const RzAnalysisOp *op) {
	const ut8 op1 = buf[1];
	const ut8 condition = H_NIB(op1);
	const ut32 seg = (ut32)op->addr & 0xFF0000;

	return SEQ3(
		SETL("addr", UNSIGNED(32, VARG(c166_global_registers[L_NIB(op1)]))),
		SETL("addr", LOGOR(U32(seg), VARL("addr"))),
		BRANCH(
			check_condition(condition << 1),
			SEQ5(
				SETL("SP", VARG("SP")),
				SETL("SP", SP_DEC),
				SETG("SP", VARL("SP")),
				STOREW(UNSIGNED(32, VARL("SP")), U16(op->addr + C166_BYTESIZE_4)),
				JMP(VARL("addr"))),
			NOP()));
}

/**
 *
 * IF (op1) THEN
 *	(SP) ← (SP) - 2
 *	((SP)) ← (IP)
 *	(IP) ← op2
 * ELSE
 *	next instruction
 * END IF
 */
static RzILOpEffect *c166_il_calla_cc_caddr(const ut8 *buf, const RzAnalysisOp *op) {
	const ut8 op1 = buf[1];
	const ut32 seg = (ut32)op->addr & 0xFF0000;
	const ut32 addr = seg | rz_read_at_le16(buf, 2);
	const ut8 d = op1 >> 3;
	const ut8 a = op1 & 0x1;
	const bool l = op1 >> 1 & 0x1;
	(void)a;
	(void)l;

	/**
	 * CALLA xcc, caddr  | CA d00a MM MM | 4
	 * JMPA  xcc, caddr  | EA d0la MM MM | 4
	 * d : 5-bit condition code specification (xcc)
	 * l : 1-bit short backward loop bit
	 * a : 1-bit branch assumption bit
	 */
	return SEQ2(
		SETL("addr", U32(addr)),
		BRANCH(
			check_condition(d),
			SEQ5(
				SETL("SP", VARG("SP")),
				SETL("SP", SP_DEC),
				SETG("SP", VARL("SP")),
				STOREW(UNSIGNED(32, VARL("SP")), U16(op->addr + C166_BYTESIZE_4)),
				JMP(VARL("addr"))),
			NOP()));
}

/**
 *
 * IF (CPUCON1.SGTDIS = 0) THEN
 *	(CSP) ← op1
 * END IF
 * (IP) ← op2
 *
 */
static RzILOpEffect *c166_il_jmps_seg_caddr(const ut8 *buf) {
	const ut8 seg = buf[1];
	const ut16 caddr = rz_read_at_le16(buf, 2);
	const ut32 to_addr = ((ut32)seg << 16) | caddr;

#ifdef C166_DUPLICATE_REG_OPERATIONS
	const ut8 SGTDIS = (ut8)rz_reg_getv(analysis->reg, "SGTDIS");
	if (SGTDIS == 0) {
		rz_reg_setv(analysis->reg, "CSP", seg);
	}
	rz_reg_setv(analysis->reg, "IP", (((ut32)seg) << 16) | caddr);
#endif

	RzILOpEffect *set_CSP = SETG("CSP", ITE(INV(VARG("SGTDIS")), U8(seg), U8(0)));
	RzILOpBitVector *_loc = UN(C166_ADDR_SIZE, to_addr);
	return SEQ2(set_CSP, JMP(_loc));
}

RZ_IPI bool rz_c166_il_opcode(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	rz_return_val_if_fail(analysis && op, false);

	switch (op->id) {
	case C166_ADD_Rwn_Rwm:
		op->il_op = c166_il_add_rwn_rwm(buf);
		break;
	case C166_ADD_reg_data16:
		op->il_op = c166_il_add_reg_data16(analysis, buf, op);
		break;
	case C166_ADD_Rwn_x:
		op->il_op = c166_il_add_rwn_x(analysis, buf, op);
		break;
	case C166_ADDB_Rbn_x:
		op->il_op = c166_il_addb_rbn_x(buf);
		break;
	case C166_BFLDL_bitoff_x:
		op->il_op = c166_il_bfldl_bitoff_x(analysis, buf);
		break;
	case C166_JMPR_cc_UC_rel:
	case C166_JMPR_cc_NET_rel:
	case C166_JMPR_cc_EQ_or_Z_rel:
	case C166_JMPR_cc_NE_or_NZ_rel:
	case C166_JMPR_cc_V_rel:
	case C166_JMPR_cc_NV_rel:
	case C166_JMPR_cc_N_rel:
	case C166_JMPR_cc_NN_rel:
	case C166_JMPR_cc_C_or_ULT_rel:
	case C166_JMPR_cc_NC_or_NGE_rel:
	case C166_JMPR_cc_SGT_rel:
	case C166_JMPR_cc_SLE_rel:
	case C166_JMPR_cc_SLT_rel:
	case C166_JMPR_cc_SGE_rel:
	case C166_JMPR_cc_UGT_rel:
	case C166_JMPR_cc_ULE_rel:
		op->il_op = c166_il_jmpr_rel(buf, op);
		break;
	case C166_BCLR_bitoff0:
	case C166_BCLR_bitoff1:
	case C166_BCLR_bitoff2:
	case C166_BCLR_bitoff3:
	case C166_BCLR_bitoff4:
	case C166_BCLR_bitoff5:
	case C166_BCLR_bitoff6:
	case C166_BCLR_bitoff7:
	case C166_BCLR_bitoff8:
	case C166_BCLR_bitoff9:
	case C166_BCLR_bitoff10:
	case C166_BCLR_bitoff11:
	case C166_BCLR_bitoff12:
	case C166_BCLR_bitoff13:
	case C166_BCLR_bitoff14:
	case C166_BCLR_bitoff15:
		op->il_op = c166_il_clr_set_bitoff(analysis, buf, false);
		break;
	case C166_BSET_bitoff0:
	case C166_BSET_bitoff1:
	case C166_BSET_bitoff2:
	case C166_BSET_bitoff3:
	case C166_BSET_bitoff4:
	case C166_BSET_bitoff5:
	case C166_BSET_bitoff6:
	case C166_BSET_bitoff7:
	case C166_BSET_bitoff8:
	case C166_BSET_bitoff9:
	case C166_BSET_bitoff10:
	case C166_BSET_bitoff11:
	case C166_BSET_bitoff12:
	case C166_BSET_bitoff13:
	case C166_BSET_bitoff14:
	case C166_BSET_bitoff15:
		op->il_op = c166_il_clr_set_bitoff(analysis, buf, true);
		break;
	case C166_ADDC_Rwn_x:
		op->il_op = c166_il_addc_rwn_x(analysis, buf, op);
		break;
	case C166_ADD_reg_mem:
		op->il_op = c166_il_add_reg_mem(analysis, buf, op);
		break;
	case C166_BFLDH_bitoff_x:
		op->il_op = c166_il_bfldh_bitoff_x(analysis, buf);
		break;
	case C166_SUB_Rwn_x:
		op->il_op = c166_il_sub_rwn_x(buf);
		break;
	case C166_BMOVN_bitaddr_bitaddr:
		op->il_op = c166_il_bmovn_bitaddr_bitaddr();
		break;
	case C166_CMP_Rwn_Rwm:
		op->il_op = c166_il_cmp_rwn_rwm();
		break;
	case C166_CMPB_Rbn_Rbm:
		op->il_op = c166_il_cmpb_rbn_rbm(analysis, buf, op);
		break;
	case C166_CMPB_reg_data8:
		op->il_op = c166_il_cmpb_reg_data8(buf);
		break;
	case C166_CMP_Rwn_x:
		op->il_op = c166_il_cmp_rwn_x();
		break;
	case C166_CMP_reg_mem:
		op->il_op = c166_il_cmp_reg_mem(analysis, buf, op);
		break;
	case C166_CMPB_Rbn_x:
		op->il_op = c166_il_cmpb_rbn_x(analysis, buf, op);
		break;
	case C166_DIV_Rwn:
		op->il_op = c166_il_div_rwn();
		break;
	case C166_SHL_Rwn_Rwm:
		op->il_op = c166_il_shl_rwn_rwm();
		break;
	case C166_XORB_Rbn_Rbm:
		op->il_op = c166_il_xorb_rbn_rbm(buf);
		break;
	case C166_XOR_reg_mem:
		op->il_op = c166_il_xor_reg_mem();
		break;
	case C166_SHL_Rwn_data4:
		op->il_op = c166_il_shl_rwn_data4();
		break;
	case C166_AND_reg_data16:
		op->il_op = c166_il_and_reg_data16(analysis, buf);
		break;
	case C166_AND_Rwn_x:
		op->il_op = c166_il_and_rwn_x();
		break;
	case C166_DIVL_Rwn:
		op->il_op = c166_il_divl_rwn();
		break;
	case C166_OR_Rwn_Rwm:
		op->il_op = c166_il_or_rwn_rwm(buf);
		break;
	case C166_OR_reg_data16:
		op->il_op = c166_il_or_reg_data16(analysis, buf);
		break;
	case C166_OR_Rwn_x:
		op->il_op = c166_il_or_rwn_x();
		break;
	case C166_ORB_Rbn_x:
		op->il_op = c166_il_orb_rbn_x();
		break;
	case C166_SHR_Rwn_data4:
		op->il_op = c166_il_shr_rwn_data4();
		break;
	case C166_JB_bitaddr_rel:
		op->il_op = c166_il_jb_bitaddr_rel(analysis, buf, op);
		break;
	case C166_CPL_Rwn:
		op->il_op = c166_il_cpl_rwn(buf);
		break;
	case C166_MOV_Rwn_oRwmp:
		op->il_op = c166_il_mov_rwn_orwmp(analysis, buf);
		break;
	case C166_JNB_bitaddr_rel:
		op->il_op = c166_il_jnb_bitaddr_rel(analysis, buf, op);
		break;
	case C166_MOV_Rwn_oRwm:
		op->il_op = c166_il_mov_rwn_orwm(analysis, buf, op);
		break;
	case C166_MOVB_Rbn_oRwm:
		op->il_op = c166_il_movb_rbn_oRwm(analysis, buf);
		break;
	case C166_JBC_bitaddr_rel:
		op->il_op = c166_il_jbc_bitaddr_rel(buf, op);
		break;
	case C166_CALLI_cc_Rwn:
		op->il_op = c166_il_calli_cc_rwn(buf, op);
		break;
	case C166_MOV_oRwm_Rwn:
		op->il_op = c166_il_mov_orwm_rwn();
		break;
	case C166_MOVB_oRwm_Rbn:
		op->il_op = c166_il_movb_orwm_rbn(analysis, buf);
		break;
	case C166_MOVBZ_Rwn_Rbm:
		op->il_op = c166_il_movbz_rwn_rbm(buf);
		break;
	case C166_CALLA_cc_caddr:
		op->il_op = c166_il_calla_cc_caddr(buf, op);
		break;
	case C166_ATOMIC_or_EXTR_irang2:
	case C166_EXTP_or_EXTS_pag10_or_seg8_irang2:
	case C166_EXTP_or_EXTS_Rwm_irang2:
		op->il_op = c166_il_extp_or_exts_pag10_or_seg8_irang2();
		break;
	case C166_MOV_Rwn_oRwm_data16:
		op->il_op = c166_il_mov_rwn_orwm_data16();
		break;
	case C166_CALLS_seg_caddr:
		op->il_op = c166_il_calls_seg_caddr(buf, op);
		break;
	case C166_MOV_Rwn_data4:
		op->il_op = c166_il_mov_rwn_data4(buf);
		break;
	case C166_MOVB_Rbn_data4:
		op->il_op = c166_il_movb_rbn_data4(analysis, buf);
		break;
	case C166_MOVB_oRwm_data16_Rbn:
		op->il_op = c166_il_movb_orwm_data16_rbn(analysis, buf);
		break;
	case C166_MOV_reg_data16:
		op->il_op = c166_il_mov_reg_data16(analysis, buf, op);
		break;
	case C166_RET:
		op->il_op = c166_il_ret();
		break;
	case C166_RETS:
		op->il_op = c166_il_rets();
		break;
	case C166_RETP_reg:
		op->il_op = c166_il_retp(analysis, buf, op);
		break;
	case C166_RETI:
		op->il_op = c166_il_reti();
		break;
	case C166_PUSH_reg:
		op->il_op = c166_il_push_reg(analysis, buf, op);
		break;
	case C166_MOV_Rwn_Rwm:
		op->il_op = c166_il_mov_rwn_rwm(buf);
		break;
	case C166_MOVB_Rbn_Rbm:
		op->il_op = c166_il_movb_rbn_rbm();
		break;
	case C166_MOVB_Rbn_oRwm_data16:
		op->il_op = c166_il_movb_rbn_orwm_data16(analysis, buf);
		break;
	case C166_MOV_mem_reg:
		op->il_op = c166_il_mov_mem_reg(analysis, buf, op);
		break;
	case C166_MOVB_reg_mem:
		op->il_op = c166_il_movb_reg_mem(analysis, buf, op);
		break;
	case C166_JMPS_seg_caddr:
		op->il_op = c166_il_jmps_seg_caddr(buf);
		break;
	case C166_ENWDT:
	case C166_IDLE:
	case C166_SBRK:
	case C166_CoXXX_93:
	case C166_PWRDN:
	case C166_CoXXX_A3:
	case C166_DISWDT:
	case C166_SRVWDT:
	case C166_CoSTORE_B3:
	case C166_EINIT:
	case C166_SRST:
	case C166_CoSTORE_C3:
	case C166_STALLAM_44:
	case C166_STALLEW_45:
		op->il_op = c166_il_lifted_nop();
		break;
	case C166_ADDB_Rbn_Rbm:
	case C166_ADDB_reg_mem:
	case C166_ADD_mem_reg:
	case C166_ADDB_mem_reg:
	case C166_ADDB_reg_data8:
	case C166_MUL_Rwn_Rwm:
	case C166_ROL_Rwn_Rwm:
	case C166_ADDC_Rwn_Rwm:
	case C166_ADDCB_Rbn_Rbm:
	case C166_ADDC_reg_mem:
	case C166_ADDCB_reg_mem:
	case C166_ADDC_mem_reg:
	case C166_ADDCB_mem_reg:
	case C166_ADDC_reg_data16:
	case C166_ADDCB_reg_data8:
	case C166_ADDCB_Rbn_x:
	case C166_MULU_Rwn_Rwm:
	case C166_ROL_Rwn_data4:
	case C166_SUB_Rwn_Rwm:
	case C166_SUBB_Rbn_Rbm:
	case C166_SUB_reg_mem:
	case C166_SUBB_reg_mem:
	case C166_SUB_mem_reg:
	case C166_SUBB_mem_reg:
	case C166_SUB_reg_data16:
	case C166_SUBB_reg_data8:
	case C166_SUBB_Rbn_x:
	case C166_BCMP_bitaddr_bitaddr:
	case C166_PRIOR_Rwn_Rwm:
	case C166_ROR_Rwn_Rwm:
	case C166_SUBC_Rwn_Rwm:
	case C166_SUBCB_Rbn_Rbm:
	case C166_SUBC_reg_mem:
	case C166_SUBCB_reg_mem:
	case C166_SUBC_mem_reg:
	case C166_SUBCB_mem_reg:
	case C166_SUBC_reg_data16:
	case C166_SUBCB_reg_data8:
	case C166_SUBC_Rwn_x:
	case C166_SUBCB_Rbn_x:
	case C166_CMPB_reg_mem:
	case C166_CMP_reg_data16:
	case C166_BMOV_bitaddr_bitaddr:
	case C166_XOR_Rwn_Rwm:
	case C166_XORB_reg_mem:
	case C166_XOR_mem_reg:
	case C166_XORB_mem_reg:
	case C166_XOR_reg_data16:
	case C166_XORB_reg_data8:
	case C166_XOR_Rwn_x:
	case C166_XORB_Rbn_x:
	case C166_BOR_bitaddr_bitaddr:
	case C166_DIVU_Rwn:
	case C166_CMPI2_Rwn_data4:
	case C166_CMPI2_Rwn_mem:
	case C166_MOV_mem_oRwn:
	case C166_CMPI2_Rwn_data16:
	case C166_MOVB_Rbn_oRwmp:
	case C166_TRAP_trap7:
	case C166_JMPI_cc_oRwn:
	case C166_CMPD1_Rwn_data4:
	case C166_NEGB_Rbn:
	case C166_CMPD1_Rwn_mem:
	case C166_MOVB_oRwn_mem:
	case C166_CMPD1_Rwn_data16:
	case C166_ASHR_Rwn_Rwm:
	case C166_CMPD2_Rwn_data4:
	case C166_CPLB_Rbn:
	case C166_CMPD2_Rwn_mem:
	case C166_MOVB_mem_oRwn:
	case C166_CMPD2_Rwn_data16:
	case C166_JNBS_bitaddr_rel:
	case C166_CALLR_rel:
	case C166_ASHR_Rwn_data4:
	case C166_MOVBZ_reg_mem:
	case C166_MOV_oRwm_data16_Rwn:
	case C166_MOVBZ_mem_reg:
	case C166_SCXT_reg_data16:
	case C166_MOV_oRwn_oRwm:
	case C166_MOVB_oRwn_oRwm:
	case C166_MOVBS_Rwn_Rbm:
	case C166_MOVBS_reg_mem:
	case C166_CoMOV:
	case C166_MOVBS_mem_reg:
	case C166_SCXT_reg_mem:
	case C166_MOV_oRwnp_oRwm:
	case C166_MOVB_oRwnp_oRwm:
	case C166_PCALL_reg_caddr:
	case C166_MOVB_reg_data8:
	case C166_MOV_oRwn_oRwmp:
	case C166_MOVB_oRwn_oRwmp:
	case C166_JMPA_cc_caddr:
	case C166_MOV_reg_mem:
	case C166_MOVB_mem_reg:
	case C166_POP_reg:
	case C166_AND_Rwn_Rwm:
	case C166_ANDB_Rbn_Rbm:
	case C166_AND_reg_mem:
	case C166_ANDB_reg_mem:
	case C166_AND_mem_reg:
	case C166_ANDB_mem_reg:
	case C166_ANDB_reg_data8:
	case C166_ANDB_Rbn_x:
	case C166_BAND_bitaddr_bitaddr:
	case C166_SHR_Rwn_Rwm:
	case C166_ORB_Rbn_Rbm:
	case C166_OR_reg_mem:
	case C166_ORB_reg_mem:
	case C166_OR_mem_reg:
	case C166_ORB_mem_reg:
	case C166_ORB_reg_data8:
	case C166_BXOR_bitaddr_bitaddr:
	case C166_DIVLU_Rwn:
	case C166_CMPI1_Rwn_data4:
	case C166_NEG_Rwn:
	case C166_CMPI1_Rwn_mem:
	case C166_CoXXX_83:
	case C166_MOV_oRwn_mem:
	case C166_CMPI1_Rwn_data16:
	case C166_MOV_noRwm_Rwn:
	case C166_MOVB_noRwm_Rbn:
	case C166_ROR_Rwn_data4:
		op->il_op = c166_il_unk();
		break;
	case C166_NOP:
	default:
		op->il_op = NOP();
	}
	return true;
}

RZ_IPI RzAnalysisILConfig *rz_c166_il_config(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);

	RzAnalysisILConfig *r = rz_analysis_il_config_new(32, analysis->big_endian, C166_ADDR_SIZE);
	r->reg_bindings = c166_global_registers;
	r->init_state = rz_analysis_il_init_state_new();
	if (!r->init_state) {
		rz_analysis_il_config_free(r);
		return NULL;
	}
	rz_analysis_il_init_state_set_var(r->init_state, "r0", IL_U16(0xFC00)); ///< CP
	rz_analysis_il_init_state_set_var(r->init_state, "r1", IL_U16(0xFC00)); /// < SP
	rz_analysis_il_init_state_set_var(r->init_state, "SP", IL_U16(0xFC00)); /// < SP
	rz_analysis_il_init_state_set_var(r->init_state, "r2", IL_U16(0xFA00)); ///< STKOV
	rz_analysis_il_init_state_set_var(r->init_state, "r3", IL_U16(0xFC00)); ///< STKUN
	rz_analysis_il_init_state_set_var(r->init_state, "DPP1", IL_UN(10, 0x0001));
	rz_analysis_il_init_state_set_var(r->init_state, "DPP2", IL_UN(10, 0x0002));
	rz_analysis_il_init_state_set_var(r->init_state, "DPP3", IL_UN(10, 0x0003));
	rz_analysis_il_init_state_set_var(r->init_state, "BUSCON0", IL_U16(0x0680)); ///< BUSCON0
	return r;
}

#include <rz_il/rz_il_opbuilder_end.h>
