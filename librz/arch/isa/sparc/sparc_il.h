// SPDX-FileCopyrightText: 2025 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef SPARC_IL_H
#define SPARC_IL_H

#include "rz_il/rz_il_opcodes.h"
#include <rz_analysis.h>
#include <capstone/capstone.h>

#define INSDETAIL() insn->detail->sparc
#define INSOP(n)    insn->detail->sparc.operands[n]
#if CS_API_MAJOR >= 6
#define INSCC_NORM() (insn->detail->sparc.cc & ~(SPARC_CC_FCC_BEGIN | SPARC_CC_CPCC_BEGIN | SPARC_CC_REG_BEGIN))
#else
#define INSCC_NORM() (insn->detail->sparc.cc)
#endif
#define INSCC_RAW() (insn->detail->sparc.cc)
#define INSHINT()   (insn->detail->sparc.hint)

#define IN_64BIT_MODE   ((mode & CS_MODE_64) == CS_MODE_64)
#define SPARC_ARCH_BITS (IN_64BIT_MODE ? 64 : 32)

#define SPARC_INSN_SIZE 4

#define SPARC_BYTE          (8 * 1)
#define SPARC_HALF_WORD     (8 * 2)
#define SPARC_WORD          (8 * 4)
#define SPARC_DOUBLE_WORD   (8 * 8)
#define SPARC_EXTENDED_WORD (8 * 8)
#define SPARC_QUAD_WORD     (8 * 16)

/**
 * \brief The memory index where SAVE and RESTORE
 * move the register window into/out of.
 */
#define SPARC_ASI_INDEX_RW 1

#define SPARC_BITNNESS (IN_64BIT_MODE ? 64 : 32)

/**
 * \brief Number of register windows to SAVE/RESTORE.
 * Most CPUs in QEMU have 8.
 */
#define SPARC_NWINDOWS 8

/**
 * \brief The size of the register window which is backed up by SAVE
 * and restored by RESTORE.
 */
#define SPARC_REG_WINDOW_SIZE (IN_64BIT_MODE ? 64 * RZ_ARRAY_SIZE(backed_up_regs) : 32 * RZ_ARRAY_SIZE(backed_up_regs))

/**
 * \brief Unsigned value \p i which is SPARC_ARCH_BITS (32 or 64) wide.
 */
#define UA(i) (IN_64BIT_MODE ? U64(i) : U32(i))

/**
 * \brief Signed value \p i which is SPARC_ARCH_BITS (32 or 64) wide.
 */
#define SA(i) (IN_64BIT_MODE ? S64(i) : S32(i))

/**
 * \brief Cast to unsigned value of SPARC_ARCH_BITS (32 or 64) wide.
 */
#define CAST_UA(val) UNSIGNED(SPARC_ARCH_BITS, val)

/**
 * \brief Cast to signed value of SPARC_ARCH_BITS (32 or 64) wide.
 */
#define CAST_SA(val) SIGNED(SPARC_ARCH_BITS, val)

/**
 * \brief Tests bit i in Pure value val.
 * Returns IL_TRUE if bit i is set. IL_FALSE otherwise.
 * If the width of val is smaller than i, it will return IL_FALSE.
 * The right most bit is bit 0.
 */
#define BIT(i, val) MSB(UNSIGNED(i + 1, val))

/**
 * \brief Set bit i in Global with gname and width gwidth.
 */
#define SET_BIT(i, gname, gwidth) SETG(gname, LOGOR(VARG(gname), SHIFTL0(UN(gwidth, 1), U8(i))))

/**
 * \brief The rounding mode for float operations.
 * It actually is selected by the RD flag in the FSR register.
 * But dynamic rounding mode selection is not implemented yet.
 * So just choose one and accept the inaccuracies for now.
 *
 * Tracking issue: https://github.com/rizinorg/rizin/issues/1461
 */
#define SPARC_RMODE() RZ_FLOAT_RMODE_RNA

#define ICC_C() LSB(VARG("ccr"))
#define ICC_V() LSB(SHIFTR0(VARG("ccr"), U8(1)))
#define ICC_Z() LSB(SHIFTR0(VARG("ccr"), U8(2)))
#define ICC_N() LSB(SHIFTR0(VARG("ccr"), U8(3)))
#define XCC_C() LSB(SHIFTR0(VARG("ccr"), U8(4)))
#define XCC_V() LSB(SHIFTR0(VARG("ccr"), U8(5)))
#define XCC_Z() LSB(SHIFTR0(VARG("ccr"), U8(6)))
#define XCC_N() LSB(SHIFTR0(VARG("ccr"), U8(7)))

#define BIT_C(il_field) LSB(il_field)
#define BIT_V(il_field) LSB(SHIFTR0(il_field, U8(1)))
#define BIT_Z(il_field) LSB(SHIFTR0(il_field, U8(2)))
#define BIT_N(il_field) LSB(SHIFTR0(il_field, U8(3)))

#define ICC() VARG("ccr")
#define XCC() SHIFTR0(VARG("ccr"), U8(4))

#define SET_FCC(n, v) SEQ2(SETL("sh", U8((n == 0 ? 10 : ((2 * (n - 1)) + 32)))), SETG("fsr", LOGOR(LOGAND(VARG("fsr"), LOGNOT(SHIFTL0(UA(3), VARL("sh")))), SHIFTL0(v, VARL("sh")))))

#define SET_FCC_EQ(n) SET_FCC(n, UA(0))
#define SET_FCC_LT(n) SET_FCC(n, UA(1))
#define SET_FCC_GT(n) SET_FCC(n, UA(2))
#define SET_FCC_UN(n) SET_FCC(n, UA(3))

#define GET_FCC_EQ(n) EQ(UA(0), LOGAND(SHIFTR0(VARG("fsr"), U8((n == 0 ? 10 : ((2 * (n - 1)) + 32)))), UA(3)))
#define GET_FCC_LT(n) EQ(UA(1), LOGAND(SHIFTR0(VARG("fsr"), U8((n == 0 ? 10 : ((2 * (n - 1)) + 32)))), UA(3)))
#define GET_FCC_GT(n) EQ(UA(2), LOGAND(SHIFTR0(VARG("fsr"), U8((n == 0 ? 10 : ((2 * (n - 1)) + 32)))), UA(3)))
#define GET_FCC_UN(n) EQ(UA(3), LOGAND(SHIFTR0(VARG("fsr"), U8((n == 0 ? 10 : ((2 * (n - 1)) + 32)))), UA(3)))

#define SSETG(gname, gval) rz_sparc_set_g(gname, gval)

typedef enum {
	RZ_SPARC_CCR_OP_ADD,
	RZ_SPARC_CCR_OP_SUB,
	RZ_SPARC_CCR_OP_SDIV,
	RZ_SPARC_CCR_OP_UDIV,
	RZ_SPARC_CCR_OP_UMUL,
	RZ_SPARC_CCR_OP_SMUL,
	RZ_SPARC_CCR_OP_AND,
	RZ_SPARC_CCR_OP_OR,
	RZ_SPARC_CCR_OP_XOR,
} RzSparcCCROp;

typedef struct {
	RzILOpEffect *set_ea; ///< The RzIL Effect to write the target jump address to the local variable EA.
	RzILOpEffect *perform_jmp; ///< The RzIL Effect to performing the jump to EA.
	/**
	 * \brief The RzIL Effect to performing the jump if the branch condition is false.
	 * Might be NULL if no condition exists.
	 */
	RzILOpEffect *perform_fail_jmp;
	RzILOpPure *cond; ///< The branch condition. NULL if branch has none.
	bool annulled_bit; ///< The annulled bit.
} RzSparcDelatedBranchOp;

typedef struct {
	RzRegItem *reg;
	csh handle;
	int omode;
	/**
	 * \brief The delayed branch operations.
	 * The map is indexed by the address the branch is executed.
	 * So if we have:
	 * ```
	 * 0x800 call somewhere
	 * 0x804 save
	 * ```
	 * The delayed branch effect is stored under the key 0x804.
	 */
	HtUP /*<RzSparcDelatedBranchOp>*/ *delayed_branch;
} RzAnalysisValueSPARC;

typedef enum {
	RZ_SPARC_CC_UPDATE = 0, ///< Update according to the operation.
	RZ_SPARC_CC_UNSET, ///< Unset.
	RZ_SPARC_CC_NO_TOUCH, ///< Don't change value.
} RzSparcSetTask;

typedef struct {
	RzSparcSetTask icc_n;
	RzSparcSetTask icc_z;
	RzSparcSetTask icc_v;
	RzSparcSetTask icc_c;
	RzSparcSetTask xcc_n;
	RzSparcSetTask xcc_z;
	RzSparcSetTask xcc_v;
	RzSparcSetTask xcc_c;
} RzSparcCCRBits;

#if CS_API_MAJOR >= 6

static inline bool is_float_upper(sparc_reg reg) {
	return RZ_BETWEEN(SPARC_REG_D16, reg, SPARC_REG_D31) ||
		RZ_BETWEEN(SPARC_REG_Q8, reg, SPARC_REG_Q15);
}

static inline bool is_float_lower(sparc_reg reg) {
	return RZ_BETWEEN(SPARC_REG_F0, reg, SPARC_REG_F31) ||
		RZ_BETWEEN(SPARC_REG_D0, reg, SPARC_REG_D15) ||
		RZ_BETWEEN(SPARC_REG_Q0, reg, SPARC_REG_Q7);
}

static inline bool is_v8_reg(sparc_reg reg) {
	return RZ_BETWEEN(SPARC_REG_F0, reg, SPARC_REG_F31) ||
		RZ_BETWEEN(SPARC_REG_D0, reg, SPARC_REG_D15) ||
		RZ_BETWEEN(SPARC_REG_Q0, reg, SPARC_REG_Q7) ||
		RZ_BETWEEN(SPARC_REG_O0, reg, SPARC_REG_O7) ||
		RZ_BETWEEN(SPARC_REG_G0, reg, SPARC_REG_G7) ||
		RZ_BETWEEN(SPARC_REG_I0, reg, SPARC_REG_I7) ||
		reg == SPARC_REG_G0_G1 ||
		reg == SPARC_REG_G2_G3 ||
		reg == SPARC_REG_G4_G5 ||
		reg == SPARC_REG_G6_G7 ||
		reg == SPARC_REG_I0_I1 ||
		reg == SPARC_REG_I2_I3 ||
		reg == SPARC_REG_I4_I5 ||
		reg == SPARC_REG_I6_I7 ||
		reg == SPARC_REG_L0_L1 ||
		reg == SPARC_REG_L2_L3 ||
		reg == SPARC_REG_L4_L5 ||
		reg == SPARC_REG_L6_L7 ||
		reg == SPARC_REG_O0_O1 ||
		reg == SPARC_REG_O2_O3 ||
		reg == SPARC_REG_O4_O5 ||
		reg == SPARC_REG_O6_O7;
}

static inline bool is_float_reg(sparc_reg reg) {
	return RZ_BETWEEN(SPARC_REG_F0, reg, SPARC_REG_F31) ||
		RZ_BETWEEN(SPARC_REG_D0, reg, SPARC_REG_D31) ||
		RZ_BETWEEN(SPARC_REG_Q0, reg, SPARC_REG_Q15);
}
#endif

RZ_IPI RzAnalysisILConfig *rz_sparc_cs_64_il_config(bool big_endian);
RZ_IPI RzAnalysisILConfig *rz_sparc_cs_32_il_config(bool big_endian);
RZ_IPI RzILOpEffect *rz_sparc_cs_get_il_op(const csh handle, const cs_insn *insn, const cs_mode mode, RZ_NULLABLE RzAnalysisValueSPARC *state);
RZ_IPI RzILOpPure *rz_sparc_cs_get_operand(RZ_BORROW csh handle, const cs_insn *insn, cs_mode mode, size_t i, size_t float_width);
RZ_IPI RzILOpEffect *rz_sparc_set_ccr_flags(RzILOpBool *icc_c, RzILOpBool *icc_v, RzILOpBool *icc_z, RzILOpBool *icc_n, RzILOpBool *xcc_c, RzILOpBool *xcc_v, RzILOpBool *xcc_z, RzILOpBool *xcc_n);
RZ_IPI RzILOpEffect *rz_sparc_2args_ccr(RzSparcCCROp op, RzILOpPure *arg0, RzILOpPure *arg1, RZ_NULLABLE RzILOpBool *carry_bit, RzSparcCCRBits *bits);
RZ_IPI const char *rz_sparc_get_next_reg_name(const csh handle, sparc_reg base_reg, size_t offset);
RZ_IPI RzILOpPure *rz_sparc_freg_to_fpure(const csh handle, sparc_reg base_reg, size_t width);
RZ_IPI RzILOpEffect *rz_sparc_fpure_to_freg(const csh handle, cs_mode mode, sparc_reg dst_reg, RzILOpFloat *src, size_t width);
RZ_IPI RzILOpEffect *rz_sparc_bv_to_consec_regs(const csh handle, cs_mode mode, sparc_reg dst_reg, RzILOpBitVector *bv, size_t width);
RZ_IPI RzILOpEffect *rz_sparc_set_g(const char *gname, RzILOpPure *gval);
RZ_IPI RZ_OWN RzILOpBool *add_overflow(RZ_OWN RzILOpBitVector *a, RZ_OWN RzILOpBitVector *b, RZ_OWN RzILOpBitVector *res);
RZ_IPI RZ_OWN RzILOpBool *sub_overflow(RZ_OWN RzILOpBitVector *a, RZ_OWN RzILOpBitVector *b, RZ_OWN RzILOpBitVector *res);

#endif // SPARC_IL_H
