// SPDX-FileCopyrightText: 2022 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PPC_IL_H
#define PPC_IL_H

#include "ppc_analysis.h"
#include <rz_reg.h>
#include <rz_analysis.h>
#include <rz_il.h>
#include <rz_types.h>
#include <capstone.h>

#define PPC_BYTE  8
#define PPC_HWORD 16
#define PPC_WORD  32
#define PPC_DWORD 64
#define PPC_QWORD 128

/**
 * \brief This value varies from implementation to implementation.
 * Should be replaced with a plugin specific config option.
 */
#define DCACHE_LINE_SIZE 32

/**
 * \brief Writes to the info log that an unimplemented instruction was encountered and returns an EMPTY() effect.
 */
#define NOT_IMPLEMENTED \
	do { \
		RZ_LOG_INFO("IL instruction not implemented."); \
		return EMPTY(); \
	} while (0)

/**
 * \brief Unsigned value \p i which is PPC_ARCH_BITS (32 or 64) wide.
 */
#define UA(i) (IN_64BIT_MODE ? U64(i) : U32(i))

/**
 * \brief Signed value \p i which is PPC_ARCH_BITS (32 or 64) wide.
 */
#define SA(i) (IN_64BIT_MODE ? S64(i) : S32(i))

/**
 * \brief Extend value \p v with sign bits to a width of \p n.
 */
#define EXTEND(n, v) LET("v", v, ITE(MSB(VARLP("v")), SIGNED(n, VARLP("v")), UNSIGNED(n, VARLP("v"))))

/**
 * \brief Extend value with sign bits to a width of 32/64 bit.
 */
#define EXTS(v) SIGNED(PPC_ARCH_BITS, v)

/**
 * \brief Extend value with 0s to a width of 32/64 bit.
 */
#define EXTZ(v) UNSIGNED(PPC_ARCH_BITS, v)

/**
 * \brief If the \p rX is 0 it returns the value 0. Otherwise the value stored in \p rX.
 */
#define IFREG0(rX) ITE(EQ(VARG(rX), UA(0)), UA(0), VARG(rX))

/**
 * \brief Rotates a 64bit value. Rotate \p x left by \p y bits.
 * \p y should be U8, \p x should be U32 and U64 respectively.
 */
#define ROTL64(x, y) (LOGOR(SHIFTL0(x, y), SHIFTR0(DUP(x), SUB(U8(64), CAST(8, IL_FALSE, DUP(y))))))

/**
 * \brief Rotates a 32bit value. If the the VM is in 64bit mode "ROTL64(x||x, y)" is executed instead. 
 */
#define ROTL32(x, y) (IN_64BIT_MODE ? ROTL64(APPEND(x, DUP(x)), y) : LOGOR(SHIFTL0(x, y), SHIFTR0(DUP(x), SUB(U8(32), CAST(8, IL_FALSE, DUP(y))))))

/**
 * \brief Returns a Pure of width \p w with the \p i bit set.
 * Please note: The left most bit is bit 0.
 */
#define BIT_I(w, i) SHIFTR0(SHIFTR(IL_TRUE, UN(w, 0), U8(1)), i)

/**
 * \brief Sets bit \p i (=IL_TRUE) in the local variable with width \p w of the name \p vn.
 * Please note: The left most bit is bit 0.
 */
#define SET_BIT(vn, w, i) SETL(vn, LOGOR(VARL(vn), BIT_I(w, i)))

/**
 * \brief Unsets bit \p i (=IL_FALSE) in the local variable with width \p w of the name \p vn.
 * Please note: The left most bit is bit 0.
 */
#define UNSET_BIT(vn, w, i) SETL(vn, LOGAND(VARL(vn), LOGNOT(BIT_MASK(w, i, i))))

/**
 * \brief Returns a Pure of length \p l with bit \p i to \p j (inclusive \p j) set to IL_TRUE.
 * \p i marks he left bit. \p j the right. \p l, \p i and \p j need to be U8.
 * Please note: The left most bit is bit 0.
 */
#define BIT_MASK(l, i, j) LOGNOT(LOGOR(SHIFTR(IL_TRUE, UN(l, 0), ADD(i, U8(1))), SHIFTL(IL_TRUE, UN(l, 0), SUB(U8(l), j))))

/** 
 * \brief Sets bit \p i to \p j of the variable \p v to the value stored in \p s.
 * Both variables must be of width w.
 * \p i and \p j should be U8
 * Please note: The left most bit is bit 0.
 */
#define SET_RANGE(v, i, j, s, w) LOGOR(LOGAND(LOGNOT(BIT_MASK(w, i, j)), v), LOGAND(SHIFTL0(s, SUB(U8(w), j)), BIT_MASK(w, i, j)))

/** 
 * \brief Tests bit i in Pure value v with a width of w.
 * Returns IL_TRUE if bit i is set. IL_FALSE otherwise.
 * Please note: The left most bit is bit 0.
 */
#define BIT_IS_SET(val, w, i) NON_ZERO(LOGAND(val, BIT_I(w, i)))

/**
 * \brief Implements the mask generation from the Reference Manual.
 * 
 * if mstart ≤ mstop then
 *      mask[mstart:mstop] = ones
 *      mask[all other bits] = zeros
 * else
 *      mask[mstart:63] = ones
 *      mask[0:mstop] = ones
 *      mask[all other bits] = zeros
 * 
 * The algorithm implemented here is:
 * 
 * ```
 * m = 0
 * while (mstart != mstop) {
 *     m[mstart] = 1
 *     mstart = (mstart + 1) % 64
 * }
 * m[mstop] = 1
 * mask = (PPC_ARCH_BITS) m
 * ```
 * 
 * All computations are on 64 bit numbers.
 * In case of a 32bit CPU the result will be casted to 32bit.
 * The local variable "mask" will hold the mask
 */
#define SET_MASK(mstart, mstop) \
	SEQ6(SETL("mstart", mstart), \
		SETL("mstop", mstop), \
		SETL("m", U64(0)), \
		REPEAT(INV(EQ(VARL("mstart"), VARL("mstop"))), \
			SEQ2(SET_BIT("m", 64, VARL("mstart")), \
				SETL("mstart", MOD(ADD(VARL("mstart"), U8(1)), U8(64))))), \
		SET_BIT("m", 64, VARL("mstop")), \
		SETL("mask", CAST(PPC_ARCH_BITS, IL_FALSE, VARL("m"))))

RZ_IPI RzAnalysisILConfig *rz_ppc_cs_64_il_config(bool big_endian);
RZ_IPI RzAnalysisILConfig *rz_ppc_cs_32_il_config(bool big_endian);

RZ_IPI RzILOpEffect *rz_ppc_cs_get_il_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode);

RZ_OWN RzILOpEffect *set_carry_add_sub(RZ_OWN RzILOpBitVector *a, RZ_OWN RzILOpBitVector *b, cs_mode mode, bool add);
RZ_OWN RzILOpEffect *cmp_set_cr(RZ_BORROW RzILOpPure *left, RZ_BORROW RzILOpPure *right, const bool signed_cmp, const char *crX, const cs_mode mode);

bool ppc_is_x_form(ut32 insn_id);
st32 ppc_get_mem_acc_size(ut32 insn_id);
bool ppc_updates_ra_with_ea(ut32 insn_id);
bool ppc_is_algebraic(ut32 insn_id);
bool ppc_sets_lr(ut32 insn_id);
bool ppc_is_conditional(ut32 insn_id);
bool ppc_moves_to_spr(ut32 insn_id);
bool is_d_mul_div(ut32 id);
bool ppc_decrements_ctr(RZ_BORROW cs_insn *insn, const cs_mode mode);
RZ_IPI ut32 ppc_fmx_to_mask(const ut8 fmx);
RZ_IPI RZ_OWN RzILOpPure *ppc_get_cr(const ut8 x);
RZ_IPI const char *ppc_get_cr_name(const ut8 x);
RZ_IPI ut8 ppc_translate_cs_cr_flag(const char *flag);

RZ_OWN RzILOpPure *ppc_get_xer(cs_mode mode);
RZ_OWN RzILOpEffect *ppc_set_xer(RzILOpPure *val, cs_mode mode);
RZ_OWN RzILOpPure *ppc_get_branch_ta(RZ_BORROW cs_insn *insn, const cs_mode mode);
RZ_OWN RzILOpPure *ppc_get_branch_cond(RZ_BORROW cs_insn *insn, const cs_mode mode);
RZ_IPI RZ_OWN RzILOpEffect *sync_crx_cr(const bool to_cr, const ut32 cr_mask);

#endif /* PPC_IL_H */
