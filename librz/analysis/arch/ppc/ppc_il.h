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

// Un/signed value with 32/64 bits.
#define UA(i) (IN_64BIT_MODE ? U64(i) : U32(i))
#define SA(i) (IN_64BIT_MODE ? S64(i) : S32(i))
// Un/signed immediate with 32/64 bits.
#define IMM_U(i) UA(i)
#define IMM_S(i) SA(i)
// Un/signed immediate with n bits.
#define IMM_UN(n, v) UN(n, v)
#define IMM_SN(n, v) SN(n, v)

// Extend value with sign bits to a width of n.
#define EXTEND(n, v) LET("v", v, ITE(MSB(VARLP("v")), SIGNED(n, VARLP("v")), UNSIGNED(n, VARLP("v"))))
// Extend value with sign bits to a width of 32/64 bit.
#define EXTS(v) SIGNED(PPC_ARCH_BITS, v)
// Extend value with 0s to a width of 32/64 bit.
#define EXTZ(v) UNSIGNED(PPC_ARCH_BITS, v)

// If the rX reg is 0 it returns the value 0. Otherwise the value store in rX.
#define IFREG0(rX) ITE(EQ(VARG(rX), UA(0)), UA(0), VARG(rX))

// y should be U8() for the rotate macros. x shoudl be 32 and 64bit.
// Rotate x left by y bits
#define ROTL64(x, y) (LOGOR(SHIFTL0(x, y), SHIFTR0(DUP(x), SUB(U8(64), DUP(y)))))
// Rotates a 32bit value. If the the VM is in 64bit mode "ROTL64(x||x, y)" is executed instead.
#define ROTL32(x, y) (IN_64BIT_MODE ? ROTL64(APPEND(x, DUP(x)), y) : LOGOR(SHIFTL0(x, y), SHIFTR0(DUP(x), SUB(U8(32), DUP(y)))))

// Sets bit `i` in the local variable with width `w` of the name `vn`.
// Please note: The left most bit is bit 0.
#define SET_BIT(vn, w, i) SETL(vn, LOGOR(VARL(vn), SHIFTR0(SHIFTR(UN(w, 0), IL_TRUE, U8(1)), i)))
// Implements the mask generation from the Reference Manual.
//
// if mstart ≤ mstop then
//      mask[mstart:mstop] = ones
//      mask[all other bits] = zeros
// else
//      mask[mstart:63] = ones
//      mask[0:mstop] = ones
//      mask[all other bits] = zeros
//
// The algorithm implemented here is:
//
// ```
// count = (mstart == mstop) ? PPC_ARCH_BITS :
//                             ((mstart < mstop) ?
//                                                (mstop - mstart) :
//                                                (mstop + (PPC_ARCH_BITS - mstart)));
// mask = 0
// while (count != 0) {
//     mask[mstart] = 1;
//     mstart = (mstart + 1) % PPC_ARCH_BITS;
//     count--;
// }
// ```
//
// mstart and mstop should be U8 pures.
// The local variable "m" will hold the mask

#define SET_MASK(mstart, mstop) \
	SEQ5(SETL("mstart", mstart), \
		SETL("mstop", mstop), \
		SETL("count", ITE(EQ(VARL("mstart"), VARL("mstop")), U8(PPC_ARCH_BITS), ITE(ULT(VARL("mstart"), VARL("mstop")), SUB(VARL("mstop"), VARL("mstart")), ADD(VARL("mstop"), SUB(U8(PPC_ARCH_BITS), VARL("mstart")))))), \
		SETL("m", UA(0)), \
		REPEAT(EQ(VARL("count"), U8(0)), \
			SEQ3(SET_BIT("m", PPC_ARCH_BITS, VARL("mstart")), \
				SETL("mstart", ADD(MOD(VARL("mstart"), UA(1)), UA(PPC_ARCH_BITS))), \
				SETL("count", SUB(VARL("count"), U8(1))))))

RZ_IPI RzAnalysisILConfig *rz_ppc_cs_64_il_config(bool big_endian);
RZ_IPI RzAnalysisILConfig *rz_ppc_cs_32_il_config(bool big_endian);

RZ_IPI RzILOpEffect *rz_ppc_cs_get_il_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode);

RZ_OWN RzILOpEffect *set_carry_add_sub(RZ_OWN RzILOpBitVector *a, RZ_OWN RzILOpBitVector *b, cs_mode mode, bool add);
RZ_OWN RzILOpEffect *cmp_set_cr(RZ_BORROW RzILOpPure *left, RZ_BORROW RzILOpPure *right, const bool signed_cmp, const char *crX, const cs_mode mode);

bool ppc_is_x_form(ut32 insn_id);
ut32 ppc_get_mem_acc_size(ut32 insn_id);
bool ppc_updates_ra_with_ea(ut32 insn_id);
bool ppc_is_algebraic(ut32 insn_id);
bool ppc_sets_lr(ut32 insn_id);
bool ppc_is_conditional(ut32 insn_id);
bool ppc_moves_to_spr(ut32 insn_id);

bool ppc_decrements_ctr(RZ_BORROW cs_insn *insn, const cs_mode mode);
RZ_OWN RzILOpPure *ppc_get_branch_ta(RZ_BORROW cs_insn *insn, const cs_mode mode);
RZ_OWN RzILOpPure *ppc_get_branch_cond(RZ_BORROW cs_insn *insn, const cs_mode mode);

#endif /* PPC_IL_H */
