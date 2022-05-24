// SPDX-FileCopyrightText: 2022 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PPC_IL_H
#define PPC_IL_H

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

// Rotate x left by y bits
#define ROTL64(x, y) (NOP)
// Rotates a 32bit value. If the the VM is in 64bit mode "ROTL64(x||x, y)" is executed instead.
#define ROTL32(x, y) (IN_64BIT_MODE ? ROTL64(APPEND(x, x), y) : NOP)

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
