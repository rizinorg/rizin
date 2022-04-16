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

#define UA(i)        (IN_64BIT_MODE ? U64(i) : U32(i))
#define SA(i)        (IN_64BIT_MODE ? S64(i) : S32(i))
#define IMM_U(i)     UA(i)
#define IMM_S(i)     SA(i)
#define IMM_UN(n, v) UN(n, v)
#define IMM_SN(n, v) SN(n, v)

#define NOT_IMPLEMENTED \
	do { \
		RZ_LOG_INFO("IL instruction not implemented."); \
		return NOP; \
	} while (0)

#define EXTEND(n, v) ITE(MSB(v), SIGNED(n, DUP(v)), UNSIGNED(n, DUP(v)))

RZ_IPI RzAnalysisILConfig *rz_ppc_cs_64_il_config(bool big_endian);
RZ_IPI RzAnalysisILConfig *rz_ppc_cs_32_il_config(bool big_endian);

RZ_IPI RzILOpEffect *rz_ppc_cs_get_il_op(RZ_BORROW csh handle, RZ_BORROW cs_insn *insn, const cs_mode mode);

RZ_OWN RzILOpEffect *set_carry_add_sub(RZ_OWN RzILOpBitVector *a, RZ_OWN RzILOpBitVector *b, cs_mode mode, bool add);
RZ_OWN RzILOpEffect *set_cr0(RZ_NONNULL RZ_BORROW RzILOpPure *val);

#endif /* PPC_IL_H */
