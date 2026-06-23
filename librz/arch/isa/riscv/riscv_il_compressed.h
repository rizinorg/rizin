// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef RISCV_IL_COMPRESSED_H
#define RISCV_IL_COMPRESSED_H

#include "riscv_il.h"

#define DECL_LIFTER(name) \
	RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size)

DECL_LIFTER(c_nop);
DECL_LIFTER(c_addi);
DECL_LIFTER(c_addi16sp);
DECL_LIFTER(c_addi4spn);
DECL_LIFTER(c_add);
DECL_LIFTER(c_andi);
DECL_LIFTER(c_slli);
DECL_LIFTER(c_srli);
DECL_LIFTER(c_srai);
DECL_LIFTER(c_or);
DECL_LIFTER(c_sub);
DECL_LIFTER(c_and);
DECL_LIFTER(c_xor);
DECL_LIFTER(c_addw);
DECL_LIFTER(c_addiw);
DECL_LIFTER(c_subw);
DECL_LIFTER(c_mv);
DECL_LIFTER(c_li);
DECL_LIFTER(c_jal);
DECL_LIFTER(c_j);
DECL_LIFTER(c_jr);
DECL_LIFTER(c_ebreak);
DECL_LIFTER(c_jalr);
DECL_LIFTER(c_lui);
DECL_LIFTER(c_sw);
DECL_LIFTER(c_swsp);
DECL_LIFTER(c_sd);
DECL_LIFTER(c_sdsp);
DECL_LIFTER(c_lwsp);
DECL_LIFTER(c_lw);
DECL_LIFTER(c_ld);
DECL_LIFTER(c_ldsp);
DECL_LIFTER(c_beqz);
DECL_LIFTER(c_bnez);

#undef DECL_LIFTER

#endif // RISCV_IL_COMPRESSED_H
