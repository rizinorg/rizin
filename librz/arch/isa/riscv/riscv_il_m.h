// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef RISCV_IL_M_H
#define RISCV_IL_M_H

#include "riscv_il.h"

#define DECL_LIFTER(name) \
	RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size)

DECL_LIFTER(mul);
DECL_LIFTER(mulh);
DECL_LIFTER(mulhsu);
DECL_LIFTER(mulhu);
DECL_LIFTER(div);
DECL_LIFTER(divu);
DECL_LIFTER(rem);
DECL_LIFTER(remu);
DECL_LIFTER(mulw);
DECL_LIFTER(divw);
DECL_LIFTER(divuw);
DECL_LIFTER(remw);
DECL_LIFTER(remuw);

#undef DECL_LIFTER

#endif // RISCV_IL_M_H
