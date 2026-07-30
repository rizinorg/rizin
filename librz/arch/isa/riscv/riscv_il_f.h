// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef RISCV_IL_F_H
#define RISCV_IL_F_H

#include "riscv_il.h"

#ifndef DECL_LIFTER
#define DECL_LIFTER(name) \
	RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size)
#endif

DECL_LIFTER(flw);
DECL_LIFTER(fsw);

DECL_LIFTER(fadd_s);
DECL_LIFTER(fsub_s);
DECL_LIFTER(fmul_s);
DECL_LIFTER(fdiv_s);
DECL_LIFTER(fsqrt_s);

DECL_LIFTER(fmadd_s);
DECL_LIFTER(fmsub_s);
DECL_LIFTER(fnmadd_s);
DECL_LIFTER(fnmsub_s);

DECL_LIFTER(fsgnj_s);
DECL_LIFTER(fsgnjn_s);
DECL_LIFTER(fsgnjx_s);

DECL_LIFTER(fmin_s);
DECL_LIFTER(fmax_s);

DECL_LIFTER(feq_s);
DECL_LIFTER(flt_s);
DECL_LIFTER(fle_s);

DECL_LIFTER(fclass_s);

DECL_LIFTER(fcvt_w_s);
DECL_LIFTER(fcvt_wu_s);
DECL_LIFTER(fcvt_l_s);
DECL_LIFTER(fcvt_lu_s);

DECL_LIFTER(fcvt_s_w);
DECL_LIFTER(fcvt_s_wu);
DECL_LIFTER(fcvt_s_l);
DECL_LIFTER(fcvt_s_lu);

DECL_LIFTER(fmv_x_w);
DECL_LIFTER(fmv_w_x);

#endif // RISCV_IL_F_H
