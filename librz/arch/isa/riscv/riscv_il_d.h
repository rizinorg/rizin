// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef RISCV_IL_D_H
#define RISCV_IL_D_H

#include "riscv_il.h"

#ifndef DECL_LIFTER
#define DECL_LIFTER(name) \
	RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size)
#endif

DECL_LIFTER(fld);
DECL_LIFTER(fsd);

DECL_LIFTER(fadd_d);
DECL_LIFTER(fsub_d);
DECL_LIFTER(fmul_d);
DECL_LIFTER(fdiv_d);
DECL_LIFTER(fsqrt_d);

DECL_LIFTER(fmadd_d);
DECL_LIFTER(fmsub_d);
DECL_LIFTER(fnmadd_d);
DECL_LIFTER(fnmsub_d);

DECL_LIFTER(fsgnj_d);
DECL_LIFTER(fsgnjn_d);
DECL_LIFTER(fsgnjx_d);

DECL_LIFTER(fmin_d);
DECL_LIFTER(fmax_d);

DECL_LIFTER(feq_d);
DECL_LIFTER(flt_d);
DECL_LIFTER(fle_d);

DECL_LIFTER(fclass_d);

DECL_LIFTER(fcvt_w_d);
DECL_LIFTER(fcvt_wu_d);
DECL_LIFTER(fcvt_l_d);
DECL_LIFTER(fcvt_lu_d);

DECL_LIFTER(fcvt_d_s);
DECL_LIFTER(fcvt_s_d);

DECL_LIFTER(fcvt_d_w);
DECL_LIFTER(fcvt_d_wu);
DECL_LIFTER(fcvt_d_l);
DECL_LIFTER(fcvt_d_lu);

DECL_LIFTER(fmv_x_d);
DECL_LIFTER(fmv_d_x);

#endif // RISCV_IL_D_H
