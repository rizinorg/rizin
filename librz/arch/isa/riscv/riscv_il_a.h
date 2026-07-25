// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef RISCV_IL_A_H
#define RISCV_IL_A_H

#include "riscv_il.h"

#define DECL_LIFTER(name) \
	RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size)

DECL_LIFTER(lr_w);
DECL_LIFTER(lr_w_aq);
DECL_LIFTER(lr_w_rl);
DECL_LIFTER(lr_w_aqrl);
DECL_LIFTER(lr_d);
DECL_LIFTER(lr_d_aq);
DECL_LIFTER(lr_d_rl);
DECL_LIFTER(lr_d_aqrl);
DECL_LIFTER(sc_w);
DECL_LIFTER(sc_w_aq);
DECL_LIFTER(sc_w_rl);
DECL_LIFTER(sc_w_aqrl);
DECL_LIFTER(sc_d);
DECL_LIFTER(sc_d_aq);
DECL_LIFTER(sc_d_rl);
DECL_LIFTER(sc_d_aqrl);
DECL_LIFTER(amoswap_w);
DECL_LIFTER(amoswap_w_aq);
DECL_LIFTER(amoswap_w_rl);
DECL_LIFTER(amoswap_w_aqrl);
DECL_LIFTER(amoswap_d);
DECL_LIFTER(amoswap_d_aq);
DECL_LIFTER(amoswap_d_rl);
DECL_LIFTER(amoswap_d_aqrl);
DECL_LIFTER(amoadd_w);
DECL_LIFTER(amoadd_w_aq);
DECL_LIFTER(amoadd_w_rl);
DECL_LIFTER(amoadd_w_aqrl);
DECL_LIFTER(amoadd_d);
DECL_LIFTER(amoadd_d_aq);
DECL_LIFTER(amoadd_d_rl);
DECL_LIFTER(amoadd_d_aqrl);
DECL_LIFTER(amoxor_w);
DECL_LIFTER(amoxor_w_aq);
DECL_LIFTER(amoxor_w_rl);
DECL_LIFTER(amoxor_w_aqrl);
DECL_LIFTER(amoxor_d);
DECL_LIFTER(amoxor_d_aq);
DECL_LIFTER(amoxor_d_rl);
DECL_LIFTER(amoxor_d_aqrl);
DECL_LIFTER(amoand_w);
DECL_LIFTER(amoand_w_aq);
DECL_LIFTER(amoand_w_rl);
DECL_LIFTER(amoand_w_aqrl);
DECL_LIFTER(amoand_d);
DECL_LIFTER(amoand_d_aq);
DECL_LIFTER(amoand_d_rl);
DECL_LIFTER(amoand_d_aqrl);
DECL_LIFTER(amoor_w);
DECL_LIFTER(amoor_w_aq);
DECL_LIFTER(amoor_w_rl);
DECL_LIFTER(amoor_w_aqrl);
DECL_LIFTER(amoor_d);
DECL_LIFTER(amoor_d_aq);
DECL_LIFTER(amoor_d_rl);
DECL_LIFTER(amoor_d_aqrl);
DECL_LIFTER(amomin_w);
DECL_LIFTER(amomin_w_aq);
DECL_LIFTER(amomin_w_rl);
DECL_LIFTER(amomin_w_aqrl);
DECL_LIFTER(amomin_d);
DECL_LIFTER(amomin_d_aq);
DECL_LIFTER(amomin_d_rl);
DECL_LIFTER(amomin_d_aqrl);
DECL_LIFTER(amomax_w);
DECL_LIFTER(amomax_w_aq);
DECL_LIFTER(amomax_w_rl);
DECL_LIFTER(amomax_w_aqrl);
DECL_LIFTER(amomax_d);
DECL_LIFTER(amomax_d_aq);
DECL_LIFTER(amomax_d_rl);
DECL_LIFTER(amomax_d_aqrl);
DECL_LIFTER(amominu_w);
DECL_LIFTER(amominu_w_aq);
DECL_LIFTER(amominu_w_rl);
DECL_LIFTER(amominu_w_aqrl);
DECL_LIFTER(amominu_d);
DECL_LIFTER(amominu_d_aq);
DECL_LIFTER(amominu_d_rl);
DECL_LIFTER(amominu_d_aqrl);
DECL_LIFTER(amomaxu_w);
DECL_LIFTER(amomaxu_w_aq);
DECL_LIFTER(amomaxu_w_rl);
DECL_LIFTER(amomaxu_w_aqrl);
DECL_LIFTER(amomaxu_d);
DECL_LIFTER(amomaxu_d_aq);
DECL_LIFTER(amomaxu_d_rl);
DECL_LIFTER(amomaxu_d_aqrl);

#undef DECL_LIFTER

#endif // RISCV_IL_A_H
