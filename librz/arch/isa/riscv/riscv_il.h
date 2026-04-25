// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef RZ_ARCH_ISA_RISCV_IL_H
#define RZ_ARCH_ISA_RISCV_IL_H

#include <capstone/capstone.h>
#include <capstone/riscv.h>

#include <rz_types.h>
#include <rz_analysis.h>
typedef RzILOpEffect *(*RiscvInstructionLifter)(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, int size);

RZ_OWN RZ_IPI RzILOpEffect *
rz_riscv_lift_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, int size);

RZ_IPI RzAnalysisILConfig *rz_riscv_il_config(RZ_NONNULL RzAnalysis *analysis);

#endif