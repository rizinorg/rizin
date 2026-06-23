// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef RISCV_IL_INTEGER_H
#define RISCV_IL_INTEGER_H

#include "riscv_il.h"

#define DECL_LIFTER(name) \
	RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size)

DECL_LIFTER(addi);
DECL_LIFTER(slli);
DECL_LIFTER(andi);
DECL_LIFTER(ori);
DECL_LIFTER(xori);
DECL_LIFTER(slti);
DECL_LIFTER(sltiu);
DECL_LIFTER(srli);
DECL_LIFTER(srai);

DECL_LIFTER(add);
DECL_LIFTER(sub);
DECL_LIFTER(and);
DECL_LIFTER(or);
DECL_LIFTER(xor);
DECL_LIFTER(slt);
DECL_LIFTER(sltu);
DECL_LIFTER(sll);
DECL_LIFTER(srl);
DECL_LIFTER(sra);

DECL_LIFTER(beq);
DECL_LIFTER(bne);
DECL_LIFTER(blt);
DECL_LIFTER(bge);
DECL_LIFTER(bltu);
DECL_LIFTER(bgeu);

DECL_LIFTER(jal);
DECL_LIFTER(jalr);

DECL_LIFTER(lui);
DECL_LIFTER(auipc);

DECL_LIFTER(sb);
DECL_LIFTER(sh);
DECL_LIFTER(sw);
DECL_LIFTER(sd);

DECL_LIFTER(lw);
DECL_LIFTER(lb);
DECL_LIFTER(lh);
DECL_LIFTER(lbu);
DECL_LIFTER(lhu);
DECL_LIFTER(ld);

DECL_LIFTER(fence);
DECL_LIFTER(fence_i);

DECL_LIFTER(addw);
DECL_LIFTER(subw);
DECL_LIFTER(sllw);
DECL_LIFTER(srlw);
DECL_LIFTER(sraw);
DECL_LIFTER(addiw);
DECL_LIFTER(slliw);
DECL_LIFTER(srliw);
DECL_LIFTER(sraiw);

DECL_LIFTER(lwu);
DECL_LIFTER(ecall);
DECL_LIFTER(ebreak);

#undef DECL_LIFTER

#endif // RISCV_IL_INTEGER_H
