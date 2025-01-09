// SPDX-FileCopyrightText: 2024-2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef MIPS_INTERNAL_H
#define MIPS_INTERNAL_H

#include <rz_arch.h>
#include <capstone/capstone.h>
#include <capstone/mips.h>

#define OPERAND(x)  insn->detail->mips.operands[x]
#define REGID(x)    insn->detail->mips.operands[x].reg
#define REG(x)      cs_reg_name(*handle, insn->detail->mips.operands[x].reg)
#define IMM(x)      insn->detail->mips.operands[x].imm
#define MEMBASE(x)  cs_reg_name(*handle, insn->detail->mips.operands[x].mem.base)
#define MEMINDEX(x) insn->detail->mips.operands[x].mem.index
#define MEMDISP(x)  insn->detail->mips.operands[x].mem.disp
#define OPCOUNT()   insn->detail->mips.op_count

RZ_IPI RzILOpEffect *mips_il(RZ_NONNULL cs_insn *insn);
RZ_IPI RzAnalysisILConfig *mips_il_config();
RZ_IPI int mips_assemble_opcode(const char *str, ut64 pc, ut8 *out);
RZ_IPI int analyze_op_esil(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn);

#endif /* MIPS_INTERNAL_H */
