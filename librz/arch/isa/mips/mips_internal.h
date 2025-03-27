// SPDX-FileCopyrightText: 2024-2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef MIPS_INTERNAL_H
#define MIPS_INTERNAL_H

#include <rz_arch.h>
#include <capstone/capstone.h>
#include <capstone/mips.h>

#define OPERAND(x)   insn->detail->mips.operands[x]
#define REGID(x)     insn->detail->mips.operands[x].reg
#define IS_REG(x)    (insn->detail->mips.operands[x].type == MIPS_OP_REG)
#define REG(x)       cs_reg_name(*handle, insn->detail->mips.operands[x].reg)
#define IS_IMM(x)    (insn->detail->mips.operands[x].type == MIPS_OP_IMM)
#define IMM(x)       insn->detail->mips.operands[x].imm
#define IS_MEM(x)    (insn->detail->mips.operands[x].type == MIPS_OP_MEM)
#define MEMBASE(x)   cs_reg_name(*handle, insn->detail->mips.operands[x].mem.base)
#define MEMOFFSET(x) (st64) insn->detail->mips.operands[x].mem.disp
#define OPCOUNT()    insn->detail->mips.op_count

RZ_IPI RzILOpEffect *mips_il(RZ_NONNULL const csh *handle, RZ_NONNULL const cs_insn *insn, const ut32 gprlen);
RZ_IPI RzAnalysisILConfig *mips_il_config(RzAnalysis *analysis);
RZ_IPI int mips_assemble_opcode(const char *line, ut64 pc, RzStrBuf *out, bool be);
RZ_IPI int analyze_op_esil(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn);

#endif /* MIPS_INTERNAL_H */
