// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RIZIN_XTENSA_H
#define RIZIN_XTENSA_H

#include <capstone/capstone.h>
#include <rz_asm.h>

typedef struct xtensa_context_t {
	csh handle;
	cs_insn *insn;
	size_t count;
} XtensaContext;

bool xtensa_init(void **user);
bool xtensa_fini(void *user);
bool xtensa_open(XtensaContext *ctx, const char *cpu, bool big_endian);
bool xtensa_disassemble(XtensaContext *self, const ut8 *buf, int len, ut64 addr);
void xtensa_disassemble_fini(XtensaContext *self);
void xtensa_analyze_op_esil(XtensaContext *ctx, RzAnalysisOp *op);

static inline cs_xtensa_op_mem *xtensa_op_mem(cs_insn *insn, unsigned int index) {
	cs_xtensa_op *op = &insn->detail->xtensa.operands[index];
	rz_warn_if_fail(op->type == XTENSA_OP_MEM);
	return &op->mem;
}

static inline xtensa_reg xtensa_op_reg(cs_insn *insn, unsigned int index) {
	cs_xtensa_op *op = &insn->detail->xtensa.operands[index];
	rz_warn_if_fail(op->type == XTENSA_OP_REG);
	return op->reg;
}

static inline int32_t xtensa_op_imm(cs_insn *insn, unsigned int index) {
	cs_xtensa_op *op = &insn->detail->xtensa.operands[index];
	rz_warn_if_fail(op->type == XTENSA_OP_IMM);
	return op->imm;
}

static inline int32_t xtensa_op_l32r(cs_insn *insn, unsigned int index) {
	cs_xtensa_op *op = &insn->detail->xtensa.operands[index];
	rz_warn_if_fail(op->type == XTENSA_OP_L32R);
	return op->imm;
}

#define REG(I)  cs_reg_name(ctx->handle, I)
#define MEM(I)  xtensa_op_mem(ctx->insn, I)
#define REGO(I) REG(xtensa_op_reg(ctx->insn, I))
#define IMM(I)  xtensa_op_imm(ctx->insn, I)
#define L32R(I) xtensa_op_l32r(ctx->insn, I)

#endif // RIZIN_XTENSA_H
