// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef MIPS_INTERNAL_H
#define MIPS_INTERNAL_H

#include <rz_asm.h>
#include <capstone/capstone.h>
#include <capstone/mips.h>

RZ_IPI int mips_assemble_opcode(const char *str, ut64 pc, ut8 *out);
RZ_IPI int analyze_op_esil(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn);

#endif /* MIPS_INTERNAL_H */
