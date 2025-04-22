// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef DISASSEMBLE_I4004_H
#define DISASSEMBLE_I4004_H

#include <rz_asm.h>
#include <rz_analysis.h>

int i4004dis(RzAsmOp *op, const ut8 *buf, int len);
int i4004_get_ins_len(ut8 hex);
int i4004_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask);

#endif /* DISASSEMBLE_I4004_H */
