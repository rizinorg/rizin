// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef TMS320_C64X_CAPSTONE_H
#define TMS320_C64X_CAPSTONE_H

#include <rz_asm.h>
#include <rz_util.h>
#include <rz_analysis.h>
#include <capstone/capstone.h>

#ifdef CAPSTONE_TMS320C64X_H

void *tms320_c64x_new();
void tms320_c64x_free(void *p);
int tms320_c64x_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len, void *c64x);
char *tms320_c64x_mnemonics(RzAsm *a, int id, bool json, void *c64x);
int tms320_c64x_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask, void *c64x);

#else

/**
 * The supplied capstone (4 or lower) does not have
 * commit ae6f2d141118680a04a949b31e9e82e7b70f10b8
 * https://github.com/capstone-engine/capstone/commit/ae6f2d141118680a04a949b31e9e82e7b70f10b8
 */

#warning Capstone does not support tms320c64x

#define tms320_c64x_new() (NULL)
#define tms320_c64x_free(x)
#define tms320_c64x_disassemble(a, op, buf, len, c64x)   (-1)
#define tms320_c64x_mnemonics(a, id, json, c64x)         (NULL)
#define tms320_c64x_op(a, op, addr, buf, le, mask, c64x) (-1)

#endif /* CAPSTONE_TMS320C64X_H */

#endif /* TMS320_C64X_CAPSTONE_H */
