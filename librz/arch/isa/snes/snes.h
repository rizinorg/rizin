// SPDX-FileCopyrightText: 2012-2015 condret <condr3t@protonmail.com>
// SPDX-FileCopyrightText: 2012-2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef SNES_H
#define SNES_H
#include <rz_asm.h>

struct snes_asm_flags {
	unsigned char M;
	unsigned char X;
};

int snesDisass(int M_flag, int X_flag, ut64 pc, RzAsmOp *op, const ut8 *buf, int len);

#endif /* SNES_H */
