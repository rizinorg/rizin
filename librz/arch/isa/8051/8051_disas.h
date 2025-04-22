// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef DISASSEMBLE_8051_H
#define DISASSEMBLE_8051_H

#include <rz_asm.h>

char *rz_8051_disas(ut64 pc, const ut8 *buf, int len, int *olen);

#endif /* DISASSEMBLE_8051_H */
