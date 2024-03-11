// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef DISASSEMBLE_6502_H
#define DISASSEMBLE_6502_H

#include <rz_asm.h>

int disass_6502(ut64 pc, RzAsmOp *op, const ut8 *buf, ut64 len);

#endif /* DISASSEMBLE_6502_H */
