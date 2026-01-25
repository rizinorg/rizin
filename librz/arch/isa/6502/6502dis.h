// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef DISASSEMBLE_6502_H
#define DISASSEMBLE_6502_H

typedef struct {
	RzConfig *cfg;
} _6502State;

_6502State *_6502_state_new();
int disass_6502(ut64 pc, RzAsmOp *op, const ut8 *buf, ut64 len);

#endif /* DISASSEMBLE_6502_H */
