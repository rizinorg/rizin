// SPDX-FileCopyrightText: 2022 wingdeans <wingdeans@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CIL_ASM_H
#define CIL_ASM_H

#include <rz_util/rz_strbuf.h>

// eg. OPCODE_SINGLE(CIL_OP_NOP, "nop", InlineNone, 0x00, NEXT)
// ->
// enum {
//   OPCODE_SINGLE = 0x00,
//   ...
// }
#define OPCODE_SINGLE(name, str, param, byte, control) name = byte,
#define OPCODE_DOUBLE(name, str, param, byte, control) name = byte,
#define OPCODE_PREFIX(name, str, param, byte, control) name = byte,
enum {
#include "opcodes_single.def"
#include "opcodes_double.def"
#include "opcodes_prefix.def"
};
#undef OPCODE_SINGLE
#undef OPCODE_DOUBLE
#undef OPCODE_PREFIX

typedef struct {
	RzStrBuf strbuf;
	int size;
	ut8 byte1;
	ut8 byte2;
	union {
		ut32 tok;
		st32 target;
	};
} CILOp;

int cil_dis(CILOp *op, const ut8 *buf, int len);
#endif
