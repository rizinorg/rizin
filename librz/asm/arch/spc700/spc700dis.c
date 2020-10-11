/* radare - LGPL - Copyright 2014 - condret@runas-racer.com */

#include <rz_types.h>
#include <rz_asm.h>
#include <stdio.h>
#include <string.h>
#include "spc700_opcode_table.h"

static ut64 spc700_op_size(int spcoptype) {
	switch(spcoptype) {
	case SPC_OP:
		return 1;
	case SPC_ARG8_1:
		return 2;
	case SPC_ARG8_2:
	case SPC_ARG16:
		return 3;
	}
	return 0;
}

static size_t spc700_disas(RzAsmOp *op, const ut8 *buf, size_t bufsz) {
	if (!bufsz) {
		return 0;
	}
	const Spc700Op *sop = &spc700_op_table[buf[0]];
	ut64 opsz = spc700_op_size (sop->type);
	if (bufsz < (ut64)opsz) {
		return 0;
	}
	switch (sop->type) {
	case SPC_OP:
		rz_strbuf_set (&op->buf_asm, sop->name);
		break;
	case SPC_ARG8_1:
		rz_strbuf_setf (&op->buf_asm, sop->name, (unsigned int)buf[1]);
		break;
	case SPC_ARG8_2:
		rz_strbuf_setf (&op->buf_asm, sop->name, (unsigned int)buf[2], (unsigned int)buf[1]);
		break;
	case SPC_ARG16:
		rz_strbuf_setf (&op->buf_asm, sop->name, (unsigned int)buf[1] + ((unsigned int)buf[2] << 8));
		break;
	default:
		rz_strbuf_set (&op->buf_asm, "invalid");
		break;
	}
	return opsz;
}
