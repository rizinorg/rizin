// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_asm.h>
#include <stdio.h>
#include <string.h>
#include "spc700_opcode_table.h"

static ut64 spc700_op_size(Spc700ArgType arg) {
	switch (arg) {
	case SPC700_ARG_NONE:
		return 1;
	case SPC700_ARG_IMM8:
	case SPC700_ARG_ABS8:
	case SPC700_ARG_REL8:
	case SPC700_ARG_UPPER8:
		return 2;
	case SPC700_ARG_ABS8_REL8:
	case SPC700_ARG_ABS8_ABS8:
	case SPC700_ARG_ABS16:
	case SPC700_ARG_ABS13_BIT3:
	case SPC700_ARG_IMM8_ABS8:
		return 3;
	}
	return 0;
}

static ut64 spc700_resolve_relative(ut64 pc, ut8 r) {
	ut16 spc = (ut16)pc;
	ut16 relpc = (ut16)(st16)(st8)r;
	spc += relpc;
	return (ut64)spc;
}

static size_t spc700_disas(RzStrBuf *out, ut64 pc, const ut8 *buf, size_t bufsz) {
	if (!bufsz) {
		return 0;
	}
	const Spc700Op *sop = &spc700_op_table[buf[0]];
	ut64 opsz = spc700_op_size(sop->arg);
	if (bufsz < (ut64)opsz) {
		return 0;
	}
	if (!out) {
		return opsz;
	}
	switch (sop->arg) {
	case SPC700_ARG_NONE:
		rz_strbuf_set(out, sop->name);
		break;
	case SPC700_ARG_IMM8:
	case SPC700_ARG_ABS8:
	case SPC700_ARG_UPPER8:
		rz_strbuf_setf(out, sop->name, (unsigned int)buf[1]);
		break;
	case SPC700_ARG_ABS8_REL8:
		rz_strbuf_setf(out, sop->name,
			(unsigned int)buf[1],
			(unsigned int)spc700_resolve_relative(pc + 3, buf[2]));
		break;
	case SPC700_ARG_ABS16:
		rz_strbuf_setf(out, sop->name, (unsigned int)buf[1] | ((unsigned int)buf[2] << 8));
		break;
	case SPC700_ARG_ABS13_BIT3:
		rz_strbuf_setf(out, sop->name,
			(unsigned int)((ut16)buf[1] | ((ut16)(buf[2] & 0x1f) << 8)),
			(unsigned int)(buf[2] >> 5));
		break;
	case SPC700_ARG_REL8:
		rz_strbuf_setf(out, sop->name,
			(unsigned int)spc700_resolve_relative(pc + 2, buf[1]));
		break;
	case SPC700_ARG_IMM8_ABS8:
	case SPC700_ARG_ABS8_ABS8:
		rz_strbuf_setf(out, sop->name, (unsigned int)buf[2], (unsigned int)buf[1]);
		break;
	default:
		rz_strbuf_set(out, "invalid");
		break;
	}
	return opsz;
}
