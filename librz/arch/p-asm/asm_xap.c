// SPDX-FileCopyrightText: 2009-2014 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>
#include "xap/dis.c"

static int arch_xap_disasm(char *str, const unsigned char *buf, ut64 seek) {
	struct state *s = get_state();
	struct directive *d;
	memset(s, 0, sizeof(*s));
	s->s_buf = buf;
	s->s_off = seek;
	s->s_out = NULL;
	d = next_inst(s);
	if (d != NULL) {
		xap_decode(s, d);
		strcpy(str, d->d_asm);
		free(d);
	} else {
		*str = '\0';
	}
#if 0
	if (s->s_ff_quirk) {
		sprintf(d->d_asm, "DC\t0x%x", i2u16(&d->d_inst));
		s->s_ff_quirk = 0;
	}
#endif
	return 0;
}
static int disassemble(RzAsm *a, struct rz_asm_op_t *op, const ut8 *buf, int len) {
	char *buf_asm = rz_strbuf_get(&op->buf_asm);
	arch_xap_disasm(buf_asm, buf, a->pc);
	return (op->size = 2);
}

RzAsmPlugin rz_asm_plugin_xap = {
	.name = "xap",
	.arch = "xap",
	.license = "PD",
	.bits = 16,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.desc = "XAP4 RISC (CSR)",
	.disassemble = &disassemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_xap,
	.version = RZ_VERSION
};
#endif
