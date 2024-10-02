// SPDX-FileCopyrightText: 2009-2014 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>

static int arch_xap_disasm(RzStrBuf *asm_buf, const unsigned char *buf, ut64 seek) {
	xap_state_t s = { 0 };
	xap_directive_t d = { 0 };
	s.s_buf = buf;
	s.s_off = seek;
	d.d_asm = asm_buf;
	if (xap_read_instruction(&s, &d) > 0) {
		xap_decode(&s, &d);
	}
#if 0
	if (s->s_ff_quirk) {
		sprintf(d->d_asm, "DC\t0x%x", i2u16(&d->d_inst));
		s->s_ff_quirk = 0;
	}
#endif
	return 0;
}
static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	arch_xap_disasm(&op->buf_asm, buf, a->pc);
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
