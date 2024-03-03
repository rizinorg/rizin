// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>

#include "../arch/avr/assembler.h"
#include "../arch/avr/disassembler.h"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	AVROp aop = { 0 };
	op->size = avr_disassembler(buf, len, a->pc, a->big_endian, &aop, &op->buf_asm);
	if (!op->size) {
		op->size = 2;
		rz_strbuf_set(&op->buf_asm, "invalid");
	}
	return op->size;
}

static int assemble(RzAsm *a, RzAsmOp *ao, const char *str) {
	st32 slen = strlen(str);

	ut8 buffer[16];
	ut32 written = avr_assembler(str, slen, buffer, sizeof(buffer), a->pc, a->big_endian);

	if (written < 1) {
		return -1;
	}

	rz_strbuf_setbin(&ao->buf, (const ut8 *)&buffer, written);
	return (int)written;
}

RzAsmPlugin rz_asm_plugin_avr = {
	.name = "avr",
	.arch = "avr",
	.license = "LGPL3",
	.bits = 8 | 16,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.desc = "AVR Atmel",
	.disassemble = &disassemble,
	.assemble = &assemble,
	.cpus =
		"ATmega8,"
		"ATmega1280,"
		"ATmega1281,"
		"ATmega16,"
		"ATmega168,"
		"ATmega2560,"
		"ATmega2561,"
		"ATmega328p,"
		"ATmega32u4,"
		"ATmega48,"
		"ATmega640,"
		"ATmega88,"
		"ATxmega128a4u,"
		"ATTiny48,"
		"ATTiny88,"
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_avr,
	.version = RZ_VERSION
};
#endif
