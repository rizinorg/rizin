// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2021 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	const ut8 *b;
	int rep = 1;

	/* Count repetitions of the current instruction, unless it's a trap. */
	if (*buf != 0x00 && *buf != 0xff) {
		for (b = &buf[1]; b < buf + len && *b == *buf; b++) {
			rep++;
		}
	}
	const char *buf_asm = "invalid";
	switch (*buf) {
	case '[':
		buf_asm = "while [ptr]";
		break;
	case ']':
		buf_asm = "loop";
		break;
	case '>':
		buf_asm = (rep > 1) ? "add ptr" : "inc ptr";
		break;
	case '<':
		buf_asm = (rep > 1) ? "sub ptr" : "dec ptr";
		break;
	case '+':
		buf_asm = (rep > 1) ? "add [ptr]" : "inc [ptr]";
		break;
	case '-':
		buf_asm = (rep > 1) ? "sub [ptr]" : "dec [ptr]";
		break;
	case ',':
		buf_asm = "in [ptr]";
		break;
	case '.':
		buf_asm = "out [ptr]";
		break;
	case 0xff:
	case 0x00:
		buf_asm = "trap";
		break;
	default:
		buf_asm = "nop";
		break;
	}

	if (rep > 1) {
		/* Note: snprintf's source and destination buffers may not
		* overlap. */
		const char *fmt = strchr(buf_asm, ' ') ? "%s, %d" : "%s %d";
		buf_asm = sdb_fmt(fmt, buf_asm, rep);
	}
	rz_strbuf_set(&op->buf_asm, buf_asm);
	op->size = rep;
	return rep;
}

static bool _write_asm(RzAsmOp *op, int value, int n) {
	ut8 *opbuf = malloc(n);
	if (opbuf == NULL) {
		return true;
	}
	memset(opbuf, value, n);
	rz_strbuf_setbin(&op->buf, opbuf, n);
	free(opbuf);
	return false;
}

static int assemble(RzAsm *a, RzAsmOp *op, const char *buf) {
	int n = 0;
	if (buf[0] && buf[1] == ' ') {
		buf += 2;
	}
	const char *arg = strchr(buf, ',');
	const char *ref = strchr(buf, '[');
	bool write_err = false;
	if (arg) {
		n = atoi(arg + 1);
	} else {
		n = 1;
	}
	if (!strncmp(buf, "trap", 4)) {
		write_err = _write_asm(op, 0xcc, n);
	} else if (!strncmp(buf, "nop", 3)) {
		write_err = _write_asm(op, 0x90, n);
	} else if (!strncmp(buf, "inc", 3)) {
		char ch = ref ? '+' : '>';
		n = 1;
		write_err = _write_asm(op, ch, n);
	} else if (!strncmp(buf, "dec", 3)) {
		char ch = ref ? '-' : '<';
		n = 1;
		write_err = _write_asm(op, ch, n);
	} else if (!strncmp(buf, "sub", 3)) {
		char ch = ref ? '-' : '<';
		write_err = _write_asm(op, ch, n);
	} else if (!strncmp(buf, "add", 3)) {
		char ch = ref ? '+' : '>';
		write_err = _write_asm(op, ch, n);
	} else if (!strncmp(buf, "while", 5)) {
		n = 1;
		write_err = _write_asm(op, '[', 1);
	} else if (!strncmp(buf, "loop", 4)) {
		n = 1;
		write_err = _write_asm(op, ']', 1);
	} else if (!strncmp(buf, "in", 2)) {
		write_err = _write_asm(op, ',', n);
	} else if (!strncmp(buf, "out", 3)) {
		write_err = _write_asm(op, '.', n);
	} else {
		n = 0;
	}
	if (write_err) {
		return 0;
	}
	return n;
}

RzAsmPlugin rz_asm_plugin_bf = {
	.name = "bf",
	.author = "pancake, nibble",
	.version = "4.0.0",
	.arch = "bf",
	.license = "LGPL3",
	.bits = 16 | 32 | 64,
	.endian = RZ_SYS_ENDIAN_NONE,
	.desc = "Brainfuck",
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_bf,
	.version = RZ_VERSION
};
#endif
