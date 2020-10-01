/* radare - LGPL - Copyright 2009-2019 - pancake, nibble */

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
		buf_asm = (rep > 1)? "add ptr": "inc ptr";
		break;
	case '<':
		buf_asm = (rep > 1)? "sub ptr": "dec ptr";
		break;
	case '+':
		buf_asm = (rep > 1)? "add [ptr]": "inc [ptr]";
		break;
	case '-':
		buf_asm = (rep > 1)? "sub [ptr]": "dec [ptr]";
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
		const char *fmt = strchr (buf_asm, ' ')? "%s, %d": "%s %d";
		buf_asm = sdb_fmt (fmt, buf_asm, rep);
	}
	rz_strbuf_set (&op->buf_asm, buf_asm);
	op->size = rep;
	return rep;
}

static int assemble(RzAsm *a, RzAsmOp *op, const char *buf) {
	int n = 0;
	if (buf[0] && buf[1] == ' ') {
		buf += 2;
	}
	const char *arg = strchr (buf, ',');
	const char *ref = strchr (buf, '[');
	ut8 opbuf[32];
	if (!strncmp (buf, "trap", 4)) {
		if (arg) {
			n = atoi (arg + 1);
			memset (opbuf, 0xcc, n);
		} else {
			opbuf[0] = 0x90;
			n = 1;
		}
	} else if (!strncmp (buf, "nop", 3))        {
		if (arg) {
			n = atoi (arg + 1);
			memset (opbuf, 0x90, n);
		} else {
			opbuf[0] = 0x90;
			n = 1;
		}
	} else if (!strncmp (buf, "inc", 3))        {
		char ch = ref? '+': '>';
		opbuf[0] = ch;
		n = 1;
	} else if (!strncmp (buf, "dec", 3))        {
		char ch = ref? '-': '<';
		opbuf[0] = ch;
		n = 1;
	} else if (!strncmp (buf, "sub", 3))        {
		char ch = ref? '-': '<';
		if (arg) {
			n = atoi (arg + 1);
			memset (opbuf, ch, n);
		} else {
			opbuf[0] = '<';
			n = 1;
		}
	} else if (!strncmp (buf, "add", 3))        {
		char ch = ref? '+': '>';
		if (arg) {
			n = atoi (arg + 1);
			memset (opbuf, ch, n);
		} else {
			opbuf[0] = '<';
			n = 1;
		}
	} else if (!strncmp (buf, "while", 5))        {
		opbuf[0] = '[';
		n = 1;
	} else if (!strncmp (buf, "loop", 4))        {
		opbuf[0] = ']';
		n = 1;
	} else if (!strncmp (buf, "in", 2))        {
		if (arg) {
			n = atoi (arg + 1);
			memset (opbuf, ',', n);
		} else {
			opbuf[0] = ',';
			n = 1;
		}
	} else if (!strncmp (buf, "out", 3))        {
		if (arg) {
			n = atoi (arg + 1);
			memset (opbuf, '.', n);
		} else {
			opbuf[0] = '.';
			n = 1;
		}
	}
	rz_strbuf_setbin (&op->buf, opbuf, n);
	return n;
}

RzAsmPlugin rz_asm_plugin_bf = {
	.name = "bf",
	.author = "pancake, nibble",
	.version = "4.0.0",
	.arch = "bf",
	.license = "LGPL3",
	.bits = 16 | 32 | 64,
	.endian = R_SYS_ENDIAN_NONE,
	.desc = "Brainfuck",
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_bf,
	.version = R2_VERSION
};
#endif
