// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2021 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_asm.h>

typedef struct {
	RzPVector /*<RzAsmTokenPattern *>*/ *token_patterns;
} BfContext;

static RZ_OWN RzPVector /*<RzAsmTokenPattern *>*/ *get_token_patterns(RzAsm *a) {
	BfContext *ctx = (BfContext *)a->plugin_data;
	RzPVector *pvec = ctx->token_patterns;
	if (pvec) {
		return pvec;
	}

	pvec = rz_pvector_new(rz_asm_token_pattern_free);

	// Patterns get added here.
	// Mnemonic pattern
	RzAsmTokenPattern *pat = RZ_NEW0(RzAsmTokenPattern);
	pat->type = RZ_ASM_TOKEN_MNEMONIC;
	pat->pattern = rz_str_dup(
		"^(while|inc|dec|out|in|trap|nop|invalid|loop)");
	rz_pvector_push(pvec, pat);

	// ptr pattern
	pat = RZ_NEW0(RzAsmTokenPattern);
	pat->type = RZ_ASM_TOKEN_REGISTER;
	pat->pattern = rz_str_dup(
		"ptr");
	rz_pvector_push(pvec, pat);

	// reference pattern
	pat = RZ_NEW0(RzAsmTokenPattern);
	pat->type = RZ_ASM_TOKEN_OPERATOR;
	pat->pattern = rz_str_dup(
		"\\[|\\]" // Matches a single bracket
	);
	rz_pvector_push(pvec, pat);

	// Separator pattern
	pat = RZ_NEW0(RzAsmTokenPattern);
	pat->type = RZ_ASM_TOKEN_SEPARATOR;
	pat->pattern = rz_str_dup(
		"\\s+");
	rz_pvector_push(pvec, pat);

	return pvec;
}

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	const char *buf_asm = "invalid";
	ut32 op_type;
	switch (*buf) {
	case '[':
		op_type = RZ_ANALYSIS_OP_TYPE_CJMP;
		buf_asm = "while [ptr]";
		break;
	case ']':
		op_type = RZ_ANALYSIS_OP_TYPE_UJMP;
		buf_asm = "loop";
		break;
	case '>':
		op_type = RZ_ANALYSIS_OP_TYPE_ADD;
		buf_asm = "inc ptr";
		break;
	case '<':
		op_type = RZ_ANALYSIS_OP_TYPE_SUB;
		buf_asm = "dec ptr";
		break;
	case '+':
		op_type = RZ_ANALYSIS_OP_TYPE_ADD;
		buf_asm = "inc [ptr]";
		break;
	case '-':
		op_type = RZ_ANALYSIS_OP_TYPE_SUB;
		buf_asm = "dec [ptr]";
		break;
	case ',':
		op_type = RZ_ANALYSIS_OP_TYPE_STORE;
		buf_asm = "in [ptr]";
		break;
	case '.':
		op_type = RZ_ANALYSIS_OP_TYPE_LOAD;
		buf_asm = "out [ptr]";
		break;
	case 0xff:
	case 0x00:
		op_type = RZ_ANALYSIS_OP_TYPE_TRAP;
		buf_asm = "trap";
		break;
	default:
		op_type = RZ_ANALYSIS_OP_TYPE_NOP;
		buf_asm = "nop";
		break;
	}

	rz_strbuf_set(&op->buf_asm, buf_asm);

	RzPVector *token_patterns = get_token_patterns(a);
	op->asm_toks = rz_asm_tokenize_asm_regex(&op->buf_asm, token_patterns);
	op->asm_toks->op_type = op_type;

	op->size = 1;
	return op->size;
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

static bool bf_init(void **user) {
	BfContext *ctx = RZ_NEW0(BfContext);
	rz_return_val_if_fail(ctx, false);
	ctx->token_patterns = NULL;
	*user = ctx;
	return true;
}

static bool bf_fini(void *user) {
	BfContext *ctx = (BfContext *)user;
	if (ctx) {
		rz_pvector_free(ctx->token_patterns);
		RZ_FREE(ctx);
	}
	return true;
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
	.init = bf_init,
	.fini = bf_fini,
	.disassemble = &disassemble,
	.assemble = &assemble
};
