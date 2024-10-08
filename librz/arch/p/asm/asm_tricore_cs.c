// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <capstone/capstone.h>

#define TRICORE_LONGEST_INSTRUCTION  4
#define TRICORE_SHORTEST_INSTRUCTION 2

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	if (!buf || len < TRICORE_SHORTEST_INSTRUCTION || !a->plugin_data) {
		return -1;
	}

	RzAsmTriCoreContext *ctx = a->plugin_data;
	if (!tricore_setup_cs_handle(ctx, a->cpu, a->features)) {
		return -1;
	}

	ctx->insn = NULL;
	ctx->count = cs_disasm(ctx->h, buf, len, a->pc, 1, &ctx->insn);
	if (ctx->count <= 0) {
		goto beach;
	}

	op->size = ctx->insn->size;
	rz_asm_op_setf_asm(op, "%s%s%s",
		ctx->insn->mnemonic, RZ_STR_ISNOTEMPTY(ctx->insn->op_str) ? " " : "", ctx->insn->op_str);

	op->asm_toks = rz_asm_tokenize_asm_regex(&op->buf_asm, ctx->token_patterns);

beach:
	cs_free(ctx->insn, ctx->count);
	ctx->insn = NULL;
	ctx->count = 0;
	return op->size;
}

#define TOKEN(_type, _pat) \
	do { \
		RzAsmTokenPattern *pat = RZ_NEW0(RzAsmTokenPattern); \
		pat->type = RZ_ASM_TOKEN_##_type; \
		pat->pattern = rz_str_dup(_pat); \
		rz_pvector_push(pvec, pat); \
	} while (0)

static RZ_OWN RzPVector /*<RzAsmTokenPattern *>*/ *get_token_patterns() {
	RzPVector *pvec = rz_pvector_new(rz_asm_token_pattern_free);
	if (!pvec) {
		return NULL;
	}

	TOKEN(META, "(\\[|\\]|-)");
	TOKEN(META, "(\\+[rc]?)");

	TOKEN(NUMBER, "(0x[[:digit:]abcdef]+)");

	TOKEN(REGISTER, "([adep][[:digit:]]{1,2})|(sp|psw|pcxi|pc|fcx|lcx|isp|icr|pipn|biv|btv)");

	TOKEN(MNEMONIC, "([[:alpha:]]+[[:alnum:]\\.]*[[:alnum:]]+)|([[:alpha:]]+)");

	TOKEN(SEPARATOR, "([[:blank:]]+)|([,;#\\(\\)\\{\\}:])");

	TOKEN(NUMBER, "([[:digit:]]+)");

	return pvec;
}

static bool init(void **u) {
	if (!u) {
		return false;
	}
	// u = RzAsm.plugin_data
	RzAsmTriCoreContext *ctx = NULL;
	if (*u) {
		rz_mem_memzero(*u, sizeof(RzAsmTriCoreContext));
		ctx = *u;
	} else {
		ctx = RZ_NEW0(RzAsmTriCoreContext);
		if (!ctx) {
			return false;
		}
		*u = ctx;
	}
	ctx->token_patterns = get_token_patterns();
	rz_asm_compile_token_patterns(ctx->token_patterns);
	return true;
}

static bool fini(void *u) {
	if (!u) {
		return true;
	}
	RzAsmTriCoreContext *ctx = u;
	cs_close(&ctx->h);
	rz_pvector_free(ctx->token_patterns);
	free(u);
	return true;
}

RzAsmPlugin rz_asm_plugin_tricore_cs = {
	.name = "tricore",
	.arch = "tricore",
	.cpus = "tricore",
	.author = "billow",
	.license = "BSD",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.desc = "Siemens TriCore CPU",
	.disassemble = &disassemble,
	.init = &init,
	.fini = &fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_tricore_cs,
	.version = RZ_VERSION
};
#endif
