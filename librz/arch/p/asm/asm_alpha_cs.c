// SPDX-FileCopyrightText: 2023 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include <capstone/capstone.h>

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	if (!buf || !op || !a->plugin_data) {
		return -1;
	}

	RzAsmAlphaContext *ctx = a->plugin_data;
	if (!alpha_setup_cs_handle(ctx, a->cpu, a->features, a->big_endian)) {
		return -1;
	}

	op->size = 4;
	ctx->insn = NULL;
	ctx->count = cs_disasm(ctx->h, (ut8 *)buf, len, a->pc, 1, &ctx->insn);
	if (ctx->count < 1) {
		rz_asm_op_set_asm(op, "invalid");
		goto beach;
	}
	if (ctx->insn->size < 1) {
		return op->size;
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
		pat->pattern = strdup(_pat); \
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

	TOKEN(REGISTER, "([rf$]{1,2}[[:digit:]]{1,2})|(sp|pc|fpcr|lr0|lr1)");

	TOKEN(MNEMONIC, "([[:alpha:]]+[[:alnum:]\\,]*([[:alpha:]]+|(<|>|=)+))");

	TOKEN(SEPARATOR, "([[:blank:]]+)|([,;\\(\\)\\{\\}:])");

	TOKEN(NUMBER, "([[:digit:]]+)");

	return pvec;
}

static bool init(void **u) {
	if (!u) {
		return false;
	}
	// u = RzAsm.plugin_data
	RzAsmAlphaContext *ctx = NULL;
	if (*u) {
		rz_mem_memzero(*u, sizeof(RzAsmAlphaContext));
		ctx = *u;
	} else {
		ctx = RZ_NEW0(RzAsmAlphaContext);
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
	RzAsmAlphaContext *ctx = u;
	cs_close(&ctx->h);
	rz_pvector_free(ctx->token_patterns);
	free(u);
	return true;
}

RzAsmPlugin rz_asm_plugin_alpha_cs = {
	.name = "alpha",
	.desc = "Capstone Alpha disassembler",
	.license = "LGPL3",
	.arch = "alpha",
	.bits = 64,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.disassemble = &disassemble,
	.init = &init,
	.fini = &fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_alpha_cs,
	.version = RZ_VERSION
};
#endif
