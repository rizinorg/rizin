// SPDX-FileCopyrightText: 2024 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	if (!buf || !op || !a->plugin_data) {
		return -1;
	}

	RzAsmLoongArchContext *ctx = a->plugin_data;
	if (!loongarch_setup_cs_handle(ctx, a->bits == 64, a->big_endian)) {
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

static bool loongarch_asm_init(void **u) {
	if (!u) {
		return false;
	}
	// u = RzAsm.plugin_data
	RzAsmLoongArchContext *ctx = NULL;
	if (*u) {
		rz_mem_memzero(*u, sizeof(RzAsmLoongArchContext));
		ctx = *u;
	} else {
		ctx = RZ_NEW0(RzAsmLoongArchContext);
		if (!ctx) {
			return false;
		}
		*u = ctx;
	}
	return true;
}

static bool loongarch_asm_fini(void *u) {
	if (!u) {
		return true;
	}
	RzAsmLoongArchContext *ctx = u;
	cs_close(&ctx->h);
	free(u);
	return true;
}

RzAsmPlugin rz_asm_plugin_loongarch_cs = {
	.name = "loongarch",
	.desc = "Loongson LoongArch disassembler",
	.license = "LGPL3",
	.arch = "loongarch",
	.bits = 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.disassemble = &disassemble,
	.init = &loongarch_asm_init,
	.fini = &loongarch_asm_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_loongarch_cs,
	.version = RZ_VERSION
};
#endif
