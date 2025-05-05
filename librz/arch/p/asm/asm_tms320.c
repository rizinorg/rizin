// SPDX-FileCopyrightText: 2014 Ilya V. Matveychikov <i.matveychikov@milabs.ru>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <tms320/tms320_dasm.h>
#include <tms320/c64x/c64x.h>

typedef struct tms_cs_context_t {
	void *c64x;
	tms320_dasm_t engine;
} TmsContext;

static int tms320_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	TmsContext *ctx = (TmsContext *)a->plugin_data;
	if (a->cpu && rz_str_casecmp(a->cpu, "c54x") == 0) {
		tms320_f_set_cpu(&ctx->engine, TMS320_F_CPU_C54X);
	} else if (a->cpu && rz_str_casecmp(a->cpu, "c55x+") == 0) {
		tms320_f_set_cpu(&ctx->engine, TMS320_F_CPU_C55X_PLUS);
	} else if (a->cpu && rz_str_casecmp(a->cpu, "c55x") == 0) {
		tms320_f_set_cpu(&ctx->engine, TMS320_F_CPU_C55X);
	} else if (a->cpu && !rz_str_casecmp(a->cpu, "c64x")) {
		return tms320_c64x_disassemble(a, op, buf, len, ctx->c64x);
	} else {
		rz_asm_op_set_asm(op, "unknown asm.cpu");
		return op->size = -1;
	}
	op->size = tms320_dasm(&ctx->engine, buf, len);
	rz_asm_op_set_asm(op, ctx->engine.syntax);
	return op->size;
}

static bool tms320_init(void **user) {
	TmsContext *ctx = RZ_NEW0(TmsContext);
	if (!ctx) {
		return false;
	}

	ctx->c64x = tms320_c64x_new();
	tms320_dasm_init(&ctx->engine);
	*user = ctx;
	return true;
}

static bool tms320_fini(void *user) {
	rz_return_val_if_fail(user, false);
	TmsContext *ctx = (TmsContext *)user;
	tms320_c64x_free(ctx->c64x);
	tms320_dasm_fini(&ctx->engine);
	free(ctx);
	return true;
}

static char *tms320_mnemonics(RzAsm *a, int id, bool json) {
	TmsContext *ctx = (TmsContext *)a->plugin_data;
	if (!a->cpu || rz_str_casecmp(a->cpu, "c64x")) {
		return NULL;
	}
	return tms320_c64x_mnemonics(a, id, json, ctx->c64x);
}

static char **tms320_cpu_descriptions() {
	static char *cpu_desc[] = {
		"c54x", "Texas Instruments TMS320C54x DSP family",
		"c55x", "Texas Instruments TMS320C55x DSP family",
		"c55x+", "Texas Instruments TMS320C55x+ DSP family",
		"c64x", "Texas Instruments TMS320C64x DSP family",
		NULL
	};
	return cpu_desc;
}

RzAsmPlugin rz_asm_plugin_tms320 = {
	.name = "tms320",
	.arch = "tms320",
	.cpus = "c54x,c55x,c55x+,c64x",
	.desc = "Texas Instruments TMS320 DSP family (c54x,c55x,c55x+,c64x) disassembler",
	.license = "LGPL3",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.init = tms320_init,
	.fini = tms320_fini,
	.disassemble = &tms320_disassemble,
	.mnemonics = tms320_mnemonics,
	.get_cpu_desc = tms320_cpu_descriptions,
};
