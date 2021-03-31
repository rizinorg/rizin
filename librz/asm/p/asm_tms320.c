// SPDX-FileCopyrightText: 2014 Ilya V. Matveychikov <i.matveychikov@milabs.ru>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <capstone.h>

#ifdef CAPSTONE_TMS320C64X_H
#define CAPSTONE_HAS_TMS320C64X 1
//#include "cs_mnemonics.c"
#else
#define CAPSTONE_HAS_TMS320C64X 0
#warning Cannot find capstone-tms320c64x support
#endif

#include "../arch/tms320/tms320_dasm.h"

typedef struct tms_cs_context_t {
#if CAPSTONE_HAS_TMS320C64X
	csh cd;
#endif
	tms320_dasm_t engine;
} TmsContext;

#if CAPSTONE_HAS_TMS320C64X

static int tms320c64x_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	TmsContext *ctx = (TmsContext *)a->plugin_data;

	cs_insn *insn;
	int n = -1, ret = -1;
	int mode = 0;
	if (op) {
		memset(op, 0, sizeof(RzAsmOp));
		op->size = 4;
	}
	if (ctx->cd != 0) {
		cs_close(&ctx->cd);
	}
	ret = cs_open(CS_ARCH_TMS320C64X, mode, &ctx->cd);
	if (ret) {
		goto fin;
	}
	cs_option(ctx->cd, CS_OPT_DETAIL, CS_OPT_OFF);
	if (!op) {
		return 0;
	}
	n = cs_disasm(ctx->cd, buf, len, a->pc, 1, &insn);
	if (n < 1) {
		rz_asm_op_set_asm(op, "invalid");
		op->size = 4;
		ret = -1;
		goto beach;
	} else {
		ret = 4;
	}
	if (insn->size < 1) {
		goto beach;
	}
	op->size = insn->size;
	char *buf_asm = sdb_fmt("%s%s%s", insn->mnemonic, insn->op_str[0] ? " " : "", insn->op_str);
	rz_str_replace_char(buf_asm, '%', 0);
	rz_str_case(buf_asm, false);
	rz_asm_op_set_asm(op, buf_asm);
	cs_free(insn, n);
beach:
// cs_close (&ctx->cd);
fin:
	return ret;
}
#endif

static int tms320_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	TmsContext *ctx = (TmsContext *)a->plugin_data;
	if (a->cpu && rz_str_casecmp(a->cpu, "c54x") == 0) {
		tms320_f_set_cpu(&ctx->engine, TMS320_F_CPU_C54X);
	} else if (a->cpu && rz_str_casecmp(a->cpu, "c55x+") == 0) {
		tms320_f_set_cpu(&ctx->engine, TMS320_F_CPU_C55X_PLUS);
	} else if (a->cpu && rz_str_casecmp(a->cpu, "c55x") == 0) {
		tms320_f_set_cpu(&ctx->engine, TMS320_F_CPU_C55X);
	} else {
#if CAPSTONE_HAS_TMS320C64X
		if (a->cpu && !rz_str_casecmp(a->cpu, "c64x")) {
			return tms320c64x_disassemble(a, op, buf, len);
		}
#endif
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
	tms320_dasm_init(&ctx->engine);
	*user = ctx;
	return true;
}

static bool tms320_fini(void *user) {
	rz_return_val_if_fail(user, false);
	TmsContext *ctx = (TmsContext *)user;
#if CAPSTONE_HAS_TMS320C64X
	cs_close(&ctx->cd);
#endif
	tms320_dasm_fini(&ctx->engine);
	free(ctx);
	return true;
}

RzAsmPlugin rz_asm_plugin_tms320 = {
	.name = "tms320",
	.arch = "tms320",
#if CAPSTONE_HAS_TMS320C64X
	.cpus = "c54x,c55x,c55x+,c64x",
	.desc = "TMS320 DSP family (c54x,c55x,c55x+,c64x)",
#else
	.cpus = "c54x,c55x,c55x+",
	.desc = "TMS320 DSP family (c54x,c55x,c55x+)",
#endif
	.license = "LGPLv3",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.init = tms320_init,
	.fini = tms320_fini,
	.disassemble = &tms320_disassemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_tms320,
	.version = RZ_VERSION
};
#endif
