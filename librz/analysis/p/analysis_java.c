// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_analysis.h>

#include "../../asm/arch/java/jvm.h"

typedef struct java_analysis_context_t {
	LookupSwitch ls;
	TableSwitch ts;
	ut64 pc;
	ut16 switchop;
	ut32 count;
} JavaAnalysisContext;

static void update_context(JavaAnalysisContext *ctx) {
	ctx->count++;
	if (ctx->switchop == BYTECODE_AA_TABLESWITCH && ctx->count > ctx->ts.length) {
		ctx->switchop = BYTECODE_00_NOP;
	} else if (ctx->switchop == BYTECODE_AB_LOOKUPSWITCH && ctx->count > ctx->ls.npairs) {
		ctx->switchop = BYTECODE_00_NOP;
	}
}

static int java_analysis(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	JavaAnalysisContext *ctx = (JavaAnalysisContext *)analysis->plugin_data;

	switch (ctx->switchop) {
	case BYTECODE_AA_TABLESWITCH:
		if (len < 4) {
			RZ_LOG_ERROR("[!] java_analysis: no enough data for lookupswitch case.\n");
			return -1;
		}
		op->size = 4;
		op->jump = ctx->pc + rz_read_be32(buf);
		op->fail = addr + op->size;
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		update_context(ctx);
		return op->size;
	case BYTECODE_AB_LOOKUPSWITCH:
		if (len < 8) {
			RZ_LOG_ERROR("[!] java_analysis: no enough data for lookupswitch case.\n");
			return -1;
		}
		op->size = 8;
		op->jump = ctx->pc + rz_read_at_be32(buf, 4);
		op->fail = addr + op->size;
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		update_context(ctx);
		return op->size;
	default:
		break;
	}

	JavaVM vm = { 0 };
	Bytecode bc = { 0 };

	ut64 section = addr;
	if (analysis->binb.bin) {
		const RzBinSection *sec = analysis->binb.get_vsect_at(analysis->binb.bin, addr);
		if (sec) {
			section = sec->paddr;
		}
	}

	if (!jvm_init(&vm, buf, len, addr, section)) {
		RZ_LOG_ERROR("[!] java_analysis: bad or invalid data.\n");
		return -1;
	}

	op->fail = UT64_MAX;
	op->jump = UT64_MAX;
	op->size = 1;
	if (jvm_fetch(&vm, &bc)) {
		op->size = bc.size;
		op->type = bc.atype;
		switch (bc.atype) {
		case RZ_ANALYSIS_OP_TYPE_CALL:
		case RZ_ANALYSIS_OP_TYPE_JMP:
			op->jump = bc.pc + bc.args[0];
			break;
		case RZ_ANALYSIS_OP_TYPE_CJMP:
			op->jump = bc.pc + bc.args[0];
			op->fail = addr + bc.size;
			break;
		case RZ_ANALYSIS_OP_TYPE_RET:
		case RZ_ANALYSIS_OP_TYPE_ILL:
			op->eob = true;
			break;
		default:
			break;
		}
		if (bc.opcode == BYTECODE_AA_TABLESWITCH) {
			ctx->switchop = BYTECODE_AA_TABLESWITCH;
			ctx->ts = *((TableSwitch *)bc.extra);
			ctx->count = 0;
			ctx->pc = addr;
		} else if (bc.opcode == BYTECODE_AB_LOOKUPSWITCH) {
			ctx->switchop = BYTECODE_AB_LOOKUPSWITCH;
			ctx->ls = *((LookupSwitch *)bc.extra);
			ctx->count = 0;
			ctx->pc = addr;
		}
		bytecode_clean(&bc);
	} else {
		RZ_LOG_ERROR("[!] java_analysis: jvm fetch failed.\n");
		return -1;
	}
	return op->size;
}

static bool set_reg_profile(RzAnalysis *analysis) {
	const char *p =
		"=PC	pc\n"
		"=SP	garbage\n"
		"=SR	garbage\n"
		"=A0	garbage\n"
		"=A1	garbage\n"
		"=A2	garbage\n"
		"=A3	garbage\n"
		"=A4	garbage\n"
		"=A5	garbage\n"
		"=A6	garbage\n"
		"gpr	pc	    .32 0  0\n"
		"gpr	garbage	.32 32 0\n";
	return rz_reg_set_profile_string(analysis->reg, p);
}

static int archinfo(RzAnalysis *analysis, int query) {
	if (query == RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE) {
		return 1;
	} else if (query == RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE) {
		return 16;
	}
	return 0;
}

static bool java_init(void **user) {
	JavaAnalysisContext *ctx = RZ_NEW0(JavaAnalysisContext);
	if (!ctx) {
		return false;
	}
	*user = ctx;
	return true;
}

static bool java_fini(void *user) {
	if (!user) {
		return false;
	}
	free(user);
	return true;
}

RzAnalysisPlugin rz_analysis_plugin_java = {
	.name = "java",
	.desc = "Java analysis plugin",
	.arch = "java",
	.license = "LGPL3",
	.bits = 32,
	.op = &java_analysis,
	.archinfo = archinfo,
	.init = java_init,
	.fini = java_fini,
	.set_reg_profile = &set_reg_profile,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_java,
	.version = RZ_VERSION
};
#endif
