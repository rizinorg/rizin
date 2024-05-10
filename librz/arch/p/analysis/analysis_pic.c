// SPDX-FileCopyrightText: 2015-2018 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2015-2018 thestr4ng3r <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2015-2018 courk <courk@courk.cc>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_analysis.h>
#include "../isa/pic/pic18.h"
#include "../isa/pic/pic16.h"

static bool pic_init(void **user) {
	PicContext *ctx = RZ_NEW0(PicContext);
	if (!ctx) {
		return false;
	}
	ctx->init_done = false;
	ctx->pic18_mm = ht_su_new(HT_STR_CONST);
	for (int i = 0; i < 0x80; ++i) {
		const char *regname = pic18_regname(i);
		ht_su_insert(ctx->pic18_mm, regname, i);
	}
	for (int i = 0x80; i < 0x100; ++i) {
		const char *regname = pic18_regname(i);
		ht_su_insert(ctx->pic18_mm, regname, i + 0xf00);
	}
	*user = ctx;
	return true;
}

static bool pic_fini(void *user) {
	PicContext *ctx = (PicContext *)user;
	if (ctx) {
		ht_su_free(ctx->pic18_mm);
		RZ_FREE(ctx);
	}
	return true;
}

static int analysis_pic_op(
	RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask) {
	if (RZ_STR_ISEMPTY(analysis->cpu) || is_pic18(analysis->cpu)) {
		return pic18_op(analysis, op, addr, buf, len, mask);
	}

	if (is_pic14_or_pic16(analysis->cpu)) {
		return pic16_op(analysis, op, addr, buf, len, mask);
	}
	return -1;
}

static char *analysis_pic_get_reg_profile(RzAnalysis *analysis) {
	if (RZ_STR_ISEMPTY(analysis->cpu) || is_pic18(analysis->cpu)) {
		return pic18_get_reg_profile(analysis);
	}

	if (is_pic14_or_pic16(analysis->cpu)) {
		return pic16_get_reg_profile(analysis);
	}
	return NULL;
}

static RzAnalysisILConfig *pic_il_config(RzAnalysis *analysis) {
	if (RZ_STR_ISEMPTY(analysis->cpu) || is_pic18(analysis->cpu)) {
		return pic18_il_config(analysis);
	}
	if (is_pic14_or_pic16(analysis->cpu)) {
		return pic16_il_config(analysis);
	}
	return NULL;
}

static int pic_archinfo(RzAnalysis *analysis, RzAnalysisInfoType query) {
	if (RZ_STR_ISEMPTY(analysis->cpu) || is_pic18(analysis->cpu)) {
		switch (query) {
		case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE: return 2;
		case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE: return 4;
		case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN: return 2;
		case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN: return 4;
		case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS: return 1;
		default: return -1;
		}
	}

	if (is_pic14_or_pic16(analysis->cpu)) {
		switch (query) {
		case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE: return 2;
		case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE: return 2;
		case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN: return 1;
		case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN: return 1;
		case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS: return 1;
		default: return -1;
		}
	}
	return -1;
}

RzAnalysisPlugin rz_analysis_plugin_pic = {
	.name = "pic",
	.desc = "PIC analysis plugin",
	.license = "LGPL3",
	.arch = "pic",
	.bits = 8,
	.op = &analysis_pic_op,
	.init = pic_init,
	.fini = pic_fini,
	.il_config = pic_il_config,
	.get_reg_profile = &analysis_pic_get_reg_profile,
	.esil = true,
	.archinfo = pic_archinfo
};
