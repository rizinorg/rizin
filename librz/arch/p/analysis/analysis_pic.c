// SPDX-FileCopyrightText: 2015-2018 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2015-2018 thestr4ng3r <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2015-2018 courk <courk@courk.cc>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_analysis.h>
#include "../isa/pic/pic_pic18.h"

typedef struct {
	RzIODesc *mem_sram;
	RzIODesc *mem_stack;
	bool init_done;
	HtSU *pic18_mm;
} PicContext;

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

#include "pic/pic_midrange_analysis.inc"
#include "pic/pic18_analysis.inc"

static int analysis_pic_op(
	RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask) {
	if (RZ_STR_ISEMPTY(analysis->cpu) ||
		RZ_STR_EQ(analysis->cpu, "pic") ||
		RZ_STR_EQ(analysis->cpu, "pic18")) {
		return analysis_pic18_op(analysis, op, addr, buf, len, mask);
	}

	if (RZ_STR_EQ(analysis->cpu, "baseline") ||
		RZ_STR_EQ(analysis->cpu, "midrange")) {
		return analysis_pic_midrange_op(analysis, op, addr, buf, len, mask);
	}
	return -1;
}

static char *analysis_pic_get_reg_profile(RzAnalysis *analysis) {
	if (RZ_STR_ISEMPTY(analysis->cpu) ||
		RZ_STR_EQ(analysis->cpu, "pic") ||
		RZ_STR_EQ(analysis->cpu, "pic18")) {
		return analysis_pic_pic18_get_reg_profile(analysis);
	}

	if (RZ_STR_EQ(analysis->cpu, "baseline") ||
		RZ_STR_EQ(analysis->cpu, "midrange")) {
		return analysis_pic_midrange_get_reg_profile(analysis);
	}
	return NULL;
}

static RzAnalysisILConfig *pic_il_config(RzAnalysis *a) {
	if (a->cpu && strcasecmp(a->cpu, "baseline") == 0) {
		// TODO: We are using the midrange il config as the baseline
		return pic_midrange_il_config(a);
	}
	if (a->cpu && strcasecmp(a->cpu, "midrange") == 0) {
		return pic_midrange_il_config(a);
	}
	if (a->cpu && (strcasecmp(a->cpu, "pic18") == 0 || RZ_STR_EQ(a->cpu, "pic"))) {
		return pic18_il_config(a);
	}
	return NULL;
}

static int pic_archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	if (RZ_STR_ISEMPTY(a->cpu) ||
		RZ_STR_EQ(a->cpu, "pic") ||
		RZ_STR_EQ(a->cpu, "pic18")) {
		switch (query) {
		case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE: return 2;
		case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE: return 4;
		case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN: return 2;
		case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN: return 4;
		case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS: return 1;
		default: return -1;
		}
	}

	if (RZ_STR_EQ(a->cpu, "baseline") ||
		RZ_STR_EQ(a->cpu, "midrange")) {
		switch (query) {
		case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE: return 2;
		case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE: return 2;
		case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN: return 2;
		case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN: return 2;
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
