// SPDX-FileCopyrightText: 2015-2018 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2015-2018 thestr4ng3r <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2015-2018 courk <courk@courk.cc>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_analysis.h>

typedef struct {
	RzIODesc *mem_sram;
	RzIODesc *mem_stack;
	bool init_done;
} PicContext;

static bool pic_init(void **user) {
	PicContext *ctx = RZ_NEW0(PicContext);
	if (!ctx) {
		return false;
	}
	ctx->init_done = false;
	*user = ctx;
	return true;
}

static bool pic_fini(void *user) {
	PicContext *ctx = (PicContext *)user;
	if (ctx) {
		RZ_FREE(ctx);
	}
	return true;
}

#include "pic/pic_midrange_analysis.inc"
#include "pic/pic18_analysis.inc"

static int analysis_pic_op(
	RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask) {
	if (analysis->cpu && strcasecmp(analysis->cpu, "baseline") == 0) {
		// TODO: implement
		return -1;
	}
	if (analysis->cpu && strcasecmp(analysis->cpu, "midrange") == 0) {
		return analysis_pic_midrange_op(analysis, op, addr, buf, len, mask);
	}
	if (analysis->cpu && strcasecmp(analysis->cpu, "pic18") == 0) {
		return analysis_pic_pic18_op(analysis, op, addr, buf, len, mask);
	}
	return -1;
}

static char *analysis_pic_get_reg_profile(RzAnalysis *analysis) {
	if (analysis->cpu && strcasecmp(analysis->cpu, "baseline") == 0) {
		// TODO: We are using the midrange profile as the baseline
		return analysis_pic_midrange_get_reg_profile(analysis);
	}
	if (analysis->cpu && strcasecmp(analysis->cpu, "midrange") == 0) {
		return analysis_pic_midrange_get_reg_profile(analysis);
	}
	if (analysis->cpu && strcasecmp(analysis->cpu, "pic18") == 0) {
		return analysis_pic_pic18_get_reg_profile(analysis);
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
	if (a->cpu && strcasecmp(a->cpu, "pic18") == 0) {
		return NULL;
	}
	return NULL;
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
	.esil = true
};
