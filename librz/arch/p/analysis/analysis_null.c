// SPDX-FileCopyrightText: 2014 jn <j.neuschaefer@gmx.net>
// SPDX-FileCopyrightText: 2014 maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_types.h>
#include <rz_lib.h>

static int null_analysis(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	/* This should better follow the disassembler */
	return op->size = 1;
}

static char *null_get_reg_profile(RzAnalysis *analysis) {
	return rz_str_dup("");
}

RzAnalysisPlugin rz_analysis_plugin_null = {
	.name = "null",
	.desc = "Fallback/Null analysis plugin",
	.arch = "none",
	.license = "LGPL3",
	.bits = 8 | 16 | 32 | 64, /* is this used? */
	.op = &null_analysis,
	.get_reg_profile = &null_get_reg_profile,
};
