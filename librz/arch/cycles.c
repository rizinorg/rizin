// SPDX-FileCopyrightText: 2014-2020 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_list.h>
#include <rz_types.h>

RZ_API RzAnalysisCycleFrame *rz_analysis_cycle_frame_new(void) {
	RzAnalysisCycleFrame *cf = RZ_NEW0(RzAnalysisCycleFrame);
	if (cf) {
		if (!(cf->hooks = rz_list_new())) {
			RZ_FREE(cf);
		}
	}
	return cf;
}

RZ_API void rz_analysis_cycle_frame_free(RzAnalysisCycleFrame *cf) {
	if (!cf) {
		return;
	}
	rz_list_free(cf->hooks);
	free(cf);
}
