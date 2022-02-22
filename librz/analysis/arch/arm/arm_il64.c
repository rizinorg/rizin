// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <capstone.h>

#include "arm_cs.h"
#include "arm_accessors64.h"

#include <rz_il/rz_il_opbuilder_begin.h>

/**
 * All regs available as global IL variables
 */
static const char *regs_bound[] = {
	NULL
};

RZ_IPI RzILOpEffect *rz_arm_cs_64_il(csh *handle, cs_insn *insn, bool thumb) {
	return NULL;
}

#include <rz_il/rz_il_opbuilder_end.h>

RZ_IPI RzAnalysisILConfig *rz_arm_cs_64_il_config(bool big_endian) {
	RzAnalysisILConfig *r = rz_analysis_il_config_new(32, big_endian, 32);
	r->reg_bindings = regs_bound;
	return r;
}
