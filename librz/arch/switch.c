// SPDX-FileCopyrightText: 2014-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2014-2019 dso <dso@rice.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

static RzAnalysisSwitchOp *__switch_op_new(void) {
	RzAnalysisSwitchOp *swop = RZ_NEW0(RzAnalysisSwitchOp);
	if (swop) {
		swop->cases = rz_list_new();
		if (!swop->cases) {
			free(swop);
			return NULL;
		}
		swop->cases->free = (void *)free;
		swop->min_val = swop->def_val = swop->max_val = 0;
	}
	return swop;
}

RZ_API RzAnalysisSwitchOp *rz_analysis_switch_op_new(ut64 addr, ut64 min_val, ut64 max_val, ut64 def_val) {
	RzAnalysisSwitchOp *swop = __switch_op_new();
	if (swop) {
		swop->addr = addr;
		swop->min_val = min_val;
		swop->def_val = def_val;
		swop->max_val = max_val;
	}
	return swop;
}

RZ_API RzAnalysisCaseOp *rz_analysis_case_op_new(ut64 addr, ut64 val, ut64 jump) {
	RzAnalysisCaseOp *c = RZ_NEW0(RzAnalysisCaseOp);
	if (c) {
		c->addr = addr;
		c->value = val;
		c->jump = jump;
	}
	return c;
}

RZ_API void rz_analysis_switch_op_free(RzAnalysisSwitchOp *swop) {
	if (swop) {
		rz_list_free(swop->cases);
		free(swop);
	}
}

RZ_API RzAnalysisCaseOp *rz_analysis_switch_op_add_case(RzAnalysisSwitchOp *swop, ut64 addr, ut64 value, ut64 jump) {
	rz_return_val_if_fail(swop && addr != UT64_MAX, NULL);
	RzAnalysisCaseOp *caseop = rz_analysis_case_op_new(addr, value, jump);
	if (caseop) {
		rz_list_append(swop->cases, caseop);
	}
	return caseop;
}
