/* radare - LGPL - Copyright 2014-2019 - pancake, dso */

#include <rz_anal.h>

static RzAnalSwitchOp *__switch_op_new(void) {
	RzAnalSwitchOp * swop = RZ_NEW0 (RzAnalSwitchOp);
	if (swop) {
		swop->cases = rz_list_new ();
		if (!swop->cases) {
			free (swop);
			return NULL;
		}
		swop->cases->free = (void *)free;
		swop->min_val = swop->def_val = swop->max_val = 0;
	}
	return swop;
}

RZ_API RzAnalSwitchOp *rz_anal_switch_op_new(ut64 addr, ut64 min_val, ut64 max_val, ut64 def_val) {
	RzAnalSwitchOp *swop = __switch_op_new ();
	if (swop) {
		swop->addr = addr;
		swop->min_val = min_val;
		swop->def_val = def_val;
		swop->max_val = max_val;
	}
	return swop;
}

RZ_API RzAnalCaseOp * rz_anal_case_op_new(ut64 addr, ut64 val, ut64 jump) {
	RzAnalCaseOp *c = RZ_NEW0 (RzAnalCaseOp);
	if (c) {
		c->addr = addr;
		c->value = val;
		c->jump = jump;
	}
	return c;
}

RZ_API void rz_anal_switch_op_free(RzAnalSwitchOp * swop) {
	if (swop) {
		rz_list_free (swop->cases);
		free (swop);
	}
}

RZ_API RzAnalCaseOp* rz_anal_switch_op_add_case(RzAnalSwitchOp * swop, ut64 addr, ut64 value, ut64 jump) {
	rz_return_val_if_fail (swop && addr != UT64_MAX, NULL);
	RzAnalCaseOp * caseop = rz_anal_case_op_new (addr, value, jump);
	if (caseop) {
		rz_list_append (swop->cases, caseop);
	}
	return caseop;
}
