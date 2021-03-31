// SPDX-FileCopyrightText: 2010-2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

RZ_API const char *rz_analysis_cond_tostring(int cc) {
	switch (cc) {
	case RZ_ANALYSIS_COND_EQ: return "eq";
	case RZ_ANALYSIS_COND_NV: return "nv";
	case RZ_ANALYSIS_COND_NE: return "ne";
	case RZ_ANALYSIS_COND_HS: return "hs";
	case RZ_ANALYSIS_COND_LO: return "lo";
	case RZ_ANALYSIS_COND_MI: return "mi";
	case RZ_ANALYSIS_COND_PL: return "pl";
	case RZ_ANALYSIS_COND_VS: return "vs";
	case RZ_ANALYSIS_COND_VC: return "vc";
	case RZ_ANALYSIS_COND_HI: return "hi";
	case RZ_ANALYSIS_COND_LS: return "ls";
	case RZ_ANALYSIS_COND_GE: return "ge";
	case RZ_ANALYSIS_COND_LT: return "lt";
	case RZ_ANALYSIS_COND_GT: return "gt";
	case RZ_ANALYSIS_COND_LE: return "le";
	case RZ_ANALYSIS_COND_AL: return "al";
	}
	return "??";
}

RZ_API RzAnalysisCond *rz_analysis_cond_new(void) {
	return RZ_NEW0(RzAnalysisCond);
}

RZ_API void rz_analysis_cond_fini(RzAnalysisCond *c) {
	if (!c) {
		return;
	}
	rz_analysis_value_free(c->arg[0]);
	rz_analysis_value_free(c->arg[1]);
	c->arg[0] = c->arg[1] = NULL;
}

RZ_API void rz_analysis_cond_free(RzAnalysisCond *c) {
	if (!c) {
		return;
	}
	rz_analysis_cond_fini(c);
	free(c);
}

// XXX?
RZ_API RzAnalysisCond *rz_analysis_cond_clone(RzAnalysisCond *cond) {
	RzAnalysisCond *c = RZ_NEW(RzAnalysisCond);
	if (!c) {
		return NULL;
	}
	memcpy(c, cond, sizeof(RzAnalysisCond));
	return c;
}

static inline const char *condstring(RzAnalysisCond *cond) {
	const char *condstr_single[] = { "!", "", "0<", "0<=", "0>", "0>=" };
	const char *condstr[] = { "==", "!=", ">=", ">", "<=", "<" };
	if (cond) {
		if (cond->arg[1]) {
			return condstr[cond->type % 6];
		} else {
			return condstr_single[cond->type % 6];
		}
	}
	return "";
}

RZ_API int rz_analysis_cond_eval(RzAnalysis *analysis, RzAnalysisCond *cond) {
	// XXX: sign issue here?
	st64 arg0 = (st64)rz_analysis_value_to_ut64(analysis, cond->arg[0]);
	if (cond->arg[1]) {
		st64 arg1 = (st64)rz_analysis_value_to_ut64(analysis, cond->arg[1]);
		switch (cond->type) {
		case RZ_ANALYSIS_COND_EQ: return arg0 == arg1;
		case RZ_ANALYSIS_COND_NE: return arg0 != arg1;
		case RZ_ANALYSIS_COND_GE: return arg0 >= arg1;
		case RZ_ANALYSIS_COND_GT: return arg0 > arg1;
		case RZ_ANALYSIS_COND_LE: return arg0 <= arg1;
		case RZ_ANALYSIS_COND_LT: return arg0 < arg1;
		}
	} else {
		switch (cond->type) {
		case RZ_ANALYSIS_COND_EQ: return !arg0;
		case RZ_ANALYSIS_COND_NE: return arg0;
		case RZ_ANALYSIS_COND_GT: return arg0 > 0;
		case RZ_ANALYSIS_COND_GE: return arg0 >= 0;
		case RZ_ANALYSIS_COND_LT: return arg0 < 0;
		case RZ_ANALYSIS_COND_LE: return arg0 <= 0;
		}
	}
	return false;
}

// XXX conflict naming with tostring()
RZ_API char *rz_analysis_cond_to_string(RzAnalysisCond *cond) {
	char *val0, *val1, *out = NULL;
	const char *cnd;
	if (!cond) {
		return NULL;
	}
	cnd = condstring(cond);
	val0 = rz_analysis_value_to_string(cond->arg[0]);
	val1 = rz_analysis_value_to_string(cond->arg[1]);
	if (val0) {
		if (RZ_ANALYSIS_COND_SINGLE(cond)) {
			int val0len = strlen(val0) + 10;
			if ((out = malloc(val0len))) {
				snprintf(out, val0len, "%s%s", cnd, val0);
			}
		} else {
			if (val1) {
				int val0len = strlen(val0) + strlen(val1) + 10;
				if ((out = malloc(val0len))) {
					snprintf(out, val0len, "%s %s %s", val0, cnd, val1);
				}
			}
		}
	}
	free(val0);
	free(val1);
	return out ? out : strdup("?");
}

RZ_API RzAnalysisCond *rz_analysis_cond_new_from_op(RzAnalysisOp *op) {
	RzAnalysisCond *cond;
	if (!(cond = rz_analysis_cond_new())) {
		return NULL;
	}
	//v->reg[0] = op->src[0];
	//v->reg[1] = op->src[1];
	cond->arg[0] = op->src[0];
	op->src[0] = NULL;
	cond->arg[1] = op->src[1];
	op->src[1] = NULL;
	// TODO: moar!
	//cond->arg[1] = op->src[1];
	return cond;
}

RZ_API RzAnalysisCond *rz_analysis_cond_new_from_string(const char *str) {
	RzAnalysisCond *cond = RZ_NEW(RzAnalysisCond);
	// TODO: find '<','=','>','!'...
	return cond;
}
