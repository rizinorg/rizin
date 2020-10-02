/* radare - LGPL - Copyright 2010-2016 - pancake */

#include <rz_anal.h>

RZ_API const char *rz_anal_cond_tostring(int cc) {
	switch (cc) {
	case RZ_ANAL_COND_EQ: return "eq";
	case RZ_ANAL_COND_NV: return "nv";
	case RZ_ANAL_COND_NE: return "ne";
	case RZ_ANAL_COND_HS: return "hs";
	case RZ_ANAL_COND_LO: return "lo";
	case RZ_ANAL_COND_MI: return "mi";
	case RZ_ANAL_COND_PL: return "pl";
	case RZ_ANAL_COND_VS: return "vs";
	case RZ_ANAL_COND_VC: return "vc";
	case RZ_ANAL_COND_HI: return "hi";
	case RZ_ANAL_COND_LS: return "ls";
	case RZ_ANAL_COND_GE: return "ge";
	case RZ_ANAL_COND_LT: return "lt";
	case RZ_ANAL_COND_GT: return "gt";
	case RZ_ANAL_COND_LE: return "le";
	case RZ_ANAL_COND_AL: return "al";
	}
	return "??";
}

RZ_API RzAnalCond *rz_anal_cond_new(void) {
	return RZ_NEW0 (RzAnalCond);
}

RZ_API void rz_anal_cond_fini (RzAnalCond *c) {
	if (!c) {
		return;
	}
	rz_anal_value_free (c->arg[0]);
	rz_anal_value_free (c->arg[1]);
	c->arg[0] = c->arg[1] = NULL;
}

RZ_API void rz_anal_cond_free (RzAnalCond *c) {
	if (!c) {
		return;
	}
	rz_anal_cond_fini (c);
	free (c);
}

// XXX?
RZ_API RzAnalCond *rz_anal_cond_clone(RzAnalCond *cond) {
	RzAnalCond *c = RZ_NEW (RzAnalCond);
	if (!c) {
		return NULL;
	}
	memcpy (c, cond, sizeof (RzAnalCond));
	return c;
}

static inline const char *condstring(RzAnalCond *cond) {
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

RZ_API int rz_anal_cond_eval(RzAnal *anal, RzAnalCond *cond) {
	// XXX: sign issue here?
	st64 arg0 = (st64) rz_anal_value_to_ut64 (anal, cond->arg[0]);
	if (cond->arg[1]) {
		st64 arg1 = (st64) rz_anal_value_to_ut64 (anal, cond->arg[1]);
		switch (cond->type) {
		case RZ_ANAL_COND_EQ: return arg0 == arg1;
		case RZ_ANAL_COND_NE: return arg0 != arg1;
		case RZ_ANAL_COND_GE: return arg0 >= arg1;
		case RZ_ANAL_COND_GT: return arg0 > arg1;
		case RZ_ANAL_COND_LE: return arg0 <= arg1;
		case RZ_ANAL_COND_LT: return arg0 < arg1;
		}
	} else {
		switch (cond->type) {
		case RZ_ANAL_COND_EQ: return !arg0;
		case RZ_ANAL_COND_NE: return arg0;
		case RZ_ANAL_COND_GT: return arg0>0;
		case RZ_ANAL_COND_GE: return arg0>=0;
		case RZ_ANAL_COND_LT: return arg0<0;
		case RZ_ANAL_COND_LE: return arg0<=0;
		}
	}
	return false;
}

// XXX conflict naming with tostring()
RZ_API char *rz_anal_cond_to_string(RzAnalCond *cond) {
	char *val0, *val1, *out = NULL;
	const char *cnd;
	if (!cond) {
		return NULL;
	}
	cnd = condstring (cond);
	val0 = rz_anal_value_to_string (cond->arg[0]);
	val1 = rz_anal_value_to_string (cond->arg[1]);
	if (val0) {
		if (RZ_ANAL_COND_SINGLE (cond)) {
			int val0len = strlen (val0) + 10;
			if ((out = malloc (val0len))) {
				snprintf (out, val0len, "%s%s", cnd, val0);
			}
		} else {
			if (val1) {
				int val0len = strlen (val0) + strlen (val1) + 10;
				if ((out = malloc (val0len))) {
					snprintf (out, val0len, "%s %s %s", val0, cnd, val1);
				}
			}
		}
	}
	free (val0);
	free (val1);
	return out? out: strdup ("?");
}

RZ_API RzAnalCond *rz_anal_cond_new_from_op(RzAnalOp *op) {
	RzAnalCond *cond;
	if (!(cond = rz_anal_cond_new ())) {
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

RZ_API RzAnalCond *rz_anal_cond_new_from_string(const char *str) {
	RzAnalCond *cond = RZ_NEW (RzAnalCond);
	// TODO: find '<','=','>','!'...
	return cond;
}
