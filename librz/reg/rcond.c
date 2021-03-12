// SPDX-FileCopyrightText: 2014-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_reg.h>

#undef Z
#undef S
#undef C
#undef O
#undef P
#define Z f->z
#define S f->s
#define C f->c
#define O f->o
#define P f->p

RZ_API RzRegItem *rz_reg_cond_get(RzReg *reg, const char *name) {
	int i = RZ_REG_TYPE_GPR;
	RzListIter *iter;
	RzRegItem *r;
	rz_return_val_if_fail(reg && name, NULL);

	rz_list_foreach (reg->regset[i].regs, iter, r) {
		if (r->flags && !strcmp(name, r->flags)) {
			return r;
		}
	}
	return NULL;
}

RZ_API int rz_reg_cond_get_value(RzReg *r, const char *name) {
	return (int)rz_reg_get_value(r, rz_reg_cond_get(r, name)) ? 1 : 0;
}

RZ_API bool rz_reg_cond_set(RzReg *r, const char *name, bool val) {
	RzRegItem *item = rz_reg_cond_get(r, name);
	if (item) {
		rz_reg_set_value(r, item, val);
		return true;
	}
	// eprintf ("Cannot find '%s'\n", name);
	return false;
}

RZ_API const char *rz_reg_cond_to_string(int n) {
	const char *cs[] = {
		"eq", "ne", "cf", "neg", "of", "hi", "he",
		"lo", "loe", "ge", "gt", "lt", "le"
	};
	if (n < 0 || (n > (sizeof(cs) / sizeof(*cs)) - 1)) {
		return NULL;
	}
	return cs[n];
}

RZ_API int rz_reg_cond_from_string(const char *str) {
	if (!strcmp(str, "eq")) {
		return RZ_REG_COND_EQ;
	}
	if (!strcmp(str, "ne")) {
		return RZ_REG_COND_NE;
	}
	if (!strcmp(str, "cf")) {
		return RZ_REG_COND_CF;
	}
	if (!strcmp(str, "neg")) {
		return RZ_REG_COND_NEG;
	}
	if (!strcmp(str, "of")) {
		return RZ_REG_COND_OF;
	}
	if (!strcmp(str, "hi")) {
		return RZ_REG_COND_HI;
	}
	if (!strcmp(str, "he")) {
		return RZ_REG_COND_HE;
	}
	if (!strcmp(str, "lo")) {
		return RZ_REG_COND_LO;
	}
	if (!strcmp(str, "loe")) {
		return RZ_REG_COND_LOE;
	}
	if (!strcmp(str, "ge")) {
		return RZ_REG_COND_GE;
	}
	if (!strcmp(str, "gt")) {
		return RZ_REG_COND_GT;
	}
	if (!strcmp(str, "lt")) {
		return RZ_REG_COND_LT;
	}
	if (!strcmp(str, "le")) {
		return RZ_REG_COND_LE;
	}
	// TODO: move this into core
	eprintf("| Usage: drc[=] [condition](=1,0)\n"
		"| eq    equal\n"
		"| ne    not equal\n"
		"| cf    carry flag set\n"
		"| neg   negative value (has sign)\n"
		"| of    overflow\n"
		"|unsigned:\n"
		"| hi    higher\n"
		"| he    higher or equal\n"
		"| lo    lower\n"
		"| loe   lower or equal\n"
		"|signed:\n"
		"| ge    greater or equal\n"
		"| gt    greater than\n"
		"| le    less or equal\n"
		"| lt    less than\n");
	return -1;
}

RZ_API int rz_reg_cond_bits(RzReg *r, int type, RzRegFlags *f) {
	switch (type) {
	case RZ_REG_COND_EQ: return Z;
	case RZ_REG_COND_NE: return !Z;
	case RZ_REG_COND_CF: return C;
	case RZ_REG_COND_NEG: return S;
	case RZ_REG_COND_OF:
		return O;
	// unsigned
	case RZ_REG_COND_HI: return (!Z && C); // HIGHER
	case RZ_REG_COND_HE: return Z || (!Z && C); // HIGHER OR EQUAL
	case RZ_REG_COND_LO: return (Z || !C); // LOWER
	case RZ_REG_COND_LOE:
		return (Z || !C); // LOWER OR EQUAL
	// signed
	case RZ_REG_COND_GE: return ((S && O) || (!S && !O));
	case RZ_REG_COND_GT: return ((S && !Z && O) || (!S && !Z && !O));
	case RZ_REG_COND_LT: return ((S && !O) || (!S && O));
	case RZ_REG_COND_LE: return (Z || (S && !O) || (!S && O));
	}
	return false;
}

RZ_API bool rz_reg_cond_bits_set(RzReg *r, int type, RzRegFlags *f, bool v) {
	switch (type) {
	case RZ_REG_COND_EQ: Z = v; break;
	case RZ_REG_COND_NE: Z = !v; break;
	case RZ_REG_COND_CF: C = v; break;
	case RZ_REG_COND_NEG: S = v; break;
	case RZ_REG_COND_OF: O = v; break;
	case RZ_REG_COND_HI:
		if (v) {
			Z = 0;
			C = 1;
		} else {
			Z = 1;
			C = 0;
		}
		break;
	case RZ_REG_COND_HE:
		if (v) {
			Z = 1;
		} else {
			Z = 0;
			C = 1;
		}
		break;
	case RZ_REG_COND_LO:
		if (v) {
			Z = 1;
			C = 0;
		} else {
			Z = 0;
			C = 1;
		}
		break;
	case RZ_REG_COND_LOE:
		if (v) {
			Z = 1;
			C = 0;
		} else {
			Z = 0;
			C = 1;
		}
		break;
	// signed
	case RZ_REG_COND_GE:
		if (v) {
			S = O = 1;
		} else {
			S = 1;
			O = 0;
		}
		break;
	case RZ_REG_COND_GT:
		if (v) {
			S = 1;
			Z = 0;
			O = 1;
		} else {
			S = 0;
			Z = 1;
			O = 0;
		}
		break;
	case RZ_REG_COND_LT:
		if (v) {
			S = 1;
			O = 0;
		} else {
			S = 1;
			O = 1;
		}
		break;
	case RZ_REG_COND_LE:
		if (v) {
			S = 0;
			Z = 1;
			O = 0;
		} else {
			S = 1;
			Z = 0;
			O = 1;
		}
		break;
	default:
		return false;
	}
	return true;
}

RZ_API int rz_reg_cond(RzReg *r, int type) {
	RzRegFlags f = { 0 };
	rz_reg_cond_retrieve(r, &f);
	return rz_reg_cond_bits(r, type, &f);
}

RZ_API RzRegFlags *rz_reg_cond_retrieve(RzReg *r, RzRegFlags *f) {
	if (!f) {
		f = RZ_NEW0(RzRegFlags);
	}
	if (!f) {
		return NULL;
	}
	f->s = rz_reg_cond_get_value(r, "sign"); // sign, negate flag, less than zero
	f->z = rz_reg_cond_get_value(r, "zero"); // zero flag
	f->c = rz_reg_cond_get_value(r, "carry"); // carry flag
	f->o = rz_reg_cond_get_value(r, "overflow"); // overflow flag
	f->p = rz_reg_cond_get_value(r, "parity"); // parity // intel only
	return f;
}

RZ_API void rz_reg_cond_apply(RzReg *r, RzRegFlags *f) {
	rz_return_if_fail(r && f);
	rz_reg_cond_set(r, "sign", f->s);
	rz_reg_cond_set(r, "zero", f->z);
	rz_reg_cond_set(r, "carry", f->c);
	rz_reg_cond_set(r, "overflow", f->o);
	rz_reg_cond_set(r, "parity", f->p);
}
