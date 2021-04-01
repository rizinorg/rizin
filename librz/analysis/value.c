// SPDX-FileCopyrightText: 2010-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

RZ_API RzAnalysisValue *rz_analysis_value_new(void) { //macro for this ?
	return RZ_NEW0(RzAnalysisValue);
}

RZ_API RzAnalysisValue *rz_analysis_value_new_from_string(const char *str) {
	/* TODO */
	return NULL;
}

RZ_API RzAnalysisValue *rz_analysis_value_copy(RzAnalysisValue *ov) {
	rz_return_val_if_fail(ov, NULL);

	RzAnalysisValue *v = RZ_NEW0(RzAnalysisValue);
	if (!v) {
		return NULL;
	}

	memcpy(v, ov, sizeof(RzAnalysisValue));
	// reference to reg and regdelta should be kept
	return v;
}

// TODO: move into .h as #define free
RZ_API void rz_analysis_value_free(RzAnalysisValue *value) {
	free(value);
#if 0
	ut64 pval = (ut64)(size_t)value;
	if (pval && pval != UT64_MAX) {
		/* TODO: free RzRegItem objects? */
		free (value);
	}
#endif
}

// mul*value+regbase+regidx+delta
RZ_API ut64 rz_analysis_value_to_ut64(RzAnalysis *analysis, RzAnalysisValue *val) {
	ut64 num;
	if (!val) {
		return 0LL;
	}
	num = val->base + (val->delta * (val->mul ? val->mul : 1));
	if (val->reg) {
		num += rz_reg_get_value(analysis->reg, val->reg);
	}
	if (val->regdelta) {
		num += rz_reg_get_value(analysis->reg, val->regdelta);
	}
	switch (val->memref) {
	case 1:
	case 2:
	case 4:
	case 8:
		//analysis->bio ...
		eprintf("TODO: memref for to_ut64 not supported\n");
		break;
	}
	return num;
}

RZ_API int rz_analysis_value_set_ut64(RzAnalysis *analysis, RzAnalysisValue *val, ut64 num) {
	if (val->memref) {
		if (analysis->iob.io) {
			ut8 data[8];
			ut64 addr = rz_analysis_value_to_ut64(analysis, val);
			rz_mem_set_num(data, val->memref, num);
			analysis->iob.write_at(analysis->iob.io, addr, data, val->memref);
		} else {
			eprintf("No IO binded to rz_analysis\n");
		}
	} else {
		if (val->reg) {
			rz_reg_set_value(analysis->reg, val->reg, num);
		}
	}
	return false; //is this necessary
}

RZ_API char *rz_analysis_value_to_string(RzAnalysisValue *value) {
	char *out = NULL;
	if (value) {
		out = rz_str_new("");
		if (!value->base && !value->reg) {
			if (value->imm != -1LL) {
				out = rz_str_appendf(out, "0x%" PFMT64x, value->imm);
			} else {
				out = rz_str_append(out, "-1");
			}
		} else {
			if (value->memref) {
				switch (value->memref) {
				case 1: out = rz_str_append(out, "(char)"); break;
				case 2: out = rz_str_append(out, "(short)"); break;
				case 4: out = rz_str_append(out, "(word)"); break;
				case 8: out = rz_str_append(out, "(dword)"); break;
				}
				out = rz_str_append(out, "[");
			}
			if (value->mul) {
				out = rz_str_appendf(out, "%d*", value->mul);
			}
			if (value->reg) {
				out = rz_str_appendf(out, "%s", value->reg->name);
			}
			if (value->regdelta) {
				out = rz_str_appendf(out, "+%s", value->regdelta->name);
			}
			if (value->base != 0) {
				out = rz_str_appendf(out, "0x%" PFMT64x, value->base);
			}
			if (value->delta > 0) {
				out = rz_str_appendf(out, "+0x%" PFMT64x, value->delta);
			} else if (value->delta < 0) {
				out = rz_str_appendf(out, "-0x%" PFMT64x, -value->delta);
			}
			if (value->memref) {
				out = rz_str_append(out, "]");
			}
		}
	}
	return out;
}
