// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_SORT_H
#define RZ_IL_SORT_H

#include <rz_types.h>
#include <rz_util/rz_float.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Type and Sort identifiers for values in the IL
 *
 * Our notion:
 *  * Types only tell which kind of value something is. E.g. whether it is a bitvector or boolean, but no other info.
 *    They can generally be expressed sufficiently as an enum.
 *  * Sorts carry any additional info that makes up the structure of a value, in particular bitvector sorts specify a concrete bit count.
 */

typedef enum {
	RZ_IL_TYPE_PURE_BOOL,
	RZ_IL_TYPE_PURE_BITVECTOR,
	RZ_IL_TYPE_PURE_FLOAT,
} RzILTypePure;

typedef struct rz_il_sort_pure_t {
	RzILTypePure type;
	union {
		struct {
			ut32 length;
		} bv;
		struct {
			RzFloatFormat format;
		} f;
	} props;
} RzILSortPure;

static inline bool rz_il_sort_pure_eq(RzILSortPure a, RzILSortPure b) {
	if (a.type != b.type) {
		return false;
	}
	if (a.type == RZ_IL_TYPE_PURE_BITVECTOR && a.props.bv.length != b.props.bv.length) {
		return false;
	}
	if (a.type == RZ_IL_TYPE_PURE_FLOAT && a.props.f.format != b.props.f.format) {
		return false;
	}
	return true;
}

static inline RzILSortPure rz_il_sort_pure_bool() {
	RzILSortPure r = {
		RZ_IL_TYPE_PURE_BOOL,
		{ { 0 } },
	};
	return r;
}

static inline RzILSortPure rz_il_sort_pure_bv(ut32 length) {
	RzILSortPure r = {
		RZ_IL_TYPE_PURE_BITVECTOR,
		{ { 0 } },
	};
	r.props.bv.length = length;
	return r;
}

static inline RzILSortPure rz_il_sort_pure_float(RzFloatFormat format) {
	RzILSortPure r = {
		RZ_IL_TYPE_PURE_FLOAT,
		{ { 0 } },
	};
	r.props.f.format = format;
	return r;
}

RZ_API RZ_OWN char *rz_il_sort_pure_stringify(RzILSortPure sort);

typedef enum {
	RZ_IL_TYPE_EFFECT_NONE = 0, ///< nop
	RZ_IL_TYPE_EFFECT_DATA = (1 << 0), ///< mutating mems, vars, etc.
	RZ_IL_TYPE_EFFECT_CTRL = (1 << 1) ///< jmp/goto
} RzILTypeEffect;

#ifdef __cplusplus
}
#endif

#endif
