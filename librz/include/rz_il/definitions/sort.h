// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_SORT_H
#define RZ_IL_SORT_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Type and Sort identifiers for values in the IL
 *
 * Our notion:
 *  * Types only tell which kind of value something is. E.g. whether it is a bitvector or boolean, but no other info.
 *    They can generally be expressed sufficiently as an enum.
 *  * Sorts carry any additional info that makes up the structure of a value, in particular bitvector sorts specify a concrete bit count.
 */

typedef enum {
	RZ_IL_TYPE_PURE_BOOL,
	RZ_IL_TYPE_PURE_BITVECTOR
} RzILTypePure;

typedef struct rz_il_sort_pure_t {
	RzILTypePure type;
	union {
		struct {
			ut32 length;
		} bv;
	} props;
} RzILSortPure;

static inline bool rz_il_sort_pure_eq(RzILSortPure a, RzILSortPure b) {
	if (a.type != b.type) {
		return false;
	}
	if (a.type == RZ_IL_TYPE_PURE_BITVECTOR && a.props.bv.length != b.props.bv.length) {
		return false;
	}
	return true;
}

static inline RzILSortPure rz_il_sort_pure_bool() {
	RzILSortPure r = {
		.type = RZ_IL_TYPE_PURE_BOOL
	};
	return r;
}

static inline RzILSortPure rz_il_sort_pure_bv(ut32 length) {
	RzILSortPure r = {
		.type = RZ_IL_TYPE_PURE_BITVECTOR
	};
	r.props.bv.length = length;
	return r;
}

#ifdef __cplusplus
}
#endif

#endif
