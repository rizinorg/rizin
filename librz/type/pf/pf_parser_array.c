// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file pf_parser_array.c
 * \brief Array-count resolution for the pf engine.
 *
 * Arrays come in two forms:
 *   - literal `[N]T` -- a fixed count N baked into the field.
 *   - by-reference `[@name]T` -- the count is the integer value of an
 *     earlier sibling field named `name` in the same struct scope.
 *
 * pf_resolve_array_count() turns either form (or a plain scalar field)
 * into a concrete element count; pf_lookup_sibling_value() backs the
 * by-reference case by scanning the sibling values recorded so far in
 * the ReadState.
 *
 * Cross-TU entry points carry the pf_ prefix (see pf_internal.h).
 */

#include <rz_util.h>
#include <string.h>

#include "pf_parser.h"
#include "pf_internal.h"

/* Look up the most-recent same-name scalar in the sibling array. */
ut64 pf_lookup_sibling_value(const ReadState *st, const char *name) {
	if (!st || !name) {
		return 0;
	}
	for (int i = st->n_siblings - 1; i >= 0; i--) {
		const RzPfValue *v = &st->siblings[i];
		if (!v->name || strcmp(v->name, name)) {
			continue;
		}
		if (v->count < 1 || !v->scalars) {
			continue;
		}
		const RzPfScalar *s = &v->scalars[0];
		/* Match by field type -> pick the right slot. */
		switch (v->type) {
		case RZ_PF_HEX8:
		case RZ_PF_DEC_U8:
		case RZ_PF_OCT8:
		case RZ_PF_BIN8:
		case RZ_PF_CHAR:
			return s->v_u8;
		case RZ_PF_DEC_S8: return (ut64)(st64)s->v_s8;
		case RZ_PF_HEX16:
		case RZ_PF_DEC_U16:
		case RZ_PF_OCT16:
		case RZ_PF_BIN16:
			return s->v_u16;
		case RZ_PF_DEC_S16: return (ut64)(st64)s->v_s16;
		case RZ_PF_HEX32:
		case RZ_PF_DEC_U32:
		case RZ_PF_OCT32:
		case RZ_PF_BIN32:
		case RZ_PF_ENUM:
		case RZ_PF_BITFIELD:
			return s->v_u32;
		case RZ_PF_DEC_S32: return (ut64)(st64)s->v_s32;
		case RZ_PF_HEX64:
		case RZ_PF_DEC_U64:
		case RZ_PF_OCT64:
		case RZ_PF_BIN64:
		case RZ_PF_POINTER:
		case RZ_PF_ULEB128:
		case RZ_PF_BITS:
			return s->v_u64;
		case RZ_PF_DEC_S64:
		case RZ_PF_SLEB128:
			return (ut64)s->v_s64;
		default:
			return 0;
		}
	}
	RZ_LOG_WARN("pf: [@%s] no earlier field with that name\n", name);
	return 0;
}

/* Resolve the effective array count for a field, honoring [@name]. */
int pf_resolve_array_count(const RzPfField *fld, const ReadState *st) {
	if (fld->length_ref) {
		ut64 v = pf_lookup_sibling_value(st, fld->length_ref);
		if (v > INT32_MAX) {
			RZ_LOG_WARN("pf: [@%s] count %" PFMT64u
				    " too large, clamping\n",
				fld->length_ref, v);
			v = INT32_MAX;
		}
		return (int)v;
	}
	return (fld->array_count > 0) ? fld->array_count : 1;
}
