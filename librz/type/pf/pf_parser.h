// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file pf_parser.h
 * \brief Internal alias header for the pf engine.
 *
 * The public pf parser API now lives in <rz_pf.h>; source files under
 * librz/type/pf/ continue to include "pf_parser.h" unchanged. This
 * header also carries the small set of helpers shared between the
 * parser and the renderers (is_string_type, is_raw_type, endian_str,
 * pf_vasprintf) as static inlines, so every TU gets its own copy with
 * no cross-TU link dependency.
 */

#ifndef PF_PARSER_H
#define PF_PARSER_H

#include <rz_pf.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

/* Internal helpers shared between pf_parser.c (reader) and pf_render.c
 * (renderers). Defined here as static inlines so both translation
 * units get their own copy without a cross-TU link dependency. */
static inline bool is_string_type(RzPfFieldType t) {
	return t == RZ_PF_ZSTRING || t == RZ_PF_STRPTR;
}

static inline bool is_raw_type(RzPfFieldType t) {
	return t == RZ_PF_HEXDUMP || t == RZ_PF_UINT128 ||
		t == RZ_PF_GUID || t == RZ_PF_TLV;
}

/* Portable replacement for vasprintf() -- which is a glibc extension
 * not provided by MSVC. The contract matches vasprintf(3) on success:
 * the caller owns *out and must free() it. On failure *out is set to
 * NULL and -1 is returned. ap is consumed in either case. */
static inline int pf_vasprintf(char **out, const char *fmt, va_list ap) {
	va_list ap2;
	va_copy(ap2, ap);
	int n = vsnprintf(NULL, 0, fmt, ap2);
	va_end(ap2);
	if (n < 0) {
		*out = NULL;
		return -1;
	}
	char *buf = malloc((size_t)n + 1);
	if (!buf) {
		*out = NULL;
		return -1;
	}
	int n2 = vsnprintf(buf, (size_t)n + 1, fmt, ap);
	if (n2 < 0) {
		free(buf);
		*out = NULL;
		return -1;
	}
	*out = buf;
	return n2;
}

/* JSON endian-marker string for a parsed field's endian flag. */
static inline const char *endian_str(RzPfEndian e) {
	switch (e) {
	case RZ_PF_ENDIAN_LE: return "little";
	case RZ_PF_ENDIAN_BE: return "big";
	default: return "context";
	}
}

#endif
