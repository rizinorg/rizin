// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file pf_parser_bitfield.c
 * \brief Bitfield spec parsing for the pf engine.
 *
 * Two flavours of `B`:
 *   - inline `B4(R=1,W=2,X=4)` -- named flags declared in the spec; the
 *     presence of `=` inside the parens is the discriminator.
 *   - typed `B4 (perm) flags` -- the flag set is resolved from the type
 *     DB at render time; only the byte width is parsed here.
 *
 * Cross-TU entry points carry the pf_ prefix (see pf_internal.h).
 */

#include <rz_util.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "pf_parser.h"
#include "pf_internal.h"

// Parse a comma-separated list of NAME=VALUE entries inside parens.
// VALUE accepts decimal, 0x... hex, or 0b... binary. Returns the
// number of entries appended; caller passes a growable array.
int pf_parse_bitflag_list(const char *body,
	RzPfBitflag **out_arr, int *out_count) {
	int cap = 8, n = 0;
	RzPfBitflag *arr = RZ_NEWS0(RzPfBitflag, cap);
	if (!arr) {
		return 0;
	}
	const char *p = body;
	while (*p) {
		while (*p == ',' || isspace((ut8)*p)) {
			p++;
		}
		if (!*p) {
			break;
		}
		const char *nm = p;
		while (*p && *p != '=' && *p != ',') {
			p++;
		}
		if (*p != '=') {
			/* Bad entry -- skip to next comma. */
			PF_DIAG(RZ_PF_ERR_ERROR, RZ_PF_ERRC_SYNTAX, nm,
				"pf: bitfield entry without '=' (expected NAME=VALUE), skipping\n");
			while (*p && *p != ',') {
				p++;
			}
			continue;
		}
		int nm_len = p - nm;
		while (nm_len > 0 && isspace((ut8)nm[nm_len - 1])) {
			nm_len--;
		}
		p++; /* eat '=' */
		while (isspace((ut8)*p)) {
			p++;
		}
		const char *vs = p;
		while (*p && *p != ',') {
			p++;
		}
		int vlen = p - vs;
		while (vlen > 0 && isspace((ut8)vs[vlen - 1])) {
			vlen--;
		}
		if (nm_len <= 0 || vlen <= 0) {
			PF_DIAG(RZ_PF_ERR_ERROR, RZ_PF_ERRC_SYNTAX, nm,
				"pf: bitfield entry has empty name or value, skipping\n");
			continue;
		}

		char *vstr = rz_str_ndup(vs, vlen);
		if (!vstr) {
			continue;
		}
		ut64 val = 0;
		if (vstr[0] == '0' && (vstr[1] == 'x' || vstr[1] == 'X')) {
			val = strtoull(vstr + 2, NULL, 16);
		} else if (vstr[0] == '0' && (vstr[1] == 'b' || vstr[1] == 'B')) {
			val = strtoull(vstr + 2, NULL, 2);
		} else {
			val = strtoull(vstr, NULL, 10);
		}
		free(vstr);

		if (n >= cap) {
			cap *= 2;
			RzPfBitflag *tmp = realloc(arr, cap * sizeof(RzPfBitflag));
			if (!tmp) {
				break;
			}
			arr = tmp;
		}
		arr[n].name = rz_str_ndup(nm, nm_len);
		arr[n].value = val;
		n++;
	}
	*out_arr = arr;
	*out_count = n;
	return n;
}

// Inline-bitfield re-interpretation: convert a parsed BIN field to
// BITFIELD when the immediately following parens contains '='.
// Returns extra bytes consumed (length of "(...)") or 0 if no.
int pf_maybe_inline_bitfield(const char *p_after_spec,
	const char *spec_end, RzPfField *fld, int size_bytes) {
	if (p_after_spec[0] != '(') {
		return 0;
	}
	const char *cl = strchr(p_after_spec + 1, ')');
	if (!cl || (spec_end && cl >= spec_end)) {
		return 0;
	}
	/* Discriminate: presence of '=' inside parens marks an inline
	 * bitflag map; otherwise leave the parens alone (it's a typedb
	 * name annotation, handled at field-name level). */
	const char *eq = memchr(p_after_spec + 1, '=', cl - (p_after_spec + 1));
	if (!eq) {
		return 0;
	}
	char *body = rz_str_ndup(p_after_spec + 1, cl - (p_after_spec + 1));
	if (!body) {
		return 0;
	}
	fld->type = RZ_PF_BITFIELD;
	fld->bitfield_size = size_bytes;
	pf_parse_bitflag_list(body, &fld->bitflags, &fld->bitflag_count);
	free(body);
	return (cl - p_after_spec) + 1;
}
