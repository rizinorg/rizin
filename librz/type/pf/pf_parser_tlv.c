// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file pf_parser_tlv.c
 * \brief TLV (Tag-Length-Value) parser, reader, and dispatch registry
 *        for the pf format DSL.
 *
 * TLV is a recurring on-disk pattern in many real-world binary
 * formats: BER/DER, NDEF, USB descriptors, Mach-O load commands,
 * BMP/PNG chunks (loosely), and many ad-hoc protocols. The pf DSL
 * exposes a single `V(...)` spec configurable by five named keys:
 *
 *     V(t=u1,l=u2,e=le,h=v,d=table_name)
 *
 *   t = tag scalar type   (u1/u2/u4/u8, optional case = endianness)
 *   l = length scalar     (same forms)
 *   e = default endian    (le/be), overrides for both tag and length
 *                         when they were given lower-case (LE).
 *   h = header inclusion  (v = value-only [default], a = length covers
 *                         tag+length+value, l = length covers
 *                         length+value).
 *   d = dispatch table    (typedb registry entry name; tag -> child
 *                         pf format. When unset, the value payload is
 *                         stored as raw bytes.)
 *
 * The dispatch registry uses a flat namespace inside the typedb's
 * `formats` hash. Keys are of the form `tlv.<table>.<hex-tag>` and
 * values are pf format strings. Look-up uses uppercase-hex with no
 * leading zeros, e.g. `tlv.usb_desc.5` for tag 0x05.
 *
 * This file is intentionally self-contained: the only types it
 * depends on come from pf_parser.h, and the only helpers it borrows
 * from pf_parser.c are forward-declared at the top of the file.
 */

#include <rz_endian.h>
#include <rz_util.h>
#include <ctype.h>
#include <stdlib.h>

#include "pf_parser.h"
#include "pf_internal.h"

/* TLV diagnostics share the main parser's positioned-error machinery
 * via the common PF_DIAG macro (declared in pf_internal.h). */
#define TLV_DIAG(sev, cat, src_ptr, ...) \
	PF_DIAG(sev, cat, src_ptr, __VA_ARGS__)

/* Compose the dispatch key from table name and tag. The caller frees. */
static char *tlv_key(const char *table, ut64 tag) {
	return rz_str_newf("tlv.%s.%" PFMT64x, table, tag);
}

/**
 * \brief Register a TLV dispatch entry.
 *
 * Maps `(table_name, tag)` to a named pf format string that will be
 * applied to the value payload when a TLV record with this tag is
 * decoded under this table.
 */
RZ_API void rz_pf_tlv_register(RZ_BORROW RzTypeDB *typedb,
	const char *table_name, ut64 tag,
	const char *child_format_name) {
	rz_return_if_fail(typedb && table_name && child_format_name);
	char *key = tlv_key(table_name, tag);
	if (!key) {
		return;
	}
	rz_type_db_format_set(typedb, key, child_format_name);
	free(key);
}

/**
 * \brief Look up the child pf format name for a given TLV tag.
 *
 * Returns NULL if the table or tag is not registered. The returned
 * pointer is borrowed from the typedb and must not be freed.
 */
RZ_API RZ_BORROW const char *rz_pf_tlv_lookup(
	RZ_BORROW const RzTypeDB *typedb,
	const char *table_name, ut64 tag) {
	if (!typedb || !table_name) {
		return NULL;
	}
	char *key = tlv_key(table_name, tag);
	if (!key) {
		return NULL;
	}
	const char *r = rz_type_db_format_get(typedb, key);
	free(key);
	return r;
}

/* Parse a `uN` / `UN` token: lower-case = LE, upper = BE. Returns
 * the byte size {1,2,4,8} and writes the endian via *endian_out, or
 * 0 if the token is unrecognised. The endian default applies when
 * the spec was lower-case but a top-level e=be later forces BE; the
 * caller handles that override. */
static int parse_tlv_int_token(const char *s,
	RzPfEndian *endian_out) {
	if (!s || !*s) {
		return 0;
	}
	char c = s[0];
	char low = (char)tolower((ut8)c);
	if (low != 'u') {
		return 0;
	}
	int sz = 0;
	switch (s[1]) {
	case '1': sz = 1; break;
	case '2': sz = 2; break;
	case '4': sz = 4; break;
	case '8': sz = 8; break;
	default: return 0;
	}
	*endian_out = (c == 'U') ? RZ_PF_ENDIAN_BE : RZ_PF_ENDIAN_LE;
	return sz;
}

/**
 * \brief Parse a single `V(...)` spec into RzPfField.tlv_spec.
 *
 * Called from the main parser dispatcher. \p p points at the leading
 * 'V'. Returns the number of characters consumed (`V(...)` length) or
 * 0 if there are no parentheses, in which case the bare `V` is
 * treated as an unconfigured TLV with safe defaults (tag=u1, len=u2,
 * value as raw).
 */
int pf_parse_tlv_spec(const char *p, const char *end,
	RzPfField *fld) {
	rz_return_val_if_fail(p && fld, 0);
	fld->type = RZ_PF_TLV;
	fld->endian = RZ_PF_ENDIAN_CTX;

	RzPfTlvSpec *spec = RZ_NEW0(RzPfTlvSpec);
	if (!spec) {
		return 1;
	}
	spec->tag_size = 1;
	spec->len_size = 2;
	spec->tag_endian = RZ_PF_ENDIAN_LE;
	spec->len_endian = RZ_PF_ENDIAN_LE;
	spec->len_includes_header = false;
	spec->dispatch_name = NULL;
	fld->tlv_spec = spec;

	if (p[1] != '(') {
		TLV_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_SYNTAX, p,
			"pf: V: bare 'V' uses defaults t=u1,l=u2 (no dispatch); "
			"add '(t=...,l=...,d=table)' to configure\n");
		return 1;
	}
	const char *cl = strchr(p + 2, ')');
	if (!cl || (end && cl >= end)) {
		TLV_DIAG(RZ_PF_ERR_ERROR, RZ_PF_ERRC_SYNTAX, p + 1,
			"pf: V: missing closing ')' for TLV spec\n");
		return 1;
	}
	if (cl == p + 2) {
		TLV_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_SYNTAX, p + 1,
			"pf: V(): empty body, defaults t=u1,l=u2 will be used\n");
		return (int)(cl - p) + 1;
	}

	char *body = rz_str_ndup(p + 2, cl - (p + 2));
	if (!body) {
		return (int)(cl - p) + 1;
	}

	/* Parse comma-separated key=value list. */
	RzPfEndian default_e = RZ_PF_ENDIAN_CTX;
	char *cursor = body;
	while (*cursor) {
		while (*cursor == ',' || isspace((ut8)*cursor)) {
			cursor++;
		}
		if (!*cursor) {
			break;
		}
		char *eq = strchr(cursor, '=');
		if (!eq) {
			TLV_DIAG(RZ_PF_ERR_ERROR, RZ_PF_ERRC_SYNTAX,
				p + 2 + (cursor - body),
				"pf: V: expected 'key=value', got bare token '%s'\n",
				cursor);
			break;
		}
		char *next = strchr(eq + 1, ',');
		if (!next) {
			next = eq + 1 + strlen(eq + 1);
		}

		int klen = eq - cursor;
		while (klen > 0 && isspace((ut8)cursor[klen - 1])) {
			klen--;
		}
		int vlen = next - (eq + 1);
		while (vlen > 0 && isspace((ut8)(eq + 1)[vlen - 1])) {
			vlen--;
		}

		char *k = rz_str_ndup(cursor, klen);
		char *v = rz_str_ndup(eq + 1, vlen);
		if (k && v) {
			if (!strcmp(k, "t")) {
				RzPfEndian en;
				int sz = parse_tlv_int_token(v, &en);
				if (sz) {
					spec->tag_size = sz;
					spec->tag_endian = en;
				} else {
					TLV_DIAG(RZ_PF_ERR_ERROR, RZ_PF_ERRC_RANGE,
						p + 2 + (cursor - body),
						"pf: V: bad tag type '%s' "
						"(expected u1/u2/u4/u8)\n",
						v);
				}
			} else if (!strcmp(k, "l")) {
				RzPfEndian en;
				int sz = parse_tlv_int_token(v, &en);
				if (sz) {
					spec->len_size = sz;
					spec->len_endian = en;
				} else {
					TLV_DIAG(RZ_PF_ERR_ERROR, RZ_PF_ERRC_RANGE,
						p + 2 + (cursor - body),
						"pf: V: bad length type '%s' "
						"(expected u1/u2/u4/u8)\n",
						v);
				}
			} else if (!strcmp(k, "e")) {
				if (!rz_str_casecmp(v, "be")) {
					default_e = RZ_PF_ENDIAN_BE;
				} else if (!rz_str_casecmp(v, "le")) {
					default_e = RZ_PF_ENDIAN_LE;
				} else {
					TLV_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_SEMANTIC,
						p + 2 + (cursor - body),
						"pf: V: unknown endian '%s' "
						"(expected le or be)\n",
						v);
				}
			} else if (!strcmp(k, "h")) {
				/* a = all (tag+len+value), l = len+value,
				 * v = value only (default). */
				if (v[0] == 'a' || v[0] == 'l') {
					spec->len_includes_header = true;
				} else if (v[0] != 'v') {
					TLV_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_SEMANTIC,
						p + 2 + (cursor - body),
						"pf: V: unknown header inclusion '%s' "
						"(expected v, l, or a)\n",
						v);
				}
			} else if (!strcmp(k, "d")) {
				free(spec->dispatch_name);
				spec->dispatch_name = rz_str_ndup(v, strlen(v));
			} else {
				TLV_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_SEMANTIC,
					p + 2 + (cursor - body),
					"pf: V: unknown key '%s' "
					"(expected t, l, e, h, or d)\n",
					k);
			}
		}
		free(k);
		free(v);
		if (!*next) {
			break;
		}
		cursor = next + 1;
	}
	/* Apply default endian override only to slots that were not set
	 * with explicit upper-case. We treat the lower-case default as
	 * "open to override". */
	if (default_e != RZ_PF_ENDIAN_CTX) {
		spec->tag_endian = default_e;
		spec->len_endian = default_e;
	}
	free(body);
	return (int)(cl - p) + 1;
}

/* Read a u1/u2/u4/u8 in given endianness. */
static ut64 read_uN(const ut8 *buf, int sz, RzPfEndian e) {
	bool be = (e == RZ_PF_ENDIAN_BE);
	switch (sz) {
	case 1: return buf[0];
	case 2: return rz_read_ble16(buf, be);
	case 4: return rz_read_ble32(buf, be);
	case 8: return rz_read_ble64(buf, be);
	default: return 0;
	}
}

/**
 * \brief Read a TLV record at \p off.
 *
 * Stores the tag and value-length in val->tlv_tag/tlv_length. The
 * value payload is either:
 *  - decoded recursively through the dispatch-registered child format
 *    (placed in val->children), or
 *  - stored as raw bytes (val->scalars[0].v_raw, val->raw_len) if no
 *    dispatch is configured or the tag is unknown.
 *
 * Returns the total bytes consumed (header + value).
 */
int pf_tlv_read(const RzPfField *fld, const ut8 *buf,
	int off, int buf_len, ut64 base_addr,
	const RzPfCtx *ctx, int depth, RzPfValue *val) {
	rz_return_val_if_fail(fld && fld->tlv_spec && buf && val, 0);
	const RzPfTlvSpec *spec = fld->tlv_spec;
	int header = spec->tag_size + spec->len_size;
	int avail = buf_len - off;
	if (avail < header) {
		return avail;
	}

	ut64 tag = read_uN(buf + off, spec->tag_size, spec->tag_endian);
	ut64 raw_len = read_uN(buf + off + spec->tag_size,
		spec->len_size, spec->len_endian);

	ut64 value_len = raw_len;
	if (spec->len_includes_header) {
		/* When 'a'/all: length covers tag+len+value, subtract
		 * both. When 'l': length covers len+value, subtract len. */
		ut64 to_subtract = (ut64)spec->len_size;
		/* We don't distinguish a vs l beyond this point -- both
		 * are encoded as len_includes_header here; assume 'a'
		 * (most common in BER/DER). */
		to_subtract += (ut64)spec->tag_size;
		if (raw_len >= to_subtract) {
			value_len = raw_len - to_subtract;
		} else {
			value_len = 0;
		}
	}
	if (value_len > (ut64)(avail - header)) {
		value_len = (ut64)(avail - header);
	}

	val->tlv_tag = tag;
	val->tlv_length = value_len;

	int value_off = off + header;
	const char *child_fmt_name = rz_pf_tlv_lookup(
		ctx ? ctx->typedb : NULL,
		spec->dispatch_name, tag);

	if (child_fmt_name && ctx && depth + 1 < ctx->max_depth) {
		/* Recurse through the named child format. Reuse a
		 * nested-struct-style approach but keep it self-contained
		 * here so we don't expose internals. */
		const char *child_fmt = rz_pf_resolve_name(
			ctx->typedb, child_fmt_name);
		if (!RZ_STR_ISEMPTY(child_fmt)) {
			RzPfFormat *sub = rz_pf_parse(child_fmt);
			if (sub) {
				int sub_count = 0;
				RzPfValue *sub_vals = rz_pf_read(sub,
					buf + value_off, (int)value_len,
					base_addr + value_off, ctx,
					&sub_count);
				rz_pf_format_free(sub);
				if (sub_vals && sub_count > 0) {
					val->children = sub_vals;
					val->nchildren = sub_count;
					return header + (int)value_len;
				}
				/* Empty: free and fall through to raw. */
				free(sub_vals);
			}
		}
	}

	/* No dispatch: store the payload as raw bytes. */
	val->count = 1;
	val->scalars = RZ_NEWS0(RzPfScalar, 1);
	if (val->scalars && value_len > 0) {
		val->scalars[0].v_raw = RZ_NEWS(ut8, (int)value_len);
		if (val->scalars[0].v_raw) {
			memcpy(val->scalars[0].v_raw,
				buf + value_off, (int)value_len);
		}
	}
	val->raw_len = (int)value_len;
	return header + (int)value_len;
}
