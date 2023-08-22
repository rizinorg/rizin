// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * \brief Per-kind pretty-printing for RzNumValue.
 *
 * Renders an RzNumValue into a multi-line, human-readable block whose
 * layout depends on the value's kind (ut64 multi-base table, float
 * scientific + bit pattern, big number decimal + hex + width). Kept
 * separate from the evaluator so consumers that only need to display
 * a value do not pull in the tree-sitter machinery.
 */

#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#include <rz_types.h>
#include <rz_util/rz_num.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_strbuf.h>

/**
 * \brief Human-readable name of an RzNumError category.
 *
 * Stable string suitable for diagnostics. Returns "unknown" for
 * values outside the enum.
 */
RZ_API const char *rz_num_error_name(RzNumError err) {
	switch (err) {
	case RZ_NUM_ERR_OK: return "ok";
	case RZ_NUM_ERR_PARSE: return "parse";
	case RZ_NUM_ERR_EMPTY: return "empty";
	case RZ_NUM_ERR_RESERVED_WORD: return "reserved word";
	case RZ_NUM_ERR_UNDEFINED_VAR: return "undefined variable";
	case RZ_NUM_ERR_DIV_ZERO: return "division by zero";
	case RZ_NUM_ERR_OVERFLOW: return "overflow";
	case RZ_NUM_ERR_TYPE_MISMATCH: return "type mismatch";
	case RZ_NUM_ERR_TIMEOUT: return "timeout";
	case RZ_NUM_ERR_UNCOMPUTABLE: return "uncomputable";
	case RZ_NUM_ERR_NOT_IMPLEMENTED: return "not implemented";
	case RZ_NUM_ERR_OUT_OF_MEMORY: return "out of memory";
	}
	return "unknown";
}

// Per-kind formatters

// Convert a ut64 to a 4-byte ASCII representation. Only emits a
// string line when every byte is printable; otherwise returns false
// and the caller skips that line.
static bool ut64_as_ascii(ut64 n, char *out, size_t outlen) {
	if (outlen < 8) {
		return false;
	}
	// Walk the bytes from low to high: that mirrors the legacy
	// `?` output's "string" line which reads back ASCII tokens
	// loaded from memory at that address.
	ut8 bytes[8];
	bool any = false;
	for (int i = 0; i < 8; i++) {
		bytes[i] = (ut8)((n >> (i * 8)) & 0xff);
		if (bytes[i] != 0) {
			any = true;
		}
	}
	if (!any) {
		return false;
	}
	int op = 0;
	out[op++] = '"';
	for (int i = 0; i < 8 && op + 2 < (int)outlen; i++) {
		ut8 b = bytes[i];
		if (b == 0) {
			break;
		}
		if (b < 0x20 || b >= 0x7f) {
			return false;
		}
		out[op++] = (char)b;
	}
	out[op++] = '"';
	out[op] = 0;
	return op > 2; // need at least one character between the quotes
}

static void print_ut64(const RzNumValue *v, RzStrBuf *sb) {
	ut64 n = v->val.n;
	char bits[65];
	char trits[42];
	char units[16];

	// Signed / unsigned interpretation in two widths. The split at
	// >> 32 mirrors the legacy `?` output: values that fit in 32
	// bits get their 32-bit signed/unsigned forms shown, otherwise
	// the 64-bit forms.
	if (n >> 32) {
		rz_strbuf_appendf(sb, "int64   %" PFMT64d "\n", (st64)n);
		rz_strbuf_appendf(sb, "uint64  %" PFMT64u "\n", (ut64)n);
	} else {
		rz_strbuf_appendf(sb, "int32   %d\n", (st32)n);
		rz_strbuf_appendf(sb, "uint32  %u\n", (ut32)n);
	}
	rz_strbuf_appendf(sb, "hex     0x%" PFMT64x "\n", n);
	rz_strbuf_appendf(sb, "octal   0%" PFMT64o "\n", n);

	rz_num_units(units, sizeof(units), n);
	rz_strbuf_appendf(sb, "unit    %s\n", units);

	// Segment:offset (real-mode style 16:12-bit split).
	ut32 seg = (ut32)(n >> 16) << 12;
	ut32 off = (ut32)(n & 0x0fff);
	rz_strbuf_appendf(sb, "segment %04x:%04x\n", seg, off);

	char ascii[24];
	if (ut64_as_ascii(n, ascii, sizeof(ascii))) {
		rz_strbuf_appendf(sb, "string  %s\n", ascii);
	}

	rz_str_bits64(bits, n);
	rz_strbuf_appendf(sb, "binary  0b%s\n", bits);
	rz_num_to_trits(trits, n);
	rz_strbuf_appendf(sb, "trits   0t%s\n", trits);
}

static void print_float(const RzNumValue *v, RzStrBuf *sb) {
	double d = v->val.d;
	// Sign-of-NaN is implementation-defined; normalise so the
	// printed form is identical across libcs.
	if (isnan(d) && signbit(d)) {
		d = -d;
	}
	rz_strbuf_appendf(sb, "float   %g\n", d);
	rz_strbuf_appendf(sb, "scifmt  %.17g\n", d);
	// IEEE-754 binary64 bit pattern (handy for back-conversion).
	union {
		double d;
		ut64 u;
	} u = { .d = d };
	rz_strbuf_appendf(sb, "hex     0x%016" PFMT64x "\n", u.u);
}

static void print_big(const RzNumValue *v, RzStrBuf *sb) {
	// Decimal output now goes through rz_big_to_decstr(), which
	// gives the exact base-10 form. The hex form is still emitted
	// alongside it: every other kind shows its hex pattern (as
	// "hex" for ut64, "hex" bit pattern for float, "hex" digest
	// for bitvector), and for symmetry the big print does too.
	char *dec = rz_big_to_decstr(v->val.big);
	if (dec) {
		rz_strbuf_appendf(sb, "decimal %s\n", dec);
		free(dec);
	}
	char *hex = rz_big_to_hexstr(v->val.big);
	if (hex) {
		// rz_big_to_hexstr already prefixes with "0x".
		rz_strbuf_appendf(sb, "hex     %s\n", hex);
		free(hex);
	}
	// Width hint: number of hex nibbles (and therefore bits) the
	// value actually occupies, useful for the reader who wants to
	// know whether this is a 65-bit value (one bit over ut64) or
	// a genuine multi-hundred-bit one.
	if (hex || dec) {
		// (already freed; recompute purely for the bit-width
		// estimate, which is cheap)
		char *h = rz_big_to_hexstr(v->val.big);
		if (h) {
			const char *p = h;
			if (*p == '-')
				p++;
			if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
				p += 2;
			}
			int nibbles = (int)strlen(p);
			rz_strbuf_appendf(sb, "width   %d bits (approx)\n",
				nibbles * 4);
			free(h);
		}
	}
}

static void print_bitvector(const RzNumValue *v, RzStrBuf *sb, bool utf8) {
	RzBitVector *bv = v->val.bv;
	if (!bv) {
		rz_strbuf_appendf(sb, "bitvec  (null)\n");
		return;
	}
	ut32 len = rz_bv_len(bv);
	char *hex = rz_bv_as_hex_string(bv, true);
	char *bin = rz_bv_as_string(bv);
	// In UTF-8 mode the width is folded into the value rows as a
	// subscript (the notation RzIL uses for bit-vector constants, via
	// the shared rz_bv_width_subscript formatter) and the binary form
	// drops the 0b prefix in favour of the subscript. The value rows
	// come first and the width row last in both modes.
	char *sub = utf8 ? rz_bv_width_subscript(len) : NULL;
	if (hex) {
		rz_strbuf_appendf(sb, "hex     %s%s\n", hex, sub ? sub : "");
	}
	if (bin) {
		if (utf8) {
			rz_strbuf_appendf(sb, "binary  %s%s\n", bin, sub ? sub : "");
		} else {
			rz_strbuf_appendf(sb, "binary  0b%s\n", bin);
		}
	}
	rz_strbuf_appendf(sb, "width   %u bits\n", len);
	free(sub);
	free(hex);
	free(bin);
}

// Public entry points

/**
 * \brief Format an RzNumValue into a multi-representation textual block.
 *
 * Each kind produces a different layout:
 *   UT64       hex / dec (signed + unsigned) / octal / binary /
 *              IEC byte unit / segment:offset / character form
 *   FLOAT      decimal scientific / shortest / hex bit pattern
 *   BIG        decimal + hex (lossless)
 *   BITVECTOR  bit-width / hex / binary
 *
 * On a value with v->err != RZ_NUM_ERR_OK, a single 'error <category>'
 * line is appended instead. The caller owns the RzStrBuf and is
 * responsible for releasing it.
 *
 * \param v   The value to format. Must be a valid (initialised)
 *            RzNumValue.
 * \param sb  Destination buffer. Must be non-NULL.
 */
RZ_API void rz_num_value_print(RZ_NONNULL const RzNumValue *v, RZ_NONNULL RzStrBuf *sb) {
	rz_num_value_print_ex(v, NULL, sb);
}

/**
 * \brief Like rz_num_value_print() but with explicit formatting options.
 *
 * With opts->utf8 set, a bit-vector additionally renders a compact
 * Unicode form (hex value with the bit-width as a subscript, e.g.
 * 0x2c\u2088), mirroring how RzIL renders bit-vectors in its Unicode
 * export. Other kinds are unaffected for now.
 *
 * \param v    The value to format. Must be a valid RzNumValue.
 * \param opts Formatting options. NULL selects the ASCII defaults.
 * \param sb   Destination buffer. Must be non-NULL.
 */
RZ_API void rz_num_value_print_ex(RZ_NONNULL const RzNumValue *v,
	RZ_NULLABLE const RzNumPrintOptions *opts, RZ_NONNULL RzStrBuf *sb) {
	rz_return_if_fail(v && sb);
	bool utf8 = opts && opts->utf8;
	if (v->err != RZ_NUM_ERR_OK) {
		rz_strbuf_appendf(sb, "error   %s\n", rz_num_error_name(v->err));
		return;
	}
	switch (v->kind) {
	case RZ_NUM_KIND_UT64:
		print_ut64(v, sb);
		break;
	case RZ_NUM_KIND_FLOAT:
		print_float(v, sb);
		break;
	case RZ_NUM_KIND_BIG:
		print_big(v, sb);
		break;
	case RZ_NUM_KIND_BITVECTOR:
		print_bitvector(v, sb, utf8);
		break;
	case RZ_NUM_KIND_NONE:
	default:
		rz_strbuf_appendf(sb, "kind    none\n");
		break;
	}
}

/**
 * \brief Compact one-line stringification of an RzNumValue.
 *
 * Suitable for inline display where the multi-line print would be
 * too noisy. Returns a freshly-allocated, caller-owned string.
 * On error returns NULL.
 */
RZ_API RZ_OWN char *rz_num_value_tostring(RZ_NONNULL const RzNumValue *v) {
	rz_return_val_if_fail(v, NULL);
	if (v->err != RZ_NUM_ERR_OK) {
		return rz_str_newf("error: %s", rz_num_error_name(v->err));
	}
	switch (v->kind) {
	case RZ_NUM_KIND_UT64:
		return rz_str_newf("0x%" PFMT64x, v->val.n);
	case RZ_NUM_KIND_FLOAT: {
		double d = v->val.d;
		if (isnan(d) && signbit(d)) {
			d = -d;
		}
		return rz_str_newf("%g", d);
	}
	case RZ_NUM_KIND_BIG: {
		char *hex = rz_big_to_hexstr(v->val.big);
		// rz_big_to_hexstr already includes "0x"; copy it to a
		// caller-owned buffer so the contract on this function
		// (caller frees) is straightforward.
		if (!hex) {
			return rz_str_dup("0x0");
		}
		return hex;
	}
	case RZ_NUM_KIND_BITVECTOR: {
		char *hex = rz_bv_as_hex_string(v->val.bv, true);
		if (!hex) {
			return rz_str_dup("0x0");
		}
		return hex;
	}
	case RZ_NUM_KIND_NONE:
	default:
		return rz_str_dup("(none)");
	}
}
