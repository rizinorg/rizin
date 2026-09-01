// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file pf_parser_bitvec.c
 * \brief Bitvector `v(N)` spec parsing and reading for the pf engine.
 *
 * A bitvector reads N individual bits (1..4096) and exposes them as N
 * separate 0/1 scalars, consuming exactly ceil(N/8) bytes. Unlike the
 * packed `:N` bitfield (RZ_PF_BITS), a bitvector reads whole bytes and
 * does not interact with the per-format bit cursor.
 *
 * Bit order within each byte is MSB-first by default; `,lsb` selects the
 * Intel-style order.
 *
 * Cross-TU entry points carry the pf_ prefix (see pf_internal.h).
 */

#include <rz_util.h>
#include <ctype.h>

#include "pf_parser.h"
#include "pf_internal.h"

/* Bitvector:  v(N)  or  v(N,lsb)  or  v(N,msb)
 *
 * Reads N individual bits from ceil(N/8) bytes of input and exposes
 * them as an array of N 0/1 values. Renders as space-separated bits
 * grouped by 8 (`1 0 1 0 1 1 0 0 | 0 1 1 ...`). JSON renders as a
 * string of '0'/'1' characters for compactness.
 *
 * Forensics use: page-frame allocation maps, NTFS $Bitmap clusters,
 * ext4 block/inode bitmaps, ELF DT_FLAGS_1, PE characteristics bits
 * that you want to *see* rather than collapse into a hex number.
 *
 * Bit order within each byte defaults to MSB-first (bit 7 of byte 0
 * is bit 0 of the vector); pass `lsb` for the Intel-ish order. */
int pf_parse_bitvec_spec(const char *p, const char *spec_end,
	RzPfField *fld) {
	int consumed = 1; /* the 'v' */
	if (p[consumed] != '(') {
		PF_DIAG(RZ_PF_ERR_ERROR, RZ_PF_ERRC_SYNTAX, p,
			"pf: 'v' bitvector spec missing '(N)' "
			"(use 'v(N)' or 'v(N,lsb)'), skipping\n");
		return 1;
	}
	consumed++; /* '(' */
	if (!isdigit((ut8)p[consumed])) {
		PF_DIAG(RZ_PF_ERR_ERROR, RZ_PF_ERRC_SYNTAX, p,
			"pf: 'v(N)' missing N (use 'v(N)' with N>=1), "
			"skipping\n");
		return consumed;
	}
	int n = 0;
	while (isdigit((ut8)p[consumed]) && n < 100000) {
		n = n * 10 + (p[consumed] - '0');
		consumed++;
	}
	if (n < 1) {
		PF_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_RANGE, p,
			"pf: bitvector width %d must be >= 1, clamping\n", n);
		n = 1;
	} else if (n > 4096) {
		PF_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_RANGE, p,
			"pf: bitvector width %d exceeds maximum 4096, "
			"clamping\n",
			n);
		n = 4096;
	}
	fld->type = RZ_PF_BITVEC;
	fld->bit_width = n;
	fld->bit_order = RZ_PF_BITORDER_MSB;
	/* Optional ,lsb / ,msb */
	if (p[consumed] == ',') {
		consumed++;
		while (p[consumed] == ' ') {
			consumed++;
		}
		if (p[consumed] == 'l' && p[consumed + 1] == 's' &&
			p[consumed + 2] == 'b') {
			fld->bit_order = RZ_PF_BITORDER_LSB;
			consumed += 3;
		} else if (p[consumed] == 'm' && p[consumed + 1] == 's' &&
			p[consumed + 2] == 'b') {
			fld->bit_order = RZ_PF_BITORDER_MSB;
			consumed += 3;
		} else {
			PF_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_SYNTAX, p,
				"pf: 'v(N,?)' unknown bit-order keyword "
				"(use 'lsb' or 'msb'); defaulting to msb\n");
			while (p + consumed < spec_end && p[consumed] != ')') {
				consumed++;
			}
		}
	}
	if (p[consumed] == ')') {
		consumed++;
	} else {
		PF_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_SYNTAX, p,
			"pf: 'v(N)' missing closing ')'\n");
	}
	return consumed;
}

/* Read a bitvector field: unpack fld->bit_width bits from buf[off..]
 * into val->scalars[0..nbits) as 0/1 bytes. Consumes ceil(N/8) bytes,
 * clamped to the available buffer.
 *
 * Worked example for `v(12)` over bytes `0xAB 0xCD` MSB-first:
 *   bit 0 = (0xAB >> 7) & 1 = 1
 *   bit 1 = (0xAB >> 6) & 1 = 0
 *   ...
 *   bit 8 = (0xCD >> 7) & 1 = 1
 *   bit 9 = (0xCD >> 6) & 1 = 1
 *   bit 10 = (0xCD >> 5) & 1 = 0
 *   bit 11 = (0xCD >> 4) & 1 = 0
 *   -> [ 1 0 1 0 1 0 1 1 | 1 1 0 0 ] */
int pf_read_bitvec_field(const RzPfField *fld, const ut8 *buf,
	int off, int avail, RzPfValue *val) {
	int nbits = fld->bit_width;
	int nbytes = (nbits + 7) / 8;
	if (nbytes > avail) {
		nbytes = avail;
		nbits = nbytes * 8;
	}
	val->count = nbits;
	val->bit_width = nbits;
	val->scalars = RZ_NEWS0(RzPfScalar, nbits > 0 ? nbits : 1);
	for (int i = 0; i < nbits; i++) {
		int byte_idx = i / 8;
		int bit_idx = i % 8;
		ut8 b = buf[off + byte_idx];
		ut8 bit;
		if (fld->bit_order == RZ_PF_BITORDER_LSB) {
			bit = (b >> bit_idx) & 1;
		} else {
			bit = (b >> (7 - bit_idx)) & 1;
		}
		val->scalars[i].v_u8 = bit;
	}
	return nbytes;
}
