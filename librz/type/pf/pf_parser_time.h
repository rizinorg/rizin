// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file pf_parser_time.h
 * \brief Timestamp wire-format API for the pf engine.
 *
 * Declares the timestamp helpers implemented in pf_parser_time.c:
 * format-name lookups, per-format size/type queries, and the
 * read/convert/render entry points used by the parser and renderers.
 * Private to librz/type/pf/; not installed.
 */

#ifndef PF_PARSER_TIME_H
#define PF_PARSER_TIME_H

#include <time.h>
#include <rz_util.h>
#include "pf_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

/* String table lookups. */
RZ_API RzPfTimeFmt rz_pf_timefmt_from_string(const char *name);
RZ_API const char *rz_pf_timefmt_as_string(RzPfTimeFmt fmt);

/* On-wire byte size of a timestamp value. */
RZ_API int rz_pf_timefmt_size(RzPfTimeFmt fmt);

/* True if the raw on-wire representation is an IEEE 754 double. */
RZ_API bool rz_pf_timefmt_is_float(RzPfTimeFmt fmt);

/* Decode a raw timestamp scalar into broken-down UTC time and optional
 * sub-second nanoseconds. Returns false if the value is out of range or
 * the format is unknown. */
RZ_API bool rz_pf_timestamp_to_tm(RzPfTimeFmt fmt,
	const RzPfScalar *raw,
	struct tm *out_tm, int *out_subsec_ns);

/* Read a timestamp field from a byte buffer at \p off. \p be is the
 * resolved endianness for the field. Returns the number of bytes
 * consumed (0 on short buffer). */
RZ_API int rz_pf_timestamp_read(const ut8 *buf, int off, int avail,
	RzPfTimeFmt fmt, bool be, RzPfScalar *out);

/* Format a timestamp scalar as a human-readable UTC string and append to
 * \p sb. Writes "(invalid timestamp)" if decoding fails. */
RZ_API void rz_pf_timestamp_format_str(RzStrBuf *sb, RzPfTimeFmt fmt,
	const RzPfScalar *raw);

/* C-language type string suitable for emitting a C struct member. */
RZ_API const char *rz_pf_timefmt_ctype(RzPfTimeFmt fmt);

#ifdef __cplusplus
}
#endif

#endif /* PF_PARSER_TIME_H */
