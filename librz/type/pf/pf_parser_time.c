// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file pf_parser_time.c
 * \brief Timestamp decoders and renderers for the pf format parser.
 *
 * Owns the full set of timestamp formats reachable through `t(...)` and
 * `T(...)` in the pf DSL: the Unix family (sec/ms/us/ns), Microsoft
 * FILETIME, MS-DOS packed date/time, Apple HFS+, Microsoft OLE
 * automation, WebKit/Chrome, and Apple Cocoa NSDate.
 *
 * Functions here are split out from pf_parser.c so the timestamp logic
 * stays isolated: every entry point takes a RzPfScalar (already read
 * from the buffer with the right endianness) and produces either a
 * struct tm or a UTC display string. No format-string parsing happens
 * in this file.
 */

#include <rz_endian.h>
#include <time.h>
#include <math.h>

#include "pf_parser.h"
#include "pf_parser_time.h"

/* All epoch deltas are seconds, relative to the Unix epoch
 * (1970-01-01 00:00:00 UTC). */
#define EPOCH_DIFF_1601_1970 11644473600LL
#define EPOCH_DIFF_1904_1970 2082844800LL
#define EPOCH_DIFF_2001_1970 978307200LL
/* OLE date origin is 1899-12-30; offset is days, not seconds. */
#define OLE_DAYS_TO_UNIX_EPOCH 25569.0
/* FILETIME counts 100-nanosecond ticks. */
#define FILETIME_TICKS_PER_SEC 10000000LL

typedef struct {
	const char *name;
	RzPfTimeFmt fmt;
} TimeFmtEntry;

static const TimeFmtEntry timefmt_table[] = {
	{ "unix32", RZ_PF_TIMEFMT_UNIX32 },
	{ "unix64", RZ_PF_TIMEFMT_UNIX64 },
	{ "unixms", RZ_PF_TIMEFMT_UNIXMS },
	{ "unixus", RZ_PF_TIMEFMT_UNIXUS },
	{ "unixns", RZ_PF_TIMEFMT_UNIXNS },
	{ "filetime", RZ_PF_TIMEFMT_FILETIME },
	{ "ntfs", RZ_PF_TIMEFMT_FILETIME }, /* alias */
	{ "dos", RZ_PF_TIMEFMT_DOS },
	{ "hfs", RZ_PF_TIMEFMT_HFS },
	{ "oletime", RZ_PF_TIMEFMT_OLETIME },
	{ "webkit", RZ_PF_TIMEFMT_WEBKIT },
	{ "cocoa", RZ_PF_TIMEFMT_COCOA },
	{ NULL, 0 }
};

/**
 * \brief Look up a timestamp format by name.
 * \param name Canonical name (e.g. "filetime") or alias (e.g. "ntfs").
 * \return The matching RzPfTimeFmt, or RZ_PF_TIMEFMT_UNIX32 if unknown.
 *
 * Empty input also returns RZ_PF_TIMEFMT_UNIX32. Unknown names produce
 * a warning log and the same fallback so that misspelled format names
 * in user input do not silently produce wildly different output.
 */
RZ_API RzPfTimeFmt rz_pf_timefmt_from_string(const char *name) {
	if (RZ_STR_ISEMPTY(name)) {
		return RZ_PF_TIMEFMT_UNIX32;
	}
	for (const TimeFmtEntry *e = timefmt_table; e->name; e++) {
		if (!rz_str_casecmp(name, e->name)) {
			return e->fmt;
		}
	}
	RZ_LOG_WARN("pf: unknown timestamp format '%s', defaulting to unix32\n", name);
	return RZ_PF_TIMEFMT_UNIX32;
}

/**
 * \brief Canonical name for a timestamp format, suitable for round-tripping.
 *
 * Aliases such as "ntfs" are mapped to their canonical name ("filetime").
 */
RZ_API const char *rz_pf_timefmt_as_string(RzPfTimeFmt fmt) {
	switch (fmt) {
	case RZ_PF_TIMEFMT_UNIX32: return "unix32";
	case RZ_PF_TIMEFMT_UNIX64: return "unix64";
	case RZ_PF_TIMEFMT_UNIXMS: return "unixms";
	case RZ_PF_TIMEFMT_UNIXUS: return "unixus";
	case RZ_PF_TIMEFMT_UNIXNS: return "unixns";
	case RZ_PF_TIMEFMT_FILETIME: return "filetime";
	case RZ_PF_TIMEFMT_DOS: return "dos";
	case RZ_PF_TIMEFMT_HFS: return "hfs";
	case RZ_PF_TIMEFMT_OLETIME: return "oletime";
	case RZ_PF_TIMEFMT_WEBKIT: return "webkit";
	case RZ_PF_TIMEFMT_COCOA: return "cocoa";
	default: return "unknown";
	}
}

/**
 * \brief Byte width of a timestamp on the wire.
 *
 * Unix32, DOS and HFS+ are 4-byte; everything else is 8-byte.
 */
RZ_API int rz_pf_timefmt_size(RzPfTimeFmt fmt) {
	switch (fmt) {
	case RZ_PF_TIMEFMT_UNIX32:
	case RZ_PF_TIMEFMT_DOS:
	case RZ_PF_TIMEFMT_HFS:
		return 4;
	case RZ_PF_TIMEFMT_UNIX64:
	case RZ_PF_TIMEFMT_UNIXMS:
	case RZ_PF_TIMEFMT_UNIXUS:
	case RZ_PF_TIMEFMT_UNIXNS:
	case RZ_PF_TIMEFMT_FILETIME:
	case RZ_PF_TIMEFMT_OLETIME:
	case RZ_PF_TIMEFMT_WEBKIT:
	case RZ_PF_TIMEFMT_COCOA:
		return 8;
	default:
		return 4;
	}
}

/**
 * \brief True if the on-wire representation is an IEEE 754 double.
 *
 * Only OLE automation date and Cocoa NSDate use floating-point.
 */
RZ_API bool rz_pf_timefmt_is_float(RzPfTimeFmt fmt) {
	return fmt == RZ_PF_TIMEFMT_OLETIME || fmt == RZ_PF_TIMEFMT_COCOA;
}

/**
 * MS-DOS packed timestamp decoder.
 *
 * Layout in a little-endian 32-bit value:
 *   bits  0..4   : seconds / 2  (DOS resolution is 2s)
 *   bits  5..10  : minutes
 *   bits 11..15  : hours
 *   bits 16..20  : day of month
 *   bits 21..24  : month (1-based)
 *   bits 25..31  : year - 1980
 *
 * Returns false if any decoded field is out of range.
 */
static bool dos_to_tm(ut32 dosval, struct tm *out) {
	ut16 dos_time = (ut16)(dosval & 0xFFFF);
	ut16 dos_date = (ut16)(dosval >> 16);

	memset(out, 0, sizeof(*out));
	out->tm_sec = (dos_time & 0x1F) * 2;
	out->tm_min = (dos_time >> 5) & 0x3F;
	out->tm_hour = (dos_time >> 11) & 0x1F;
	out->tm_mday = dos_date & 0x1F;
	out->tm_mon = ((dos_date >> 5) & 0x0F) - 1;
	out->tm_year = ((dos_date >> 9) & 0x7F) + 80;

	return (out->tm_mon >= 0 && out->tm_mon <= 11 &&
		out->tm_mday >= 1 && out->tm_mday <= 31 &&
		out->tm_hour <= 23 && out->tm_min <= 59 &&
		out->tm_sec <= 59);
}

/**
 * \brief Decode a raw timestamp scalar to UTC broken-down time.
 *
 * The scalar must already hold the value in the correct slot for the
 * format: v_u32 for 4-byte integer formats, v_u64 for 8-byte integer
 * formats, v_f64 for OLE/Cocoa. The reader (rz_pf_timestamp_read) takes
 * care of placing the bytes in the right slot.
 *
 * \param out_subsec_ns Optional out-param for sub-second precision; set
 *                      to 0 for second-resolution formats.
 * \return true on success, false on unknown format or out-of-range DOS
 *         field. struct tm is left zeroed on failure.
 */
RZ_API bool rz_pf_timestamp_to_tm(RzPfTimeFmt fmt,
	const RzPfScalar *raw,
	struct tm *out_tm, int *out_subsec_ns) {
	rz_return_val_if_fail(raw && out_tm, false);

	memset(out_tm, 0, sizeof(*out_tm));
	if (out_subsec_ns) {
		*out_subsec_ns = 0;
	}

	time_t unix_sec = 0;
	long subsec_ns = 0;

	switch (fmt) {
	case RZ_PF_TIMEFMT_UNIX32:
		unix_sec = (time_t)(st32)raw->v_u32;
		break;
	case RZ_PF_TIMEFMT_UNIX64:
		unix_sec = (time_t)(st64)raw->v_u64;
		break;
	case RZ_PF_TIMEFMT_UNIXMS: {
		st64 ms = (st64)raw->v_u64;
		unix_sec = (time_t)(ms / 1000LL);
		subsec_ns = (long)(ms % 1000LL) * 1000000L;
		break;
	}
	case RZ_PF_TIMEFMT_UNIXUS: {
		st64 us = (st64)raw->v_u64;
		unix_sec = (time_t)(us / 1000000LL);
		subsec_ns = (long)(us % 1000000LL) * 1000L;
		break;
	}
	case RZ_PF_TIMEFMT_UNIXNS: {
		st64 ns = (st64)raw->v_u64;
		unix_sec = (time_t)(ns / 1000000000LL);
		subsec_ns = (long)(ns % 1000000000LL);
		break;
	}
	case RZ_PF_TIMEFMT_FILETIME: {
		/* FILETIME is 100ns ticks since 1601-01-01. Convert to
		 * 100ns ticks since 1970-01-01, then split into sec / ns. */
		st64 utk = (st64)raw->v_u64 -
			EPOCH_DIFF_1601_1970 * FILETIME_TICKS_PER_SEC;
		unix_sec = (time_t)(utk / FILETIME_TICKS_PER_SEC);
		subsec_ns = (long)(utk % FILETIME_TICKS_PER_SEC) * 100L;
		break;
	}
	case RZ_PF_TIMEFMT_DOS:
		return dos_to_tm(raw->v_u32, out_tm);
	case RZ_PF_TIMEFMT_HFS:
		unix_sec = (time_t)((st64)raw->v_u32 - EPOCH_DIFF_1904_1970);
		break;
	case RZ_PF_TIMEFMT_OLETIME: {
		/* OLE Automation date: days since 1899-12-30 as a double. */
		double ole = raw->v_f64;
		double ts = (ole - OLE_DAYS_TO_UNIX_EPOCH) * 86400.0;
		unix_sec = (time_t)ts;
		subsec_ns = (long)((ts - (double)unix_sec) * 1e9);
		break;
	}
	case RZ_PF_TIMEFMT_WEBKIT: {
		/* WebKit/Chrome: microseconds since 1601-01-01. */
		st64 us1601 = (st64)raw->v_u64;
		st64 us1970 = us1601 - EPOCH_DIFF_1601_1970 * 1000000LL;
		unix_sec = (time_t)(us1970 / 1000000LL);
		subsec_ns = (long)(us1970 % 1000000LL) * 1000L;
		break;
	}
	case RZ_PF_TIMEFMT_COCOA: {
		/* Cocoa NSDate: seconds since 2001-01-01 as a double. */
		double ts = raw->v_f64 + (double)EPOCH_DIFF_2001_1970;
		unix_sec = (time_t)ts;
		subsec_ns = (long)((ts - (double)unix_sec) * 1e9);
		break;
	}
	default:
		return false;
	}

	struct tm *r = gmtime(&unix_sec);
	if (!r) {
		return false;
	}
	memcpy(out_tm, r, sizeof(*out_tm));
	if (out_subsec_ns) {
		*out_subsec_ns = (int)subsec_ns;
	}
	return true;
}

/**
 * \brief Read a timestamp's raw bytes from a buffer.
 *
 * Picks the right slot in RzPfScalar based on the format (v_u32, v_u64
 * or v_f64) and uses the field-resolved endianness for the byte read.
 *
 * \return Number of bytes consumed, or 0 if avail < size.
 */
RZ_API int rz_pf_timestamp_read(const ut8 *buf, int off, int avail,
	RzPfTimeFmt fmt, bool be, RzPfScalar *out) {
	memset(out, 0, sizeof(*out));
	int sz = rz_pf_timefmt_size(fmt);
	if (avail < sz) {
		return 0;
	}
	const ut8 *p = buf + off;
	if (rz_pf_timefmt_is_float(fmt)) {
		out->v_f64 = be ? rz_read_be_double(p) : rz_read_le_double(p);
	} else if (sz == 4) {
		out->v_u32 = rz_read_ble32(p, be);
	} else {
		out->v_u64 = rz_read_ble64(p, be);
	}
	return sz;
}

/**
 * \brief Append a human-readable UTC timestamp to a string buffer.
 *
 * Uses a fixed "%Y-%m-%d %H:%M:%S" layout, appends sub-second precision
 * (.NNN / .NNNNNN / .NNNNNNNNN) where the format provides it, and ends
 * with " UTC". On decode failure writes "(invalid timestamp)".
 */
RZ_API void rz_pf_timestamp_format_str(RzStrBuf *sb, RzPfTimeFmt fmt,
	const RzPfScalar *raw) {
	struct tm tm;
	int subsec_ns = 0;
	if (!rz_pf_timestamp_to_tm(fmt, raw, &tm, &subsec_ns)) {
		rz_strbuf_append(sb, "(invalid timestamp)");
		return;
	}
	char tbuf[64];
	strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm);
	rz_strbuf_append(sb, tbuf);
	switch (fmt) {
	case RZ_PF_TIMEFMT_UNIXMS:
	case RZ_PF_TIMEFMT_OLETIME:
	case RZ_PF_TIMEFMT_COCOA:
		rz_strbuf_appendf(sb, ".%03d", subsec_ns / 1000000);
		break;
	case RZ_PF_TIMEFMT_UNIXUS:
	case RZ_PF_TIMEFMT_WEBKIT:
		rz_strbuf_appendf(sb, ".%06d", subsec_ns / 1000);
		break;
	case RZ_PF_TIMEFMT_UNIXNS:
	case RZ_PF_TIMEFMT_FILETIME:
		rz_strbuf_appendf(sb, ".%09d", subsec_ns);
		break;
	default:
		break;
	}
	rz_strbuf_append(sb, " UTC");
}

/**
 * \brief C-type string for a timestamp, used by the C-struct renderer.
 *
 * Includes an inline C comment tagging the format so the emitted code
 * self-documents which wire format it came from.
 */
RZ_API const char *rz_pf_timefmt_ctype(RzPfTimeFmt fmt) {
	switch (fmt) {
	case RZ_PF_TIMEFMT_UNIX32: return "uint32_t /* unix32 */";
	case RZ_PF_TIMEFMT_UNIX64: return "int64_t /* unix64 */";
	case RZ_PF_TIMEFMT_UNIXMS: return "int64_t /* unixms */";
	case RZ_PF_TIMEFMT_UNIXUS: return "int64_t /* unixus */";
	case RZ_PF_TIMEFMT_UNIXNS: return "int64_t /* unixns */";
	case RZ_PF_TIMEFMT_FILETIME: return "uint64_t /* FILETIME */";
	case RZ_PF_TIMEFMT_DOS: return "uint32_t /* DOS time */";
	case RZ_PF_TIMEFMT_HFS: return "uint32_t /* HFS+ */";
	case RZ_PF_TIMEFMT_OLETIME: return "double /* OLE time */";
	case RZ_PF_TIMEFMT_WEBKIT: return "int64_t /* WebKit */";
	case RZ_PF_TIMEFMT_COCOA: return "double /* Cocoa */";
	default: return "uint32_t /* time */";
	}
}
