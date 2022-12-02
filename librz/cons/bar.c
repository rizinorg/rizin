// SPDX-FileCopyrightText: 2022 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include <rz_util/rz_assert.h>

// TODO: add support for colors
/**
 * \brief Create the string buffer with the progressbar
 *
 * \param opts Progressbar options: color, style, legend
 * \param pc How much percent is filled
 * \param width Width of the histogram
 */
RZ_API RZ_OWN RzStrBuf *rz_progressbar(RZ_NONNULL RzBarOptions *opts, int pc, int width) {
	rz_return_val_if_fail(opts, NULL);
	RzStrBuf *buf = rz_strbuf_new("");
	if (!buf) {
		return NULL;
	}
	int i, cols = (width == -1) ? 78 : width;
	const char *h_line = opts->unicode ? RUNE_LONG_LINE_HORIZ : "-";
	const char *block = opts->unicode ? UTF_BLOCK : "#";

	pc = RZ_MAX(0, RZ_MIN(100, pc));
	if (opts->legend) {
		rz_strbuf_appendf(buf, "%4d%% ", pc);
	}
	cols -= 15;
	rz_strbuf_append(buf, "[");
	for (i = cols * pc / 100; i; i--) {
		rz_strbuf_append(buf, block);
	}
	for (i = cols - (cols * pc / 100); i; i--) {
		rz_strbuf_append(buf, h_line);
	}
	rz_strbuf_append(buf, "]");
	return buf;
}

/**
 * \brief Create the string buffer with the rangebar
 *
 * \param opts Rangebar options: color, style, legend
 * \param startA Position of the range start
 * \param endA Position of the range end
 * \param min Minimum range value
 * \param max Maximum range value
 * \param width Width of the rangebar
 */
RZ_API RZ_OWN RzStrBuf *rz_rangebar(RZ_NONNULL RzBarOptions *opts, ut64 startA, ut64 endA, ut64 min,
	ut64 max, int width) {
	rz_return_val_if_fail(opts, NULL);
	RzStrBuf *buf = rz_strbuf_new("|");
	if (!buf) {
		return NULL;
	}
	int cols = (width == -1) ? 78 : width;
	const char *h_line = opts->unicode ? RUNE_LONG_LINE_HORIZ : "-";
	const char *block = opts->unicode ? UTF_BLOCK : "#";
	int mul = (max - min) / cols;
	bool isFirst = true;
	for (int j = 0; j < cols; j++) {
		ut64 startB = min + (j * mul);
		ut64 endB = min + ((j + 1) * mul);
		if (startA <= endB && endA >= startB) {
			if (opts->color & isFirst) {
				rz_strbuf_append(buf, Color_GREEN);
				isFirst = false;
			}
			rz_strbuf_append(buf, block);
		} else {
			if (!isFirst) {
				rz_strbuf_append(buf, Color_RESET);
			}
			rz_strbuf_append(buf, h_line);
		}
	}
	rz_strbuf_append(buf, "|");
	return buf;
}
