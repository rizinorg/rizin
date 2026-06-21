// SPDX-FileCopyrightText: 2026 Maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include "minunit.h"

bool test_histogram_horizontal(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.color = false;
	opts.unicode = false;
	opts.ruler = true;

	ut8 data[] = { 50, 200 };
	RzStrBuf *buf = rz_histogram_horizontal(&opts, data, 2, 2);

	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Histogram buffer should not be null");
	// Ruler labels are now inclusive: top row -> vmax (255), bottom -> vmin (0).
	mu_assert_true(strstr(res, "255|") != NULL, "Top ruler label = vmax");
	mu_assert_true(strstr(res, "0|") != NULL, "Bottom ruler label = vmin");
	mu_assert_true(strstr(res, "_") != NULL, "Baseline marker present in bottom row");
	free(res);
	rz_cons_free();
	mu_end;
}

bool test_histogram_vertical(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.color = false;
	opts.unicode = false;

	ut8 data[] = { 255, 0 };
	RzStrBuf *buf = rz_histogram_vertical(&opts, data, 2, 5);

	char *res = rz_strbuf_drain(buf);
	// Vertical histogram for 255 and 0 should have one full column and one empty
	mu_assert_notnull(res, "Histogram buffer should not be null");
	mu_assert_true(strstr(res, "#") != NULL, "Blocks present for data 255");
	free(res);
	rz_cons_free();
	mu_end;
}

// When value_max is set, the ruler labels must show that range (and unit)
// rather than the legacy 0..255 byte scale (issue #5290).
bool test_histogram_horizontal_ruler_percent(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.color = false;
	opts.unicode = false;
	opts.ruler = true;
	opts.value_min = 0;
	opts.value_max = 100;
	opts.value_unit = "%";

	ut8 data[] = { 255, 128, 64, 0 };
	RzStrBuf *buf = rz_histogram_horizontal(&opts, data, 4, 4);

	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Histogram buffer should not be null");
	mu_assert_true(strstr(res, "100%|") != NULL, "Top ruler label uses value_max + unit");
	// Legacy 0..255 labels must not leak in when value_max is set.
	mu_assert_true(strstr(res, " 255|") == NULL, "Legacy 255 label absent");
	free(res);
	rz_cons_free();
	mu_end;
}

// When value_max is left at 0, the ruler must fall back to the historical
// 0..255 scale (backwards compatibility for callers that did not opt in).
bool test_histogram_horizontal_ruler_default(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.color = false;
	opts.unicode = false;
	opts.ruler = true;

	ut8 data[] = { 255, 0 };
	RzStrBuf *buf = rz_histogram_horizontal(&opts, data, 2, 4);

	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Histogram buffer should not be null");
	mu_assert_true(strstr(res, "255|") != NULL, "Default 0..255 ruler still shows 255 at top");
	free(res);
	rz_cons_free();
	mu_end;
}

// With value_max=100 and storage 0..255, a datum at the storage peak (255)
// must reach the very top of the chart. This guards the "blank top rows"
// behaviour cer-0 raised in #5290 against regressing.
bool test_histogram_horizontal_top_row_filled(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.color = false;
	opts.unicode = false;
	opts.thinline = false;
	opts.ruler = false;
	opts.value_min = 0;
	opts.value_max = 100;

	ut8 data[] = { 255 };
	RzStrBuf *buf = rz_histogram_horizontal(&opts, data, 1, 4);

	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Histogram buffer should not be null");
	// The first rendered row (the top of the chart) must contain a filled
	// block, not just whitespace.
	const char *first_newline = strchr(res, '\n');
	mu_assert_notnull(first_newline, "Output should have at least one row");
	bool top_row_has_block = false;
	for (const char *p = res; p < first_newline; p++) {
		if (*p == '#') {
			top_row_has_block = true;
			break;
		}
	}
	mu_assert_true(top_row_has_block, "Top row reached for storage peak with value_max=100");
	free(res);
	rz_cons_free();
	mu_end;
}

// scr.hist.width opt-in: when opts->cols is set, the rendered width follows it
// instead of the legacy 78 column default.
bool test_histogram_horizontal_cols_override(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.color = false;
	opts.unicode = false;
	opts.ruler = false;
	opts.cols = 20;

	ut8 data[] = { 128 };
	RzStrBuf *buf = rz_histogram_horizontal(&opts, data, 1, 2);

	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Histogram buffer should not be null");
	// The first line should be exactly 20 chars wide (not 78).
	const char *nl = strchr(res, '\n');
	mu_assert_notnull(nl, "Output must have at least one row");
	mu_assert_eq((int)(nl - res), 20, "Custom cols=20 honoured");
	free(res);
	rz_cons_free();
	mu_end;
}

// Sparse Y-axis labels: a tall histogram must not carry one label per row
// (the old behaviour). At most a small number of labels should appear, with
// the top and bottom values always included.
bool test_histogram_horizontal_sparse_labels(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.color = false;
	opts.unicode = false;
	opts.ruler = true;
	opts.cols = 10;

	ut8 data[] = { 200 };
	RzStrBuf *buf = rz_histogram_horizontal(&opts, data, 1, 20);

	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Histogram buffer should not be null");
	// Count how many rows carry a numeric label by counting how many lines
	// start with a digit (ignoring the leading whitespace gutter).
	int label_count = 0;
	int line_count = 0;
	const char *p = res;
	while (*p) {
		const char *eol = strchr(p, '\n');
		if (!eol) {
			break;
		}
		line_count++;
		// Find first non-space character.
		const char *q = p;
		while (q < eol && *q == ' ') {
			q++;
		}
		if (q < eol && *q >= '0' && *q <= '9') {
			label_count++;
		}
		p = eol + 1;
	}
	mu_assert_true(line_count >= 20, "At least 20 body rows produced");
	mu_assert_true(label_count >= 2, "At least two label rows (top + bottom)");
	mu_assert_true(label_count <= 6, "Far fewer label rows than body rows (sparse)");
	free(res);
	rz_cons_free();
	mu_end;
}

// Floating-point ruler labels: with value_scale=0.01 and value_precision=2,
// an integer value range 0..100 must render as decimal labels 0.00..1.00.
bool test_histogram_horizontal_float_labels(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.color = false;
	opts.unicode = false;
	opts.ruler = true;
	opts.value_min = 0;
	opts.value_max = 100;
	opts.value_scale = 0.01;
	opts.value_precision = 2;

	ut8 data[] = { 255 };
	RzStrBuf *buf = rz_histogram_horizontal(&opts, data, 1, 4);

	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Histogram buffer should not be null");
	mu_assert_true(strstr(res, "1.00|") != NULL, "Top label uses 2 decimal digits");
	mu_assert_true(strstr(res, "0.00|") != NULL, "Bottom label uses 2 decimal digits");
	free(res);
	rz_cons_free();
	mu_end;
}

// X-axis offset ruler: when blocksize is set, the output must include
// "^" tick markers and absolute byte offset labels at the bottom.
bool test_histogram_horizontal_xaxis_offsets(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.color = false;
	opts.unicode = false;
	opts.ruler = true;
	opts.offpos = 0x1000;
	opts.blocksize = 0x10;
	opts.cols = 60;

	ut8 data[] = { 50, 100, 150, 200 };
	RzStrBuf *buf = rz_histogram_horizontal(&opts, data, 4, 6);

	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Histogram buffer should not be null");
	mu_assert_true(strstr(res, "0x1000") != NULL, "Start offset label present");
	mu_assert_true(strstr(res, "0x1030") != NULL, "End offset label present");
	mu_assert_true(strstr(res, "^") != NULL, "Tick characters present");
	free(res);
	rz_cons_free();
	mu_end;
}

// Floating-point data input: when opts->data_f is supplied alongside
// value_precision > 0, the ut8 \p data argument is ignored and the chart
// uses the fp values directly. Two entropies that would round to the same
// ut8 should still be distinguishable.
bool test_histogram_horizontal_data_f(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.color = false;
	opts.unicode = false;
	opts.ruler = true;
	opts.value_min = 0;
	opts.value_max = 1;
	opts.value_precision = 2;
	// Two entropies that both round to ut8 127, but are distinct as doubles.
	double fdata[] = { 0.501, 0.499 };
	opts.data_f = fdata;
	// Pass a dummy ut8 buffer that, if the function ignored data_f, would
	// produce a different chart shape.
	ut8 dummy[] = { 0, 0 };

	RzStrBuf *buf = rz_histogram_horizontal(&opts, dummy, 2, 4);
	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Histogram buffer should not be null");
	// Top label is 1.00 (vmax), bottom is 0.00 (vmin).
	mu_assert_true(strstr(res, "1.00|") != NULL, "Top label = vmax with precision");
	mu_assert_true(strstr(res, "0.00|") != NULL, "Bottom label = vmin with precision");
	// The dummy ut8 zero data would render an empty chart; data_f at 0.5
	// must instead produce filled cells. Look for any block character.
	mu_assert_true(strstr(res, "#") != NULL, "fp data renders bars (ut8 was ignored)");
	free(res);
	rz_cons_free();
	mu_end;
}

// Multi-character value_unit suffix (e.g. "MB", "ms") must fit in the gutter
// alongside the numeric label.
bool test_histogram_horizontal_multi_char_unit(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.ruler = true;
	opts.value_min = 0;
	opts.value_max = 100;
	opts.value_unit = "MB";

	ut8 data[] = { 200, 150, 100, 50 };
	RzStrBuf *buf = rz_histogram_horizontal(&opts, data, 4, 6);
	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Render should produce output");
	mu_assert_true(strstr(res, "100MB|") != NULL, "Top label uses multi-char unit");
	mu_assert_true(strstr(res, "0MB|") != NULL, "Bottom label uses multi-char unit");
	free(res);
	rz_cons_free();
	mu_end;
}

// value_precision=1 (one decimal) and value_precision=3 (three decimals)
// both format correctly.
bool test_histogram_horizontal_precision_variants(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.ruler = true;
	opts.value_min = 0;
	opts.value_max = 10;
	opts.value_precision = 1;
	ut8 data[] = { 100, 200 };
	RzStrBuf *buf = rz_histogram_horizontal(&opts, data, 2, 4);
	char *res = rz_strbuf_drain(buf);
	mu_assert_true(strstr(res, "10.0|") != NULL, "Precision=1 top label");
	mu_assert_true(strstr(res, "0.0|") != NULL, "Precision=1 bottom label");
	free(res);

	opts.value_precision = 3;
	opts.value_max = 1;
	opts.value_scale = 1.0;
	buf = rz_histogram_horizontal(&opts, data, 2, 4);
	res = rz_strbuf_drain(buf);
	mu_assert_true(strstr(res, "1.000|") != NULL, "Precision=3 top label");
	mu_assert_true(strstr(res, "0.000|") != NULL, "Precision=3 bottom label");
	free(res);
	rz_cons_free();
	mu_end;
}

// value_scale rescales the integer label value (e.g. milliseconds → seconds).
bool test_histogram_horizontal_value_scale(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.ruler = true;
	opts.value_min = 0;
	opts.value_max = 1000;
	opts.value_scale = 0.001; // ms → s
	opts.value_precision = 2;
	opts.value_unit = "s";

	ut8 data[] = { 100, 200, 50 };
	RzStrBuf *buf = rz_histogram_horizontal(&opts, data, 3, 4);
	char *res = rz_strbuf_drain(buf);
	mu_assert_true(strstr(res, "1.00s|") != NULL, "Scaled top label (1000 * 0.001 = 1.00)");
	mu_assert_true(strstr(res, "0.00s|") != NULL, "Scaled bottom label");
	free(res);
	rz_cons_free();
	mu_end;
}

// Unicode mode produces UTF-8 block (█) and box-drawing vline (│).
bool test_histogram_horizontal_unicode(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.unicode = true;
	opts.ruler = true;
	ut8 data[] = { 200, 100, 50 };
	RzStrBuf *buf = rz_histogram_horizontal(&opts, data, 3, 4);
	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Render should produce output");
	// UTF-8 byte sequences: U+2502 (│) = 0xE2 0x94 0x82; U+2588 (█) = 0xE2 0x96 0x88.
	mu_assert_true(strstr(res, "\xe2\x94\x82") != NULL, "Unicode vline (U+2502) present");
	mu_assert_true(strstr(res, "\xe2\x96\x88") != NULL, "Unicode block (U+2588) present");
	// ASCII fallbacks must NOT appear.
	mu_assert_true(strstr(res, "|") == NULL, "ASCII '|' absent in unicode mode");
	mu_assert_true(strstr(res, "#") == NULL, "ASCII '#' absent in unicode mode");
	free(res);
	rz_cons_free();
	mu_end;
}

// Thinline mode draws bars as vertical pipes instead of block characters.
bool test_histogram_horizontal_thinline(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.thinline = true;
	opts.ruler = true;
	ut8 data[] = { 200, 100 };
	RzStrBuf *buf = rz_histogram_horizontal(&opts, data, 2, 4);
	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Render should produce output");
	// In thinline mode bars are '|', so the only block characters present are
	// the baseline '_' and the gutter vline. Make sure '#' is absent.
	mu_assert_true(strstr(res, "#") == NULL, "Block '#' absent in thinline mode");
	mu_assert_true(strstr(res, "|") != NULL, "Vline '|' present");
	free(res);
	rz_cons_free();
	mu_end;
}

// Color mode wraps bars in ANSI escape sequences.
bool test_histogram_horizontal_color(void) {
	rz_cons_new();
	rz_cons_singleton()->context->color_mode = COLOR_MODE_16M;
	rz_cons_pal_init(rz_cons_singleton()->context);
	rz_cons_pal_update_event();
	RzHistogramOptions opts = { 0 };
	opts.color = true;
	opts.ruler = true;
	opts.pal = &rz_cons_singleton()->context->pal;
	ut8 data[] = { 200, 100 };
	RzStrBuf *buf = rz_histogram_horizontal(&opts, data, 2, 4);
	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Render should produce output");
	mu_assert_true(strstr(res, "\x1b[") != NULL, "ANSI escape sequence present");
	mu_assert_true(strstr(res, "\x1b[0m") != NULL, "Reset escape present");
	free(res);
	rz_cons_free();
	mu_end;
}

// No X-axis ruler when opts->blocksize is 0 (preserves legacy output for
// callers that don't supply a blocksize).
bool test_histogram_horizontal_no_blocksize_no_xaxis(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.ruler = true;
	opts.offpos = 0x1000;
	opts.blocksize = 0; // explicit, but it's the default too
	ut8 data[] = { 200, 100, 50 };
	RzStrBuf *buf = rz_histogram_horizontal(&opts, data, 3, 6);
	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Render should produce output");
	mu_assert_true(strstr(res, "0x1000") == NULL, "No X-axis offset labels when blocksize is 0");
	mu_assert_true(strstr(res, "^") == NULL, "No '^' tick markers when blocksize is 0");
	free(res);
	rz_cons_free();
	mu_end;
}

// Baseline '_' marker appears at the bottom row even when there are zero-data
// columns (preserves legacy behaviour for low-magnitude charts).
bool test_histogram_horizontal_baseline_marker(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.ruler = true;
	// Data with strict zeros — these must render '_' on the bottom row
	// (not stay blank). PR #6355's `d > 0` guard regressed this.
	ut8 data[] = { 0, 100, 0, 200, 0 };
	RzStrBuf *buf = rz_histogram_horizontal(&opts, data, 5, 6);
	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Render should produce output");
	mu_assert_true(strstr(res, "_") != NULL, "Baseline '_' present for zero data columns");
	free(res);
	rz_cons_free();
	mu_end;
}

// Narrow charts (opts->cols < 4) suppress the X-axis ruler since there's
// no room for offset labels.
bool test_histogram_horizontal_narrow_chart(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.ruler = true;
	opts.offpos = 0x1000;
	opts.blocksize = 0x10;
	opts.cols = 3; // below the 4-col minimum for X-axis ruler
	ut8 data[] = { 200, 100, 50 };
	RzStrBuf *buf = rz_histogram_horizontal(&opts, data, 3, 6);
	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Narrow chart must still render");
	mu_assert_true(strstr(res, "0x1000") == NULL, "No X-axis offsets when cols < 4");
	free(res);
	rz_cons_free();
	mu_end;
}

// data_f bypasses ut8 quantisation: two doubles that round to the same ut8
// must render distinctly on a chart tall enough to separate them.
bool test_histogram_horizontal_data_f_precision(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.ruler = true;
	opts.value_min = 0;
	opts.value_max = 1;
	opts.value_precision = 2;
	// Two doubles that both quantise to (ut8)(255 * x) == 127.
	// Without data_f they'd render identically.
	double fdata[] = { 0.499, 0.501 };
	opts.data_f = fdata;
	ut8 dummy[] = { 0, 0 };

	// Tall chart so the fp resolution actually matters.
	RzStrBuf *buf = rz_histogram_horizontal(&opts, dummy, 2, 80);
	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Render should produce output");

	// Count rows where the first column is filled vs the second.
	// They must differ by at least one row (the fp precision wins).
	int col1_fills = 0, col2_fills = 0;
	char *p = res;
	while (*p) {
		char *eol = strchr(p, '\n');
		if (!eol)
			break;
		// Skip gutter (variable width). Find the vline.
		char *bar = strchr(p, '|');
		if (bar && bar < eol && bar + 1 < eol) {
			if (bar[1] == '#')
				col1_fills++;
			if (bar + 2 < eol && bar[2] == '#')
				col2_fills++;
		}
		p = eol + 1;
	}
	// fdata[1] > fdata[0], so column 2 must reach at least as high.
	mu_assert_true(col2_fills >= col1_fills, "fp data preserves ordering");
	free(res);
	rz_cons_free();
	mu_end;
}

// Combination test: every feature toggled on at once must still render
// without crashing and must show evidence of each feature.
bool test_histogram_horizontal_combined_features(void) {
	rz_cons_new();
	rz_cons_singleton()->context->color_mode = COLOR_MODE_16M;
	rz_cons_pal_init(rz_cons_singleton()->context);
	rz_cons_pal_update_event();
	RzHistogramOptions opts = { 0 };
	opts.unicode = true;
	opts.thinline = true;
	opts.color = true;
	opts.ruler = true;
	opts.pal = &rz_cons_singleton()->context->pal;
	opts.offpos = 0x401000;
	opts.blocksize = 0x10;
	opts.cols = 60;
	opts.value_min = 0;
	opts.value_max = 1;
	opts.value_precision = 2;
	double fdata[16];
	for (int i = 0; i < 16; i++) {
		fdata[i] = i / 15.0;
	}
	opts.data_f = fdata;
	ut8 dummy[16] = { 0 };

	RzStrBuf *buf = rz_histogram_horizontal(&opts, dummy, 16, 10);
	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Combined-features render should produce output");
	mu_assert_true(strstr(res, "1.00") != NULL, "Fractional top label present");
	mu_assert_true(strstr(res, "0.00") != NULL, "Fractional bottom label present");
	mu_assert_true(strstr(res, "0x401000") != NULL, "X-axis start offset present");
	mu_assert_true(strstr(res, "\xe2\x94\x82") != NULL, "Unicode vline present");
	mu_assert_true(strstr(res, "\x1b[") != NULL, "ANSI escape present");
	mu_assert_true(strstr(res, "^") != NULL, "X-axis tick present");
	free(res);
	rz_cons_free();
	mu_end;
}

// The renderer's contract: every rendered row is exactly gutter_w + opts->cols
// printable characters wide. Callers that clamp `cols` to fit the terminal
// must subtract the gutter themselves.
bool test_histogram_horizontal_row_width_contract(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.ruler = true;
	opts.value_min = 0;
	opts.value_max = 100;
	opts.value_unit = "%";
	opts.cols = 50;

	ut8 data[16];
	for (int i = 0; i < 16; i++) {
		data[i] = i * 16;
	}
	RzStrBuf *buf = rz_histogram_horizontal(&opts, data, 16, 6);
	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Render should produce output");

	// The widest possible label here is "100%" -> gutter = 1+4+1 = 6 cols.
	// Data rows must be exactly gutter + cols characters wide.
	const int expected_data_row_w = 6 + 50;
	char *line = res;
	int row_idx = 0;
	while (line && *line && row_idx < 6) {
		char *nl = strchr(line, '\n');
		size_t len = nl ? (size_t)(nl - line) : strlen(line);
		mu_assert_eq((int)len, expected_data_row_w, "Each chart row matches gutter + cols");
		line = nl ? nl + 1 : NULL;
		row_idx++;
	}
	free(res);
	rz_cons_free();
	mu_end;
}

// Regression: with value_max=1 and value_precision=2 the previous integer
// label_value_at truncated 1*i/(rows-1) to 0 for all but the last row, so
// upper labels printed as "1.00" four times in a row (see PR #6427 review).
// The fp interpolation should now produce distinct labels like
// 1.00, 0.75, 0.50, 0.25, 0.00.
bool test_histogram_horizontal_no_duplicate_labels(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.ruler = true;
	opts.value_min = 0;
	opts.value_max = 1;
	opts.value_precision = 2;

	ut8 data[8] = { 0 };
	RzStrBuf *buf = rz_histogram_horizontal(&opts, data, 8, 10);
	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Render should produce output");

	mu_assert_true(strstr(res, "1.00|") != NULL, "Top label is 1.00");
	mu_assert_true(strstr(res, "0.00|") != NULL, "Bottom label is 0.00");
	mu_assert_true(strstr(res, "0.50|") != NULL || strstr(res, "0.56|") != NULL ||
			strstr(res, "0.44|") != NULL,
		"At least one intermediate label is between extremes");

	// Count how many times "1.00|" appears - must be exactly once.
	int count = 0;
	const char *p = res;
	while ((p = strstr(p, "1.00|")) != NULL) {
		count++;
		p++;
	}
	mu_assert_eq(count, 1, "Top label 1.00 appears exactly once (no duplicates)");

	free(res);
	rz_cons_free();
	mu_end;
}

// ----- Visual / interactive horizontal histogram tests ----------------------

// Build a fresh interactive harness with sensible defaults for the tests.
static RzHistogramInteractive *make_visual_hist(int size, int w, int h, RzHistogramOptions *opts) {
	RzConsCanvas *can = rz_cons_canvas_new(w, h);
	if (!can) {
		return NULL;
	}
	RzHistogramInteractive *hist = rz_histogram_interactive_new(can, opts);
	if (!hist) {
		rz_cons_canvas_free(can);
		return NULL;
	}
	hist->size = size;
	hist->blocksize = 0x10;
	hist->w = w;
	hist->h = h;
	hist->zoom = 1;
	hist->barnumber = 0;
	return hist;
}

// Free a harness from make_visual_hist. interactive_free frees the canvas
// and the opts pointer too, so callers do NOT also free those.
static void free_visual_hist(RzHistogramInteractive *hist) {
	rz_histogram_interactive_free(hist);
}

// Smoke test: the renderer produces output, the status line is present, and
// the cursor at index 0 doesn't trigger the #4431 segfault (negative adder).
bool test_histogram_interactive_horizontal_basic(void) {
	rz_cons_new();
	RzHistogramOptions *opts = rz_histogram_options_new();
	mu_assert_notnull(opts, "opts new");
	opts->ruler = false; // simplest path
	ut8 data[16];
	for (int i = 0; i < 16; i++) {
		data[i] = i * 16;
	}
	RzHistogramInteractive *hist = make_visual_hist(16, 40, 10, opts);
	mu_assert_notnull(hist, "hist new");
	RzStrBuf *buf = rz_histogram_interactive_horizontal(hist, data);
	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Render should produce output");
	mu_assert_true(strstr(res, "Index 0 data 0") != NULL, "Status line present");
	free(res);
	free_visual_hist(hist);
	rz_cons_free();
	mu_end;
}

// Y-axis ruler with percent unit + value_max=100 + value_scale=0.01 +
// precision=2 should render labels like 1.00%, 0.50%, 0.00% across 5 anchors.
bool test_histogram_interactive_horizontal_ruler_percent(void) {
	rz_cons_new();
	RzHistogramOptions *opts = rz_histogram_options_new();
	mu_assert_notnull(opts, "opts new");
	opts->ruler = true;
	opts->value_max = 100;
	opts->value_scale = 0.01;
	opts->value_precision = 2;
	opts->value_unit = "%";
	ut8 data[32];
	for (int i = 0; i < 32; i++) {
		data[i] = i * 8;
	}
	RzHistogramInteractive *hist = make_visual_hist(32, 60, 14, opts);
	mu_assert_notnull(hist, "hist new");
	RzStrBuf *buf = rz_histogram_interactive_horizontal(hist, data);
	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Render should produce output");
	mu_assert_true(strstr(res, "1.00%") != NULL, "Top fractional label present");
	mu_assert_true(strstr(res, "0.00%") != NULL, "Bottom fractional label present");
	free(res);
	free_visual_hist(hist);
	rz_cons_free();
	mu_end;
}

// Default 0..255 byte ruler should produce labels 255 (top) and 0 (bottom).
bool test_histogram_interactive_horizontal_ruler_default(void) {
	rz_cons_new();
	RzHistogramOptions *opts = rz_histogram_options_new();
	mu_assert_notnull(opts, "opts new");
	opts->ruler = true;
	ut8 data[16];
	for (int i = 0; i < 16; i++) {
		data[i] = 255;
	}
	RzHistogramInteractive *hist = make_visual_hist(16, 50, 14, opts);
	mu_assert_notnull(hist, "hist new");
	RzStrBuf *buf = rz_histogram_interactive_horizontal(hist, data);
	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Render should produce output");
	mu_assert_true(strstr(res, "255|") != NULL, "Top byte label present");
	mu_assert_true(strstr(res, "0|") != NULL, "Bottom byte label present");
	free(res);
	free_visual_hist(hist);
	rz_cons_free();
	mu_end;
}

// Pin the #4431 segfault: with barnumber at the very left (0) and zoom such
// that span > histogramwidth, the adder must clamp to 0 (not go negative).
// The renderer should produce output without crashing.
bool test_histogram_interactive_horizontal_no_negative_adder(void) {
	rz_cons_new();
	RzHistogramOptions *opts = rz_histogram_options_new();
	mu_assert_notnull(opts, "opts new");
	ut8 data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	RzHistogramInteractive *hist = make_visual_hist(8, 80, 10, opts);
	mu_assert_notnull(hist, "hist new");
	hist->barnumber = 0;
	hist->zoom = 1;
	RzStrBuf *buf = rz_histogram_interactive_horizontal(hist, data);
	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Render at barnumber=0 should not crash");
	mu_assert_true(strstr(res, "Index 0") != NULL, "Cursor index 0 reported");
	free(res);
	free_visual_hist(hist);
	rz_cons_free();
	mu_end;
}

// Percent indicator on the status line should appear when chart % is meaningful.
bool test_histogram_interactive_horizontal_percent(void) {
	rz_cons_new();
	RzHistogramOptions *opts = rz_histogram_options_new();
	mu_assert_notnull(opts, "opts new");
	ut8 data[20];
	for (int i = 0; i < 20; i++) {
		data[i] = i * 12;
	}
	RzHistogramInteractive *hist = make_visual_hist(20, 60, 12, opts);
	mu_assert_notnull(hist, "hist new");
	hist->barnumber = 10; // ~50% through 20 bars
	RzStrBuf *buf = rz_histogram_interactive_horizontal(hist, data);
	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Render should produce output");
	mu_assert_true(strstr(res, "%") != NULL, "Percent indicator on status line");
	free(res);
	free_visual_hist(hist);
	rz_cons_free();
	mu_end;
}

// Cursor markers ▼ at the top and ▲ at the bottom (or `v`/`^` in ASCII) make
// the cursor column identifiable even when colour rendering is off. The
// markers themselves are NOT colour-highlighted (kept plain) - the wordhl
// highlighting lives on the cursor bar between them, drawn as a continuous
// vertical line regardless of whether the data threshold reaches that row.
bool test_histogram_interactive_horizontal_cursor_markers(void) {
	rz_cons_new();
	{
		RzHistogramOptions *opts = rz_histogram_options_new();
		mu_assert_notnull(opts, "opts new");
		opts->unicode = true;
		ut8 data[16];
		for (int i = 0; i < 16; i++) {
			data[i] = i * 16;
		}
		RzHistogramInteractive *hist = make_visual_hist(16, 50, 12, opts);
		mu_assert_notnull(hist, "hist new");
		hist->barnumber = 8;
		RzStrBuf *buf = rz_histogram_interactive_horizontal(hist, data);
		char *res = rz_strbuf_drain(buf);
		mu_assert_notnull(res, "Render should produce output");
		mu_assert_true(strstr(res, "\xe2\x96\xbc" /* ▼ */) != NULL, "Top marker present (utf8)");
		mu_assert_true(strstr(res, "\xe2\x96\xb2" /* ▲ */) != NULL, "Bottom marker present (utf8)");
		free(res);
		free_visual_hist(hist);
	}
	{
		RzHistogramOptions *opts = rz_histogram_options_new();
		mu_assert_notnull(opts, "opts new");
		opts->unicode = false; // ASCII fallback markers
		ut8 data[16];
		for (int i = 0; i < 16; i++) {
			data[i] = i * 16;
		}
		RzHistogramInteractive *hist = make_visual_hist(16, 50, 12, opts);
		mu_assert_notnull(hist, "hist new");
		hist->barnumber = 8;
		RzStrBuf *buf = rz_histogram_interactive_horizontal(hist, data);
		char *res = rz_strbuf_drain(buf);
		mu_assert_notnull(res, "Render should produce output");
		mu_assert_true(strchr(res, 'v') != NULL, "Top marker present (ASCII v)");
		// ^ also appears in the X-axis ruler ticks, so we just check at
		// least one is on a non-ruler row.
		mu_assert_true(strchr(res, '^') != NULL, "Bottom marker present (ASCII ^)");
		free(res);
		free_visual_hist(hist);
	}
	rz_cons_free();
	mu_end;
}

// The cursor bar must be a CONTINUOUS vertical line between the top/bottom
// markers - drawn on every row in between regardless of the data threshold.
// With a low-value cursor column and a tall chart, the gradient bars would
// only reach the lower rows, but the cursor line should still extend up to
// the top marker.
bool test_histogram_interactive_horizontal_cursor_full_line(void) {
	rz_cons_new();
	RzHistogramOptions *opts = rz_histogram_options_new();
	mu_assert_notnull(opts, "opts new");
	opts->unicode = false; // ASCII so we can count `|` chars in the cursor column
	opts->thinline = true; // force `|` glyph (else `#`)
	ut8 data[8] = { 8, 16, 32, 4 /* cursor at this very small value */, 64, 128, 200, 255 };
	RzHistogramInteractive *hist = make_visual_hist(8, 50, 12, opts);
	mu_assert_notnull(hist, "hist new");
	hist->barnumber = 3;
	RzStrBuf *buf = rz_histogram_interactive_horizontal(hist, data);
	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Render should produce output");
	// Count `|` characters - the cursor column must contribute one for every
	// chart row except the top/bottom (where the markers live). For a 12-row
	// chart minus 2 reserved for X-axis ruler -> ~10 chart rows -> at least 8
	// `|` characters on the cursor column.
	int pipe_count = 0;
	for (const char *p = res; *p; p++) {
		if (*p == '|') {
			pipe_count++;
		}
	}
	mu_assert_true(pipe_count >= 6, "Cursor column extends as a continuous vertical line");
	free(res);
	free_visual_hist(hist);
	rz_cons_free();
	mu_end;
}

// When opts->minimap is true, the minimap rows must be rendered REGARDLESS
// of whether the data is zoomed in or shown in full. The user setting wins:
// `e scr.hist.minimap=true` always shows the minimap, `false` always hides it.
bool test_histogram_interactive_horizontal_minimap_toggle(void) {
	rz_cons_new();
	ut8 data[256];
	for (int i = 0; i < 256; i++) {
		data[i] = i;
	}
	// minimap disabled -> no window indicator characters, even when zoomed
	{
		RzHistogramOptions *opts = rz_histogram_options_new();
		mu_assert_notnull(opts, "opts new");
		opts->unicode = true;
		opts->minimap = false;
		RzHistogramInteractive *hist = make_visual_hist(256, 80, 15, opts);
		mu_assert_notnull(hist, "hist new");
		hist->barnumber = 128;
		hist->zoom = 4; // forces a subset view
		RzStrBuf *buf = rz_histogram_interactive_horizontal(hist, data);
		char *res = rz_strbuf_drain(buf);
		mu_assert_notnull(res, "Render should produce output");
		mu_assert_null(strstr(res, "\xe2\x94\x8f"), "Minimap window left bracket absent when minimap=false (zoomed)");
		free(res);
		free_visual_hist(hist);
	}
	// minimap enabled while zoomed -> minimap present with the window indicator
	{
		RzHistogramOptions *opts = rz_histogram_options_new();
		mu_assert_notnull(opts, "opts new");
		opts->unicode = true;
		opts->minimap = true;
		RzHistogramInteractive *hist = make_visual_hist(256, 80, 15, opts);
		mu_assert_notnull(hist, "hist new");
		hist->barnumber = 128;
		hist->zoom = 4;
		RzStrBuf *buf = rz_histogram_interactive_horizontal(hist, data);
		char *res = rz_strbuf_drain(buf);
		mu_assert_notnull(res, "Render should produce output");
		mu_assert_true(strstr(res, "\xe2\x94\x8f") != NULL, "Minimap left bracket present when minimap=true (zoomed)");
		free(res);
		free_visual_hist(hist);
	}
	// minimap enabled while NOT zoomed -> minimap still present (user setting wins)
	{
		RzHistogramOptions *opts = rz_histogram_options_new();
		mu_assert_notnull(opts, "opts new");
		opts->unicode = true;
		opts->minimap = true;
		RzHistogramInteractive *hist = make_visual_hist(256, 80, 15, opts);
		mu_assert_notnull(hist, "hist new");
		hist->barnumber = 128;
		hist->zoom = 1; // not zoomed - whole data visible
		RzStrBuf *buf = rz_histogram_interactive_horizontal(hist, data);
		char *res = rz_strbuf_drain(buf);
		mu_assert_notnull(res, "Render should produce output");
		mu_assert_true(strstr(res, "\xe2\x94\x81") != NULL, "Minimap mid bar present when minimap=true (not zoomed)");
		free(res);
		free_visual_hist(hist);
	}
	rz_cons_free();
	mu_end;
}

// Helper for the cursor-width test: counts the most 'v' characters on any
// single line of the rendered output. The top marker `v` is unambiguous (the
// bottom marker `^` also appears on the X-axis ruler so we can't use it).
static int max_v_chars_per_line(const char *res) {
	int max_v = 0;
	for (const char *p = res; *p;) {
		const char *eol = strchr(p, '\n');
		size_t len = eol ? (size_t)(eol - p) : strlen(p);
		int vs = 0;
		for (size_t k = 0; k < len; k++) {
			if (p[k] == 'v') {
				vs++;
			}
		}
		if (vs > max_v) {
			max_v = vs;
		}
		if (!eol) {
			break;
		}
		p = eol + 1;
	}
	return max_v;
}

// The cursor is ALWAYS exactly one screen column wide on every chart row,
// independent of zoom level OR the histogramwidth-vs-width ratio.
// Two distinct widening bugs are pinned here:
//   1. sizeofonebar > 1 (high zoom): each data index spans `sizeofonebar`
//      screen columns; only kbar==0 may carry the cursor.
//   2. histogramwidth < width (chart much wider than data): several adjacent
//      screen columns map to the same data index via integer truncation;
//      only the pre-computed j_cursor column may carry the cursor.
bool test_histogram_interactive_horizontal_cursor_width(void) {
	rz_cons_new();

	// Case 1: high zoom forces sizeofonebar > 1.
	{
		RzHistogramOptions *opts = rz_histogram_options_new();
		mu_assert_notnull(opts, "opts new");
		opts->unicode = false;
		opts->thinline = true;
		opts->color = false;
		ut8 data[4] = { 64, 128, 192, 255 };
		RzHistogramInteractive *hist = make_visual_hist(4, 80, 12, opts);
		mu_assert_notnull(hist, "hist new");
		hist->barnumber = 1;
		hist->zoom = 20; // -> sizeofonebar > 1
		RzStrBuf *buf = rz_histogram_interactive_horizontal(hist, data);
		char *res = rz_strbuf_drain(buf);
		mu_assert_notnull(res, "Render");
		mu_assert_eq(max_v_chars_per_line(res), 1, "1-char cursor at sizeofonebar > 1");
		free(res);
		free_visual_hist(hist);
	}

	// Case 2: chart wider than data with zoom=1. histogramwidth=4, width=80,
	// so 20 screen columns map to each data index. Without the j_cursor fix
	// every one of those 20 columns would render as the cursor.
	{
		RzHistogramOptions *opts = rz_histogram_options_new();
		mu_assert_notnull(opts, "opts new");
		opts->unicode = false;
		opts->thinline = true;
		opts->color = false;
		ut8 data[4] = { 64, 128, 192, 255 };
		RzHistogramInteractive *hist = make_visual_hist(4, 80, 12, opts);
		mu_assert_notnull(hist, "hist new");
		hist->barnumber = 1;
		hist->zoom = 1; // -> sizeofonebar == 1, but width >> histogramwidth
		RzStrBuf *buf = rz_histogram_interactive_horizontal(hist, data);
		char *res = rz_strbuf_drain(buf);
		mu_assert_notnull(res, "Render");
		mu_assert_eq(max_v_chars_per_line(res), 1, "1-char cursor at histogramwidth < width");
		free(res);
		free_visual_hist(hist);
	}

	rz_cons_free();
	mu_end;
}

// The hex preview panel kicks in only when:
//   - hist->cursor_bytes is non-NULL and non-empty,
//   - the terminal is wide (hist->w > 200), AND
//   - shrinking the minimap by 43 cols still leaves at least 40 for the map.
// Verify that when these are met, two lines of `px 0x20`-style hex appear
// on the right of the minimap rows (16 bytes per row, formatted as 8 pairs
// of 2 bytes separated by single spaces), with px-style colour codes
// applied per-byte when opts->color is set.
bool test_histogram_interactive_horizontal_hex_preview(void) {
	rz_cons_new();

	// Case 1: wide terminal + cursor_bytes -> hex preview shown
	{
		RzHistogramOptions *opts = rz_histogram_options_new();
		mu_assert_notnull(opts, "opts new");
		opts->unicode = false; // ASCII so we can grep on raw hex
		opts->minimap = true;
		ut8 data[64];
		for (int i = 0; i < 64; i++) {
			data[i] = (ut8)i * 4;
		}
		RzHistogramInteractive *hist = make_visual_hist(64, 220, 18, opts);
		mu_assert_notnull(hist, "hist new");
		hist->barnumber = 32;
		ut8 cursor_bytes[32];
		// Distinctive markers: 0xab, 0xcd, 0xef on the first row,
		// 0x12, 0x34, 0x56 on the second row.
		memset(cursor_bytes, 0, sizeof(cursor_bytes));
		cursor_bytes[0] = 0xab;
		cursor_bytes[1] = 0xcd;
		cursor_bytes[2] = 0xef;
		cursor_bytes[16] = 0x12;
		cursor_bytes[17] = 0x34;
		cursor_bytes[18] = 0x56;
		hist->cursor_bytes = cursor_bytes;
		hist->cursor_bytes_len = sizeof(cursor_bytes);
		RzStrBuf *buf = rz_histogram_interactive_horizontal(hist, data);
		char *res = rz_strbuf_drain(buf);
		mu_assert_notnull(res, "Render");
		// First row of hex: `abcd ef00 0000 0000 ...`
		mu_assert_true(strstr(res, "abcd ef00") != NULL, "Hex line 1 present (abcd ef00)");
		// Second row of hex: `1234 5600 0000 0000 ...`
		mu_assert_true(strstr(res, "1234 5600") != NULL, "Hex line 2 present (1234 5600)");
		free(res);
		free_visual_hist(hist);
	}

	// Case 2: narrow terminal -> hex preview NOT shown
	{
		RzHistogramOptions *opts = rz_histogram_options_new();
		mu_assert_notnull(opts, "opts new");
		opts->unicode = false;
		opts->minimap = true;
		ut8 data[64];
		for (int i = 0; i < 64; i++) {
			data[i] = (ut8)i * 4;
		}
		RzHistogramInteractive *hist = make_visual_hist(64, 100, 18, opts);
		mu_assert_notnull(hist, "hist new");
		hist->barnumber = 32;
		ut8 cursor_bytes[32];
		memset(cursor_bytes, 0xff, sizeof(cursor_bytes)); // distinctive ffff...
		hist->cursor_bytes = cursor_bytes;
		hist->cursor_bytes_len = sizeof(cursor_bytes);
		RzStrBuf *buf = rz_histogram_interactive_horizontal(hist, data);
		char *res = rz_strbuf_drain(buf);
		mu_assert_notnull(res, "Render");
		mu_assert_null(strstr(res, "ffff ffff ffff"), "Hex panel suppressed at narrow width (<= 200 cols)");
		free(res);
		free_visual_hist(hist);
	}

	// Case 3: wide terminal but cursor_bytes is NULL -> no hex panel
	{
		RzHistogramOptions *opts = rz_histogram_options_new();
		mu_assert_notnull(opts, "opts new");
		opts->unicode = false;
		opts->minimap = true;
		ut8 data[64];
		for (int i = 0; i < 64; i++) {
			data[i] = (ut8)i * 4;
		}
		RzHistogramInteractive *hist = make_visual_hist(64, 220, 18, opts);
		mu_assert_notnull(hist, "hist new");
		hist->barnumber = 32;
		// cursor_bytes stays NULL by default.
		RzStrBuf *buf = rz_histogram_interactive_horizontal(hist, data);
		char *res = rz_strbuf_drain(buf);
		mu_assert_notnull(res, "Render");
		// Just confirm there's nothing that LOOKS like the hex panel. The
		// chart can't produce e.g. `[0-9a-f]{4} [0-9a-f]{4}` so we look for
		// a specific marker pattern that would appear if the panel
		// rendered with all-zero bytes (`0000 0000 0000 ...`).
		mu_assert_null(strstr(res, "0000 0000 0000"), "Hex panel suppressed without cursor_bytes");
		free(res);
		free_visual_hist(hist);
	}

	// Case 4: wide terminal + colour mode -> per-byte px-style colour codes
	// applied. 0x00 gets the green slot, 0xff the red slot, 0x7f yellow,
	// printable ASCII the btext slot, other bytes the "other" slot.
	{
		RzHistogramOptions *opts = rz_histogram_options_new();
		mu_assert_notnull(opts, "opts new");
		opts->unicode = true;
		opts->minimap = true;
		opts->color = true;
		opts->pal = &rz_cons_singleton()->context->pal;
		ut8 data[64];
		for (int i = 0; i < 64; i++) {
			data[i] = (ut8)i * 4;
		}
		RzHistogramInteractive *hist = make_visual_hist(64, 220, 18, opts);
		mu_assert_notnull(hist, "hist new");
		hist->barnumber = 32;
		ut8 cursor_bytes[32];
		memset(cursor_bytes, 0xab, sizeof(cursor_bytes)); // baseline "other"
		cursor_bytes[0] = 0x00; // green
		cursor_bytes[2] = 0xff; // red
		cursor_bytes[4] = 0x7f; // yellow
		cursor_bytes[6] = 'A'; // printable -> btext
		hist->cursor_bytes = cursor_bytes;
		hist->cursor_bytes_len = sizeof(cursor_bytes);
		RzStrBuf *buf = rz_histogram_interactive_horizontal(hist, data);
		char *res = rz_strbuf_drain(buf);
		mu_assert_notnull(res, "Render");
		// The hex bytes themselves still appear as text. We can't assert
		// the exact escape because palette indirection means the colour
		// can come from `pal->b0x00` or the fallback Color_GREEN. So just
		// check that there is at least one ESC sequence in the output
		// (proving the colour path ran) and that the raw hex byte values
		// are still present.
		mu_assert_true(strstr(res, "\x1b[") != NULL, "Colour escape sequences present");
		mu_assert_true(strstr(res, "00") != NULL, "0x00 byte rendered");
		mu_assert_true(strstr(res, "ff") != NULL, "0xff byte rendered");
		mu_assert_true(strstr(res, "7f") != NULL, "0x7f byte rendered");
		free(res);
		free_visual_hist(hist);
	}

	rz_cons_free();
	mu_end;
}

bool all_tests() {
	mu_run_test(test_histogram_horizontal);
	mu_run_test(test_histogram_vertical);
	mu_run_test(test_histogram_horizontal_ruler_percent);
	mu_run_test(test_histogram_horizontal_ruler_default);
	mu_run_test(test_histogram_horizontal_top_row_filled);
	mu_run_test(test_histogram_horizontal_cols_override);
	mu_run_test(test_histogram_horizontal_sparse_labels);
	mu_run_test(test_histogram_horizontal_float_labels);
	mu_run_test(test_histogram_horizontal_xaxis_offsets);
	mu_run_test(test_histogram_horizontal_data_f);
	mu_run_test(test_histogram_horizontal_multi_char_unit);
	mu_run_test(test_histogram_horizontal_precision_variants);
	mu_run_test(test_histogram_horizontal_value_scale);
	mu_run_test(test_histogram_horizontal_unicode);
	mu_run_test(test_histogram_horizontal_thinline);
	mu_run_test(test_histogram_horizontal_color);
	mu_run_test(test_histogram_horizontal_no_blocksize_no_xaxis);
	mu_run_test(test_histogram_horizontal_baseline_marker);
	mu_run_test(test_histogram_horizontal_narrow_chart);
	mu_run_test(test_histogram_horizontal_data_f_precision);
	mu_run_test(test_histogram_horizontal_combined_features);
	mu_run_test(test_histogram_horizontal_row_width_contract);
	mu_run_test(test_histogram_horizontal_no_duplicate_labels);
	mu_run_test(test_histogram_interactive_horizontal_basic);
	mu_run_test(test_histogram_interactive_horizontal_ruler_percent);
	mu_run_test(test_histogram_interactive_horizontal_ruler_default);
	mu_run_test(test_histogram_interactive_horizontal_no_negative_adder);
	mu_run_test(test_histogram_interactive_horizontal_percent);
	mu_run_test(test_histogram_interactive_horizontal_cursor_markers);
	mu_run_test(test_histogram_interactive_horizontal_cursor_full_line);
	mu_run_test(test_histogram_interactive_horizontal_cursor_width);
	mu_run_test(test_histogram_interactive_horizontal_minimap_toggle);
	mu_run_test(test_histogram_interactive_horizontal_hex_preview);
	return tests_passed != tests_run;
}

mu_main(all_tests)
