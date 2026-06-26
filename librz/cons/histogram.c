// SPDX-FileCopyrightText: 2022 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-FileCopyrightText: 2026 Ashish <15678ashishk@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include <rz_util/rz_assert.h>

#define DEFAULT_SPEED 1
#define ZOOM_DEFAULT  1

/**
 * \brief Create the string buffer with the horizontal histogram.
 *
 * Output example for an entropy chart (\c opts->value_max == 1, \c
 * opts->value_precision == 2, \c opts->blocksize set, ruler enabled):
 *
 * \verbatim
 * 1.00|
 *     |                                          ##########
 *     |                                       ################
 * 0.77|                                   #########################
 *     |        ##############################################################
 *     |    ##########################################################################
 * 0.54|##############################################################################
 *     |##############################################################################
 *     |##############################################################################
 * 0.31|##############################################################################
 *     |##############################################################################
 *     |##############################################################################
 *     |##############################################################################
 * 0.00|##############################################################################
 *      ^                                       ^                              ^
 *      0x401000                                0x4013b0                       0x401770
 * \endverbatim
 *
 * Notable rendering features driven from \c opts:
 *   - Y-axis labels are sparse (at most five anchors: top, ~25 %, ~50 %,
 *     ~75 %, bottom). The chart's vertical range is read directly off the
 *     ruler. Inclusive endpoints: the top label is exactly \c value_max,
 *     the bottom label is exactly \c value_min.
 *   - \c value_scale and \c value_precision format labels as fractional
 *     values (e.g. 0.00..1.00 for Shannon entropy).
 *   - When \c opts->blocksize is non-zero, an X-axis offset ruler is
 *     appended below the chart with \c ^ tick markers and \c 0x... start /
 *     middle / end byte offsets.
 *   - When \c opts->data_f is non-NULL, the renderer reads from that
 *     double-precision buffer instead of \p data and uses fp arithmetic
 *     for the row thresholds, retaining full precision for callers like
 *     \c p==e where the ut8 quantisation would otherwise lose ~1/255.
 *
 * \param opts Histogram options: value range, formatting, ruler, blocksize,
 *             optional double-precision data buffer, colour palette, etc.
 * \param data ut8 data buffer (used unless \c opts->data_f is set).
 * \param width Number of data points in \p data (or in \c opts->data_f).
 * \param height Number of rows in the rendered chart.
 */
// Max anchor labels on a horizontal histogram's Y-axis ruler.
#define RZ_HISTOGRAM_RULER_MAX_LABELS 5

// Format a row's ruler label honouring value_scale / value_precision / value_unit.
// Returns the printable width.
static int format_ruler_label(const RzHistogramOptions *opts, double row_value, const char *unit, char *out, size_t cap) {
	int n;
	if (opts->value_precision > 0) {
		double scale = opts->value_scale != 0.0 ? opts->value_scale : 1.0;
		double v = row_value * scale;
		n = snprintf(out, cap, "%.*f%s", opts->value_precision, v, unit);
	} else {
		n = snprintf(out, cap, "%d%s", (int)row_value, unit);
	}
	return n < 0 ? 0 : n;
}

// Label value at row i. Inclusive endpoints: top -> vmax, bottom -> vmin.
// Uses fp interpolation when value_precision > 0 so that values like
// vmax=1 produce distinct labels (1.00, 0.75, 0.50, 0.25, 0.00) instead of
// integer truncation collapsing them all to "1.00". For precision=0 the
// math stays in ints so the existing 0..255 byte ruler keeps bit-exact
// labels (e.g. 255, 197, 138, 79, 0 for 5 anchors across 14 rows).
static double label_value_at(const RzHistogramOptions *opts, int i, ut32 rows, int vmax, int vmin) {
	if (rows <= 1) {
		return (double)vmax;
	}
	if (opts->value_precision > 0) {
		return (double)vmax - ((double)i * (double)(vmax - vmin)) / (double)(rows - 1);
	}
	return (double)(vmax - (int)((ut64)i * (vmax - vmin) / (rows - 1)));
}

// Pick up to RZ_HISTOGRAM_RULER_MAX_LABELS evenly spaced anchor rows
// (always including top and bottom). Returns the number selected.
static int select_ruler_label_rows(ut32 rows, bool *show) {
	memset(show, 0, sizeof(bool) * rows);
	if (rows == 0) {
		return 0;
	}
	int slots = RZ_HISTOGRAM_RULER_MAX_LABELS;
	if ((ut32)slots > rows) {
		slots = (int)rows;
	}
	if (slots <= 1) {
		show[0] = true;
		return 1;
	}
	for (int s = 0; s < slots; s++) {
		ut32 r = (ut32)((ut64)s * (rows - 1) / (slots - 1));
		if (r >= rows) {
			r = rows - 1;
		}
		show[r] = true;
	}
	int count = 0;
	for (ut32 r = 0; r < rows; r++) {
		if (show[r]) {
			count++;
		}
	}
	return count;
}

// Gutter width (cols) to fit the widest ruler label including the trailing
// vline. Returns 0 when the ruler is disabled.
static int compute_ruler_gutter(const RzHistogramOptions *opts, ut32 rows, const char *unit) {
	if (!opts->ruler) {
		return 0;
	}
	char buf[64];
	int widest = 0;
	int vmax = opts->value_max > 0 ? opts->value_max : 255;
	int vmin = opts->value_max > 0 ? opts->value_min : 0;
	if (vmax <= vmin) {
		vmax = vmin + 1;
	}
	for (ut32 i = 0; i < rows; i++) {
		int n = format_ruler_label(opts, label_value_at(opts, (int)i, rows, vmax, vmin), unit, buf, sizeof(buf));
		if (n > widest) {
			widest = n;
		}
	}
	return widest + 2; // " <label>|"
}

// Render the Y-axis label gutter for one row.
static void render_ruler_gutter(RzStrBuf *buf, const RzHistogramOptions *opts, ut32 i, ut32 rows,
	int vmax, int vmin, const char *unit, const char *vline, int gutter_w, const bool *show_label) {
	if (gutter_w <= 0) {
		return;
	}
	if (show_label && show_label[i]) {
		char label[64];
		double lv = label_value_at(opts, (int)i, rows, vmax, vmin);
		int n = format_ruler_label(opts, lv, unit, label, sizeof(label));
		int pad = gutter_w - 1 - n;
		if (pad < 1) {
			pad = 1;
		}
		for (int p = 0; p < pad; p++) {
			rz_strbuf_append(buf, " ");
		}
		rz_strbuf_append(buf, label);
	} else {
		for (int p = 0; p < gutter_w - 1; p++) {
			rz_strbuf_append(buf, " ");
		}
	}
	rz_strbuf_append(buf, vline);
}

// Compute whether a chart cell at row i, column j should be filled.
static bool cell_filled(const RzHistogramOptions *opts, const ut8 *data, int realJ,
	int row_value, double row_value_f, int vmin, int vrange, int data_storage_max) {
	if (opts->value_precision > 0) {
		// fp path: skip integer rounding in the threshold and (ut8)(255*x)
		// quantisation when opts->data_f is set.
		double v;
		if (opts->data_f) {
			v = opts->data_f[realJ];
		} else {
			v = (double)vmin + ((double)data[realJ] * (double)vrange) / (double)data_storage_max;
		}
		return v >= row_value_f;
	}
	int v = vmin + (int)((int)data[realJ] * vrange / data_storage_max);
	return v >= row_value;
}

// Emit one chart cell (bar / vline / `_` baseline / space) honouring colour.
static void render_chart_cell(RzStrBuf *buf, const RzHistogramOptions *opts, bool fill,
	const char *kol, const char *vline, const char *block, bool is_baseline_row) {
	const char *glyph = opts->thinline ? vline : block;
	if (opts->color) {
		if (fill || is_baseline_row) {
			rz_strbuf_appendf(buf, "%s%s%s", kol, glyph, Color_RESET);
		} else {
			rz_strbuf_append(buf, " ");
		}
	} else if (fill) {
		rz_strbuf_append(buf, glyph);
	} else if (is_baseline_row) {
		rz_strbuf_append(buf, "_");
	} else {
		rz_strbuf_append(buf, " ");
	}
}

// Emit the bottom X-axis ruler (`^` ticks + `0x...` start/middle/end offset labels).
static void render_xaxis_ruler(RzStrBuf *buf, const RzHistogramOptions *opts,
	ut32 cols, ut32 width, int gutter_w) {
	if (!opts->ruler || opts->blocksize == 0 || cols < 4) {
		return;
	}
	ut64 start_off = opts->offpos;
	ut64 end_off = opts->offpos + (ut64)(width > 0 ? width - 1 : 0) * opts->blocksize;
	ut64 mid_off = opts->offpos + (ut64)((width > 0 ? width - 1 : 0) / 2) * opts->blocksize;
	char l0[32], l1[32], l2[32];
	int n0 = snprintf(l0, sizeof(l0), "0x%" PFMT64x, start_off);
	int n1 = snprintf(l1, sizeof(l1), "0x%" PFMT64x, mid_off);
	int n2 = snprintf(l2, sizeof(l2), "0x%" PFMT64x, end_off);
	int mid_col = (int)cols / 2;
	// Skip middle tick if its label would overlap the start or end label.
	bool draw_mid = (n0 + 2 < mid_col) && (n1 + 2 + mid_col < (int)cols) && (n2 + 2 < (int)cols - mid_col);

	for (int p = 0; p < gutter_w; p++) {
		rz_strbuf_append(buf, " ");
	}
	for (ut32 c = 0; c < cols; c++) {
		if (c == 0 || c + 1 == cols || (draw_mid && (int)c == mid_col)) {
			rz_strbuf_append(buf, "^");
		} else {
			rz_strbuf_append(buf, " ");
		}
	}
	rz_strbuf_append(buf, "\n");

	for (int p = 0; p < gutter_w; p++) {
		rz_strbuf_append(buf, " ");
	}
	rz_strbuf_append(buf, l0);
	int written = n0;
	if (draw_mid) {
		while (written < mid_col) {
			rz_strbuf_append(buf, " ");
			written++;
		}
		rz_strbuf_append(buf, l1);
		written += n1;
	}
	int pad_to = (int)cols - n2;
	while (written < pad_to) {
		rz_strbuf_append(buf, " ");
		written++;
	}
	rz_strbuf_append(buf, l2);
	rz_strbuf_append(buf, "\n");
}

RZ_API RZ_OWN RzStrBuf *rz_histogram_horizontal(RZ_NONNULL RzHistogramOptions *opts, RZ_NONNULL const ut8 *data, ut32 width, ut32 height) {
	rz_return_val_if_fail(opts && data, NULL);
	RzStrBuf *buf = rz_strbuf_new("");
	if (!buf) {
		return NULL;
	}

	size_t i, j;
	ut32 cols = opts->cols > 0 ? opts->cols : 78;
	ut32 rows = height > 0 ? height : 10;
	const char *vline = opts->unicode ? RUNE_LINE_VERT : "|";
	const char *block = opts->unicode ? UTF_BLOCK : "#";
	// value_max=0 selects the legacy 0..255 byte scale.
	int vmax = opts->value_max > 0 ? opts->value_max : 255;
	int vmin = opts->value_max > 0 ? opts->value_min : 0;
	if (vmax <= vmin) {
		vmax = vmin + 1;
	}
	int vrange = vmax - vmin;
	const char *unit = (opts->value_unit && *opts->value_unit) ? opts->value_unit : "";
	// Rescale each ut8 datum into vmin..vmax before thresholding so a
	// peak in storage reaches the top of the chart regardless of the
	// semantic range (#5290 cer-0).
	const int data_storage_max = 255;

	int gutter_w = compute_ruler_gutter(opts, rows, unit);
	bool *show_label = NULL;
	if (opts->ruler && rows > 0) {
		show_label = RZ_NEWS0(bool, rows);
		if (show_label) {
			select_ruler_label_rows(rows, show_label);
		}
	}

	const char *kol[5] = { NULL };
	if (opts->color) {
		kol[0] = opts->pal->call;
		kol[1] = opts->pal->jmp;
		kol[2] = opts->pal->cjmp;
		kol[3] = opts->pal->mov;
		kol[4] = opts->pal->nop;
	}

	for (i = 0; i < rows; i++) {
		// Integer threshold preserves the legacy `_` baseline. The fp path
		// engages when value_precision > 0 (or opts->data_f is supplied).
		int row_value = vmax - (int)((ut64)i * vrange / rows);
		double row_value_f = 0.0;
		if (opts->value_precision > 0 && rows > 1) {
			row_value_f = (double)vmax - ((double)i * (double)vrange) / (double)(rows - 1);
		}
		size_t koli = i * 5 / rows;
		bool is_baseline_row = (i + 1 == rows);

		render_ruler_gutter(buf, opts, (ut32)i, rows, vmax, vmin, unit, vline, gutter_w, show_label);

		for (j = 0; j < cols; j++) {
			int realJ = j * width / cols;
			bool fill = cell_filled(opts, data, realJ, row_value, row_value_f,
				vmin, vrange, data_storage_max);
			render_chart_cell(buf, opts, fill, kol[koli], vline, block, is_baseline_row);
		}
		rz_strbuf_append(buf, "\n");
	}

	render_xaxis_ruler(buf, opts, cols, width, gutter_w);

	free(show_label);
	return buf;
}

static void histogram_block(RZ_NONNULL RzHistogramOptions *opts, RZ_NONNULL RzStrBuf *buf, int k, int cols) {
	rz_return_if_fail(opts && buf);
	const char *h_line = opts->unicode ? RUNE_LONG_LINE_HORIZ : "-";
	const char *block = opts->unicode ? UTF_BLOCK : "#";
	if (cols < 1) {
		cols = 1;
	}
	if (opts->color) {
		const char *kol[5];
		kol[0] = opts->pal->nop;
		kol[1] = opts->pal->mov;
		kol[2] = opts->pal->cjmp;
		kol[3] = opts->pal->jmp;
		kol[4] = opts->pal->call;
		int idx = (int)((k * 4) / cols);
		if (idx < 5) {
			const char *str = kol[idx];
			if (opts->thinline) {
				rz_strbuf_appendf(buf, "%s%s%s", str, h_line, Color_RESET);
			} else {
				rz_strbuf_appendf(buf, "%s%s%s", str, block, Color_RESET);
			}
		}
	} else {
		if (opts->thinline) {
			rz_strbuf_append(buf, h_line);
		} else {
			rz_strbuf_append(buf, block);
		}
	}
}

/**
 * \brief Create the string buffer with the vertical histogram
 *
 * │████████████████████████████████████████████████
 * │███
 * │████████████████████████████████████████████
 * │█████████████████████
 * │███████████████████████████████████████████████
 * │█████████████
 * │██████████████
 *
 * \param opts Histogram options: color, style, legend and cursor position
 * \param data A buffer with the numerical data in the format of one byte per value
 * \param width Width of the histogram
 * \param step Step for the new line
 */
RZ_API RZ_OWN RzStrBuf *rz_histogram_vertical(RZ_NONNULL RzHistogramOptions *opts, RZ_NONNULL const ut8 *data, int width, int step) {
	rz_return_val_if_fail(opts && data, NULL);
	RzStrBuf *buf = rz_strbuf_new("");
	if (!buf) {
		return NULL;
	}

	const int increment = 5;
	const char *v_line = opts->unicode ? RUNE_LINE_VERT : "|";
	int i = 0, j;

	// get the max of columns
	int cols = 0;
	for (i = 0; i < width; i++) {
		cols = data[i] > cols ? data[i] : cols;
	}
	cols /= 5;
	for (i = 0; i < width; i++) {
		ut8 next = (i + 1 < width) ? data[i + 1] : 0;
		int base = 0, k = 0;
		if (step > 0) {
			if (opts->offset) {
				ut64 at = opts->offpos + (i * step);
				if (opts->cursor) {
					if (i == opts->curpos) {
						rz_strbuf_appendf(buf, Color_INVERT "> 0x%08" PFMT64x " " Color_RESET, at);
					} else {
						rz_strbuf_appendf(buf, "  0x%08" PFMT64x " ", at);
					}
				} else {
					rz_strbuf_appendf(buf, "0x%08" PFMT64x " ", at);
				}
			}
			rz_strbuf_appendf(buf, "%03x %04x %s", i, data[i], v_line);
		} else {
			rz_strbuf_appendf(buf, "%s", v_line);
		}
		if (next < increment) {
			base = 1;
		}
		if (next < data[i]) {
			if (data[i] > increment) {
				for (j = 0; j < next + base; j += increment) {
					histogram_block(opts, buf, k, cols);
					k++;
				}
			}
			for (j = next + increment; j + base < data[i]; j += increment) {
				histogram_block(opts, buf, k, cols);
				k++;
			}
		} else {
			histogram_block(opts, buf, k, cols);
			k++;
		}
		if (i + 1 == width) {
			for (j = data[i] + increment + base; j + base < next; j += increment) {
				histogram_block(opts, buf, k, cols);
				k++;
			}
		} else if (data[i + 1] > data[i]) {
			for (j = data[i] + increment + base; j + base < next; j += increment) {
				histogram_block(opts, buf, k, cols);
				k++;
			}
		}
		if (opts->color) {
			rz_strbuf_append(buf, Color_RESET);
		}
		rz_strbuf_append(buf, "\n");
	}
	return buf;
}

RZ_API RzHistogramOptions *rz_histogram_options_new() {
	RzHistogramOptions *histops = RZ_NEW0(RzHistogramOptions);
	if (!histops) {
		return NULL;
	}
	return histops;
}

RZ_API void rz_histogram_options_free(RzHistogramOptions *histops) {
	free(histops);
}

RZ_API RzHistogramInteractive *rz_histogram_interactive_new(RzConsCanvas *can, RzHistogramOptions *opts) {
	RzHistogramInteractive *hist = RZ_NEW0(RzHistogramInteractive);
	if (!hist) {
		return NULL;
	}
	hist->opts = opts;
	hist->can = can;
	hist->zoom = ZOOM_DEFAULT;
	hist->movspeed = DEFAULT_SPEED;
	hist->barnumber = 0;
	return hist;
}

RZ_API void rz_histogram_interactive_free(RzHistogramInteractive *hist) {
	if (!hist) {
		return;
	}
	rz_cons_canvas_free(hist->can);
	rz_histogram_options_free(hist->opts);
	free(hist);
}

RZ_API void rz_histogram_interactive_zoom_in(RzHistogramInteractive *hist) {
	hist->zoom += ZOOM_DEFAULT;
	int logofwidth = 0;
	while ((1 << logofwidth) <= hist->w) {
		logofwidth++;
	}
	logofwidth--;
	if (hist->zoom > hist->size / hist->w + logofwidth) {
		hist->zoom -= ZOOM_DEFAULT;
	}
}

RZ_API void rz_histogram_interactive_zoom_out(RzHistogramInteractive *hist) {
	hist->zoom -= ZOOM_DEFAULT;
	if (hist->zoom == 0) {
		hist->zoom = ZOOM_DEFAULT;
	}
}

// Return the colour string used by `px` for a single byte (mirrors
// rz_print_byte_color). Caller is responsible for resetting after.
// Returns Color_RESET ("") when colour rendering is disabled.
static const char *hex_byte_color(const RzConsPrintablePalette *pal, bool use_color, ut8 b) {
	if (!use_color) {
		return "";
	}
	if (b == 0x00) {
		return pal && pal->b0x00 ? pal->b0x00 : Color_GREEN;
	}
	if (b == 0x7f) {
		return pal && pal->b0x7f ? pal->b0x7f : Color_YELLOW;
	}
	if (b == 0xff) {
		return pal && pal->b0xff ? pal->b0xff : Color_RED;
	}
	if (IS_PRINTABLE(b)) {
		return pal && pal->btext ? pal->btext : Color_WHITE;
	}
	return pal && pal->other ? pal->other : Color_MAGENTA;
}

// Append one row of 16 bytes as 8 space-separated pairs ("4865 6c6c ..."),
// px-style: each byte wrapped in its colour code when opts->color is set,
// missing bytes (idx >= bytes_len) rendered as two spaces to keep width stable.
static void append_hex_preview_row(RzStrBuf *buf, const RzHistogramOptions *opts,
	const ut8 *bytes, ut32 bytes_len, ut32 offset) {
	const bool use_color = opts && opts->color;
	const RzConsPrintablePalette *pal = opts ? opts->pal : NULL;
	for (ut32 i = 0; i < 16; i++) {
		ut32 idx = offset + i;
		if (bytes && idx < bytes_len) {
			ut8 b = bytes[idx];
			const char *col = hex_byte_color(pal, use_color, b);
			if (use_color && *col) {
				rz_strbuf_appendf(buf, "%s%02x%s", col, b, Color_RESET);
			} else {
				rz_strbuf_appendf(buf, "%02x", b);
			}
		} else {
			rz_strbuf_append(buf, "  ");
		}
		// Insert a separator space after every 2 bytes, except the last pair.
		if (i % 2 == 1 && i < 15) {
			rz_strbuf_append(buf, " ");
		}
	}
	// Trailing pad: rz_cons_canvas_write can clip the last column when a row
	// (especially one with UTF-8 glyphs) fills the canvas exactly.
	rz_strbuf_append(buf, " ");
}

// Render the top minimap: a window indicator framing the visible slice, above
// a density-gradient row (block elements encode each slice's average byte).
// When hex_panel is set, a two-line px-style hex preview of hex_bytes is drawn
// to the right of the two rows.
static void render_visual_minimap(RzStrBuf *buf, const RzHistogramOptions *opts,
	const ut8 *data, ut32 histogramwidth, ut32 map_w,
	ut32 adder, ut32 visible_span, ut32 gutter_w,
	bool hex_panel, const ut8 *hex_bytes, ut32 hex_bytes_len) {
	const char *levels_utf8[9] = {
		" ",
		UTF_BLOCK_LOWER_EIGHTH, UTF_BLOCK_LOWER_QUARTER, UTF_BLOCK_LOWER_THREE_EIGHTHS,
		UTF_BLOCK_LOWER_HALF, UTF_BLOCK_LOWER_FIVE_EIGHTHS, UTF_BLOCK_LOWER_THREE_QUARTERS,
		UTF_BLOCK_LOWER_SEVEN_EIGHTHS, UTF_BLOCK
	};
	const char *levels_ascii[9] = { " ", ".", ":", "-", "=", "+", "*", "#", "@" };
	const char **levels = opts->unicode ? levels_utf8 : levels_ascii;
	const char *win_left = opts->unicode ? RUNE_CORNER_TL_HEAVY : "[";
	const char *win_right = opts->unicode ? RUNE_CORNER_TR_HEAVY : "]";
	const char *win_mid = opts->unicode ? RUNE_LINE_HORIZ_HEAVY : "-";

	// Window indicator, drawn above the density row: heavy corners ┏━━━┓
	// bracket the visible slice.
	rz_strbuf_appendf(buf, "%*s", (int)gutter_w, "");
	st32 win_start_col = (st32)((ut64)adder * map_w / histogramwidth);
	st32 win_end_col = (st32)((ut64)(adder + visible_span) * map_w / histogramwidth);
	if (win_end_col <= win_start_col) {
		win_end_col = win_start_col + 1;
	}
	if (win_end_col > (st32)map_w) {
		win_end_col = (st32)map_w;
	}
	for (ut32 c = 0; c < map_w; c++) {
		if ((st32)c < win_start_col || (st32)c >= win_end_col) {
			rz_strbuf_append(buf, " ");
		} else if ((st32)c == win_start_col && win_end_col - win_start_col > 1) {
			rz_strbuf_append(buf, win_left);
		} else if ((st32)c == win_end_col - 1 && win_end_col - win_start_col > 1) {
			rz_strbuf_append(buf, win_right);
		} else {
			rz_strbuf_append(buf, win_mid);
		}
	}
	if (hex_panel) {
		rz_strbuf_append(buf, "   "); // separator margin
		append_hex_preview_row(buf, opts, hex_bytes, hex_bytes_len, 0);
	}
	rz_strbuf_append(buf, "\n");

	// Density row: each screen column averages a slice of the full data.
	rz_strbuf_appendf(buf, "%*s", (int)gutter_w, "");
	for (ut32 c = 0; c < map_w; c++) {
		st32 start_idx = (st32)((ut64)c * histogramwidth / map_w);
		st32 end_idx = (st32)((ut64)(c + 1) * histogramwidth / map_w);
		ut64 sum = 0;
		st32 cnt = 0;
		ut32 avg, lvl;
		if (end_idx <= start_idx) {
			end_idx = start_idx + 1;
		}
		if (end_idx > (st32)histogramwidth) {
			end_idx = (st32)histogramwidth;
		}
		for (st32 idx = start_idx; idx < end_idx; idx++) {
			sum += data[idx];
			cnt++;
		}
		avg = (cnt > 0) ? (ut32)(sum / cnt) : 0;
		lvl = avg * 8 / 255;
		if (lvl > 8) {
			lvl = 8;
		}
		rz_strbuf_append(buf, levels[lvl]);
	}
	if (hex_panel) {
		rz_strbuf_append(buf, "   "); // separator margin
		append_hex_preview_row(buf, opts, hex_bytes, hex_bytes_len, 16);
	}
	rz_strbuf_append(buf, "\n");
}

// Bottom status line: "Index N data V" on the left, "0x... NN%" right-aligned.
static void render_visual_status(RzStrBuf *buf, const RzHistogramInteractive *hist,
	const ut8 *data) {
	const RzHistogramOptions *opts = hist->opts;
	ut64 cursor_off = opts->offpos + (ut64)hist->barnumber * hist->blocksize;
	int percent = 0;
	char left[128] = { 0 };
	char right[64] = { 0 };
	int left_len, right_len;
	ut32 total_w;
	if (hist->size > 1) {
		percent = (int)((ut64)hist->barnumber * 100 / (ut64)(hist->size - 1));
	}
	rz_strf(left, "Index %d data %d", hist->barnumber, data[hist->barnumber]);
	rz_strf(right, "0x%" PFMT64x "  %3d%%", cursor_off, percent);
	left_len = (int)strlen(left);
	right_len = (int)strlen(right);
	total_w = hist->w > 0 ? (ut32)hist->w : 80;
	rz_strbuf_append(buf, left);
	if ((ut32)(left_len + right_len) + 1 <= total_w) {
		int pad = (int)total_w - left_len - right_len;
		rz_strbuf_appendf(buf, "%*s", pad, "");
		rz_strbuf_append(buf, right);
	} else {
		// Not enough room to right-align; squeeze in one space.
		rz_strbuf_append(buf, " ");
		rz_strbuf_append(buf, right);
	}
}

// Render the bottom X-axis offset ruler for the visual histogram (`^` ticks +
// `0x...` labels, one tick per (label_w + 3) cols).
static void render_visual_xaxis_ruler(RzStrBuf *buf, const RzHistogramInteractive *hist,
	int adder, int sizeofonebar, int gutter_w, ut32 data_cols) {
	const RzHistogramOptions *opts = hist->opts;
	int zoom = hist->zoom;
	int histogramwidth = hist->size;
	ut32 width = data_cols;
	const int label_pad = 3;
	char addr_sample[32] = { 0 };
	ut64 last_off = opts->offpos + (ut64)(hist->size - 1) * hist->blocksize;
	int addr_w, ticks, next_tick, *tick_cols;
	ut32 c;
	rz_strf(addr_sample, "0x%" PFMT64x, last_off);
	addr_w = (int)strlen(addr_sample);
	if (addr_w < 1) {
		addr_w = 1;
	}
	ticks = (int)data_cols / (addr_w + label_pad);
	if (ticks < 2) {
		ticks = 2;
	}
	if ((ut32)ticks > data_cols) {
		ticks = (int)data_cols;
	}
	tick_cols = calloc(ticks, sizeof(int));
	if (!tick_cols) {
		return;
	}
	for (int t = 0; t < ticks; t++) {
		tick_cols[t] = (int)((ut64)t * (data_cols - 1) / (ticks - 1));
	}
	rz_strbuf_appendf(buf, "%*s", gutter_w, "");
	next_tick = 0;
	for (c = 0; c < data_cols; c++) {
		if (next_tick < ticks && (int)c == tick_cols[next_tick]) {
			rz_strbuf_append(buf, "^");
			next_tick++;
		} else {
			rz_strbuf_append(buf, " ");
		}
	}
	rz_strbuf_append(buf, "\n");
	rz_strbuf_appendf(buf, "%*s", gutter_w, "");
	c = 0;
	for (int t = 0; t < ticks; t++) {
		int start_col = tick_cols[t];
		int realj, max_room, wrote;
		ut64 off;
		char label[32] = { 0 };
		if ((int)c < start_col) {
			rz_strbuf_appendf(buf, "%*s", start_col - (int)c, "");
			c = (ut32)start_col;
		}
		if (sizeofonebar > 1) {
			realj = adder + (int)c / sizeofonebar;
		} else {
			realj = adder + (int)((ut64)c * histogramwidth / ((ut64)zoom * width));
		}
		if (realj < 0) {
			realj = 0;
		} else if (realj >= hist->size) {
			realj = hist->size - 1;
		}
		off = opts->offpos + (ut64)realj * hist->blocksize;
		rz_strf(label, "0x%" PFMT64x, off);
		wrote = (int)strlen(label);
		// Truncate if the label would overflow into the next tick.
		if (t + 1 < ticks) {
			max_room = tick_cols[t + 1] - start_col - 1;
		} else {
			max_room = sizeof(label);
		}
		if (max_room < 1) {
			max_room = 1;
		}
		if (wrote > max_room) {
			wrote = max_room;
		}
		for (int k2 = 0; k2 < wrote; k2++) {
			rz_strbuf_appendf(buf, "%c", label[k2]);
			c++;
		}
	}
	rz_strbuf_append(buf, "\n");
	free(tick_cols);
}

// Aggregate the data value shown in screen column `j`: a single index when
// zoomed in, otherwise the average of the indices the column spans. Reports the
// representative data index back through `realj`.
static ut64 histogram_column_value(const RzHistogramInteractive *hist, const ut8 *data,
	int adder, int sizeofonebar, ut32 width, size_t j, int *realj) {
	int histogramwidth = hist->size;
	int zoom = hist->zoom;
	int rj, rjnext = 0;
	ut64 curdata = 0;
	if (sizeofonebar > 1) {
		rj = adder + (int)j;
		curdata = data[rj];
	} else {
		rj = adder + (j)*histogramwidth / (zoom * width);
		rjnext = adder + (j + 1) * histogramwidth / (zoom * width);
		if (rjnext <= rj) {
			rjnext = rj + 1;
		}
		int count = 0;
		for (int k = rj; k < rjnext && k < hist->size; k++) {
			if (k < 0) {
				continue;
			}
			curdata += data[k];
			count++;
		}
		if (count > 0) {
			curdata /= count;
		}
	}
	if (sizeofonebar == 1 && rj <= hist->barnumber && rjnext > hist->barnumber) {
		rj = hist->barnumber;
		curdata = data[rj];
	}
	*realj = rj;
	return curdata;
}

// Paint one chart cell: a cursor marker on the end rows, the solid cursor bar
// on the cursor column, the gradient block when the column value crosses the
// row threshold, or a blank otherwise.
static void render_visual_chart_cell(RzStrBuf *buf, const RzHistogramOptions *opts,
	bool is_cursor, bool is_top_row, bool is_bot_row, ut64 curdata, int realj, int size,
	size_t threshold, const char *cur_col, const char *grad_col, const char *vline,
	const char *block) {
	const char *glyph = opts->thinline ? vline : block;
	if (is_cursor && (is_top_row || is_bot_row)) {
		rz_strbuf_append(buf, is_top_row ? (opts->unicode ? UTF_TRIANGLE_DOWN : "v") : (opts->unicode ? UTF_TRIANGLE_UP : "^"));
	} else if (is_cursor) {
		if (opts->color) {
			rz_strbuf_appendf(buf, "%s%s%s", cur_col, glyph, Color_RESET);
		} else {
			rz_strbuf_append(buf, glyph);
		}
	} else if (realj < size && realj >= 0 && (255 - curdata < threshold || is_bot_row)) {
		rz_strbuf_appendf(buf, "%s%s%s", grad_col, glyph, Color_RESET);
	} else {
		rz_strbuf_append(buf, " ");
	}
}

// Render the chart body: the Y-axis gutter plus one block-gradient row per
// screen row, with the cursor column highlighted full height.
static void render_visual_chart_body(RzStrBuf *buf, const RzHistogramInteractive *hist,
	const ut8 *data, int adder, int sizeofonebar, ut32 width, ut32 rows, int gutter_w,
	const bool *show_label, const char **kol, const char *colofcurbar, int ruler_max,
	int ruler_min, const char *ruler_unit) {
	const RzHistogramOptions *opts = hist->opts;
	int histogramwidth = hist->size;
	int zoom = hist->zoom;
	const char *vline = opts->unicode ? RUNE_LINE_VERT : "|";
	const char *block = opts->unicode ? UTF_BLOCK : "#";

	// Resolve the cursor's screen column up-front so it renders on exactly one
	// column even when histogramwidth < width (many columns share one index).
	int j_cursor;
	if (sizeofonebar > 1) {
		j_cursor = hist->barnumber - adder;
	} else if (histogramwidth > 0) {
		int rel = hist->barnumber - adder;
		if (rel < 0) {
			rel = 0;
		}
		j_cursor = (int)((ut64)rel * (ut64)zoom * (ut64)width / (ut64)histogramwidth);
	} else {
		j_cursor = -1;
	}
	if (j_cursor < 0 || j_cursor >= (int)width) {
		j_cursor = -1;
	}

	for (size_t i = 0; i < rows; i++) {
		size_t threshold = i * (0xff / rows);
		size_t koli = i * 5 / rows;
		render_ruler_gutter(buf, opts, (ut32)i, rows, ruler_max, ruler_min,
			ruler_unit, vline, gutter_w, show_label);
		for (size_t j = 0; j < width; j++) {
			int realj;
			ut64 curdata = histogram_column_value(hist, data, adder, sizeofonebar, width, j, &realj);
			for (int kbar = 0; kbar < sizeofonebar; kbar++) {
				bool is_cursor = ((int)j == j_cursor) && (kbar == 0);
				render_visual_chart_cell(buf, opts, is_cursor, i == 0, i + 1 == rows,
					curdata, realj, hist->size, threshold, colofcurbar, kol[koli], vline, block);
			}
		}
		rz_strbuf_append(buf, "\n");
	}
}

/**
 * \brief Create the string buffer with the visual horizontal histogram
 *
 * The output combines five layers:
 *
 *   ┏━━━━━━━━━━━━━━━━━━━┓                                                       (1)
 *   ▁▂▃▄▆█▇▆▄▂▁         ▁▂▃▄▅                                                   (2)
 *   8.0|              █                                                          (3)
 *      |             ██                █                                         (3)
 *   6.0|             ██     █       █  █                                         (3)
 *      |     █      ███   █ █     ██████                                         (3)
 *   4.0|   █ █     ████  ██ █    ████████                                        (3)
 *      |  ██ █    █████ ███ █    █████████                                       (3)
 *   2.0| ████ █  █████████████  ██████████                                       (3)
 *      |███████ ███████████████ ███████████                                      (3)
 *   0.0|██████████████████████████████████                                       (3)
 *      ^             ^              ^              ^                             (4)
 *      0x100000000   0x100000160    0x1000002c0    0x100000420                   (4)
 *   Index 42 data 196                                  0x100000540    35%        (5)
 *
 *   (1) Window indicator: `┏━━━┓` marks the visible slice on the minimap.
 *   (2) Minimap density row (block chars ▁..█ = per-slice average byte). On a
 *       wide terminal (`hist->w > 200`) with cursor_bytes, a two-line px-style
 *       hex preview of the 32 bytes at the cursor sits to its right.
 *   (3) Chart body with up to 5 sparse Y-axis labels and the cursor bar.
 *   (4) X-axis offset ruler: `^` ticks plus the absolute byte offset per tick.
 *   (5) Status line: index + value on the left, offset + percent right-aligned.
 *
 * The legacy 0..255 byte ruler is used when `opts->value_max == 0`. Otherwise
 * the chart honours `opts->value_min..value_max` with `value_precision`
 * decimals and an optional `value_unit` suffix (e.g. Shannon entropy uses
 * value_max=8, value_precision=1 → labels 8.0, 6.0, 4.0, 2.0, 0.0).
 *
 * \param hist Information about the interactive histogram (canvas, cursor,
 *             zoom level, opts).
 * \param data A buffer with the numerical data in the format of one byte per
 *             value (already quantised to [0..255] by the caller).
 */
RZ_API RZ_OWN RzStrBuf *rz_histogram_interactive_horizontal(RZ_NONNULL RzHistogramInteractive *hist, RZ_NONNULL const ut8 *data) {
	rz_return_val_if_fail(hist && data, NULL);
	RzStrBuf *buf = rz_strbuf_new("");
	if (!buf) {
		return NULL;
	}

	RzHistogramOptions *opts = hist->opts;
	ut32 width = hist->w;
	ut32 height = hist->h;
	ut32 rows = height > 0 ? height : 10;
	rows--;
	// Reserve 2 lines for the X-axis ruler (tick line + label line). The
	// status line lives on the same final row as the prompt so it does not
	// consume a chart row.
	if (opts->ruler && rows > 4) {
		rows -= 2;
	}

	// value_max=0 selects the legacy 0..255 byte scale.
	int ruler_max = (opts->value_max > 0) ? opts->value_max : 255;
	int ruler_min = (opts->value_max > 0) ? opts->value_min : 0;
	if (ruler_max <= ruler_min) {
		ruler_max = ruler_min + 1;
	}
	const char *ruler_unit = (opts->value_unit && *opts->value_unit) ? opts->value_unit : "";
	int gutter_w = opts->ruler ? compute_ruler_gutter(opts, rows, ruler_unit) : 0;
	if (gutter_w > 0 && (int)width <= gutter_w + 1) {
		// Not enough room for both ruler and data: disable the gutter.
		gutter_w = 0;
	}
	if (gutter_w > 0) {
		width -= gutter_w;
	}

	int zoom = hist->zoom;
	int histogramwidth = hist->size;
	int sizeofonebar = 1;
	if (zoom > (histogramwidth / (int)width)) {
		sizeofonebar = zoom - (histogramwidth / (int)width);
	}
	width /= sizeofonebar;

	// Colour palette: gradient for the chart, distinct colour for the cursor.
	const char *kol[5];
	const char *colofcurbar;
	if (opts->color) {
		kol[0] = opts->pal->call;
		kol[1] = opts->pal->jmp;
		kol[2] = opts->pal->cjmp;
		kol[3] = opts->pal->mov;
		kol[4] = opts->pal->nop;
		// Use the dedicated word-highlight colour for the cursor bar so it
		// stays visible against any gradient. Color_INVERT here was washed
		// out against the bright gradient palette.
		colofcurbar = opts->pal->wordhl;
	} else {
		kol[0] = Color_BGGRAY;
		kol[1] = Color_BGGRAY;
		kol[2] = Color_BGGRAY;
		kol[3] = Color_BGGRAY;
		kol[4] = Color_BGGRAY;
		colofcurbar = Color_BGGRAY;
	}

	// adder = origin of the visible window. Clamp to [0, histogramwidth-span]
	// so the rendering loop never reads `data[-N]` (fixes the #4431 segfault
	// on `p==v` for files where the cursor is at offset 0).
	int adder = 0;
	int visible_span;
	if (sizeofonebar > 1) {
		// Zoomed in: one data index per bar.
		adder = hist->barnumber + 1 - (int)width / 2;
		if (adder + (int)width > histogramwidth) {
			adder = histogramwidth - (int)width;
		}
		if (adder < 0) {
			adder = 0;
		}
		visible_span = (int)width;
	} else {
		// Zoomed out: aggregate histogramwidth/zoom indices per column.
		int span = (zoom > 0) ? (histogramwidth / zoom) : histogramwidth;
		if (span <= 0) {
			span = 1;
		}
		if (span >= histogramwidth) {
			adder = 0;
		} else {
			adder = hist->barnumber - span / 2;
			if (adder + span > histogramwidth) {
				adder = histogramwidth - span;
			}
			if (adder < 0) {
				adder = 0;
			}
		}
		visible_span = span;
	}
	if (visible_span > histogramwidth) {
		visible_span = histogramwidth;
	}

	// Show the minimap when opts->minimap is set and there are rows to spare.
	// Not gated on (visible_span < histogramwidth): if the user enables it they
	// expect it even when all data is in view (the indicator spans the map).
	bool show_minimap = opts->minimap && (rows > 6);
	if (show_minimap) {
		rows -= 2;
		ut32 map_w = width * (ut32)sizeofonebar;
		if (map_w == 0) {
			map_w = 1;
		}
		// Hex preview on the right: 39 cols of hex + 3 separator + 1 pad = 43.
		// Enabled only with cursor_bytes, a wide terminal (hist->w > 200), and
		// at least 40 cols left for the minimap itself.
		const int HEX_PANEL_W = 43;
		bool show_hex = (hist->cursor_bytes && hist->cursor_bytes_len > 0 &&
			hist->w > 200 && (int)map_w > HEX_PANEL_W + 40);
		if (show_hex) {
			map_w -= HEX_PANEL_W;
		}
		render_visual_minimap(buf, opts, data, histogramwidth, map_w,
			adder, visible_span, gutter_w,
			show_hex, hist->cursor_bytes, hist->cursor_bytes_len);
	}

	// Pick up to 5 anchor rows for the sparse Y-axis labels.
	bool *show_label = NULL;
	if (opts->ruler && gutter_w > 0 && rows > 0) {
		show_label = RZ_NEWS0(bool, rows);
		if (show_label) {
			select_ruler_label_rows(rows, show_label);
		}
	}

	render_visual_chart_body(buf, hist, data, adder, sizeofonebar, width, rows,
		gutter_w, show_label, kol, colofcurbar, ruler_max, ruler_min, ruler_unit);

	// X-axis byte-offset ruler.
	if (opts->ruler) {
		ut32 data_cols = width * (ut32)sizeofonebar;
		if (data_cols > 0) {
			render_visual_xaxis_ruler(buf, hist, adder, sizeofonebar, gutter_w, data_cols);
		}
	}

	// Bottom status line: cursor index/data on the left, offset/percent
	// right-aligned.
	render_visual_status(buf, hist, data);

	free(show_label);
	return buf;
}
