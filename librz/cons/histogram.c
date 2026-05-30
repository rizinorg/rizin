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

/**
 * \brief Create the string buffer with the horizontal histogram
 *
 *		 █    ██      █             █                                        █
 *		 █    ██      █             █                                       ██
 *	 █   █    ██      █             █ █                                     ██
 *	 ██  █    ██  █ ███             █ █              █                      ██   █
 *	 ██  ██   ███ █ ███             █ █              █ █     █    █   █ █   ██   █
 *	 ██  ██   ███ █ ███          █  █ █         █    █ █    ██    █   ███   ██   █
 *	 ██  ██   ███ █ ███          █  █ █  █      █    █ █    ██    █   ███  ███ █ █
 *	███  ██   ███ █ ███          █  █ █  █      █    █ █    ██    █   ███  █████ █
 *	███████   ███ █ ███          █  █ █  █      █    ███    ██    █   ███  █████ █
 *	███████   ███ █ ███   ██    ██  █ █  █  █   █    ███   ███   ██   ███  █████ █
 *	███████  ████ █ ███   ██    ██  █ █  █  █   █    ███   ███   ██   ████ █████ █
 * 	███████  ████ █ ███   ██    ██  █ █  ██ █   ██   ███   ███   ██   ████ █████ █
 *	███████__████_█_███__███__█_██_████__████___██__████___███___██__█████_█████_█
 *
 * \param hist Information about the interactive histogram
 * \param data A buffer with the numerical data in the format of one byte per value
 * \param width Width of the histogram
 * \param height Height of the histogram
 */
RZ_API RZ_OWN RzStrBuf *rz_histogram_interactive_horizontal(RZ_NONNULL RzHistogramInteractive *hist, const unsigned char *data) {
	rz_return_val_if_fail(data, NULL);
	RzStrBuf *buf = rz_strbuf_new("");
	if (!buf) {
		return NULL;
	}

	RzHistogramOptions *opts = hist->opts;
	size_t i, j;
	unsigned int width = hist->w;
	unsigned int height = hist->h;
	ut32 rows = height > 0 ? height : 10;
	rows--;
	const char *vline = opts->unicode ? RUNE_LINE_VERT : "|";
	const char *block = opts->unicode ? UTF_BLOCK : "#";
	const char *kol[5];
	kol[0] = opts->pal->call;
	kol[1] = opts->pal->jmp;
	kol[2] = opts->pal->cjmp;
	kol[3] = opts->pal->mov;
	kol[4] = opts->pal->nop;
	int zoom = hist->zoom;
	int histogramwidth = hist->size;
	int sizeofonebar = 1;
	if (zoom > (histogramwidth / width)) {
		sizeofonebar = zoom - (histogramwidth / width);
	}
	width /= sizeofonebar;
	const char *colofcurbar;
	if (opts->color) {
		kol[0] = opts->pal->call;
		kol[1] = opts->pal->jmp;
		kol[2] = opts->pal->cjmp;
		kol[3] = opts->pal->mov;
		kol[4] = opts->pal->nop;
		colofcurbar = Color_RED;
	} else {
		kol[0] = Color_BGGRAY;
		kol[1] = Color_BGGRAY;
		kol[2] = Color_BGGRAY;
		kol[3] = Color_BGGRAY;
		kol[4] = Color_BGGRAY;
		colofcurbar = Color_BGGRAY;
	}
	int adder = 0;
	// adder is for movement of graphs
	// like if graph has width more than the screen width
	// then we need some index from which it to start to maintain the current index in the middle
	if (sizeofonebar > 1) {
		adder = hist->barnumber + 1 - width / 2;
	} else {
		adder = hist->barnumber + 1 - histogramwidth / (zoom * 2);
	}
	for (i = 0; i < rows; i++) {
		size_t threshold = i * (0xff / rows);
		size_t koli = i * 5 / rows;
		int k;
		for (j = 0; j < width; j++) {
			int realj, realjnext = 0; // realj is the starting index for a bar
						  // realjnext is the starting index for the next bar
			unsigned long long curdata = 0;
			if (sizeofonebar > 1) {
				// if size of a single bar is greater than 1 means only one index corresponds to a single bar
				// so no need to take the average of bars from realj to realjnext
				realj = adder + j;
				curdata = data[realj];
			} else {
				realj = adder + (j)*histogramwidth / (zoom * width);
				realjnext = adder + (j + 1) * histogramwidth / (zoom * width);
				// take average of the size of the data from realj to realjnext to get a average bar size
				for (int i = realj; i < realjnext; i++) {
					curdata += data[i];
				}
				curdata /= (realjnext - realj);
			}
			if (sizeofonebar == 1 && realj <= hist->barnumber && realjnext > hist->barnumber) {
				realj = hist->barnumber;
				curdata = data[realj];
			}
			for (k = 0; k < sizeofonebar; k++) {
				if (realj < hist->size && realj >= 0 && (255 - curdata < threshold || (i + 1 == rows))) {
					if (realj == hist->barnumber) {
						if (opts->thinline) {
							rz_strbuf_appendf(buf, "%s%s%s", colofcurbar, vline, Color_RESET);
						} else {
							rz_strbuf_appendf(buf, "%s%s%s", colofcurbar, block, Color_RESET);
						}
					} else {
						if (opts->thinline) {
							rz_strbuf_appendf(buf, "%s%s%s", kol[koli], vline, Color_RESET);
						} else {
							rz_strbuf_appendf(buf, "%s%s%s", kol[koli], block, Color_RESET);
						}
					}
				} else {
					rz_strbuf_append(buf, " ");
				}
			}
		}
		rz_strbuf_append(buf, "\n");
	}
	rz_strbuf_appendf(buf, "Current Index %d data %d", hist->barnumber, data[hist->barnumber]);
	return buf;
}
