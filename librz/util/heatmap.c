// SPDX-FileCopyrightText: 2026 Shivam Chaudhary <sc31122004@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_heatmap.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_alloc.h>
#include <rz_util/rz_str.h>
#include <rz_cons.h>

#define DEFAULT_TERM_WIDTH  80
#define DEFAULT_TERM_HEIGHT 24
#define CELL_STR_WIDTH      2 // Character + space

struct rz_heatmap_t {
	RzHeatmapOptions opts;
	RzHeatmapProgressCb progress_cb;
	RzHeatmapRowLabelCb row_label_cb;
	RzHeatmapUpdateCb update_cb;
	void *user_data;
	size_t computed_rows;
	size_t computed_cols;
	size_t max_row_label_len;
};

static void compute_layout(RzHeatmap *hm) {
	size_t term_w = hm->opts.term_width ? hm->opts.term_width : DEFAULT_TERM_WIDTH;

	hm->max_row_label_len = 0;
	if (hm->row_label_cb && hm->opts.total_cells > 0) {
		// Sample row 0 to estimate label length if possible
		const char *sample_label = hm->row_label_cb(0, hm->user_data);
		if (sample_label) {
			hm->max_row_label_len = strlen(sample_label);
		}
	}

	if (hm->opts.cols > 0) {
		hm->computed_cols = hm->opts.cols;
	} else {
		size_t prefix_len = hm->max_row_label_len ? hm->max_row_label_len + 3 : 0;
		if (term_w > prefix_len + CELL_STR_WIDTH) {
			hm->computed_cols = (term_w - prefix_len) / CELL_STR_WIDTH;
		} else {
			hm->computed_cols = 1;
		}
	}

	if (hm->computed_cols == 0) {
		hm->computed_cols = 1;
	}

	hm->computed_rows = (hm->opts.total_cells + hm->computed_cols - 1) / hm->computed_cols;
	if (hm->computed_rows == 0) {
		hm->computed_rows = 1;
	}
}

static void append_cell(RzStrBuf *sb, const RzHeatmapOptions *opts, float progress) {
	// Clamp progress between 0.0 and 1.0
	if (progress < 0.0f) {
		progress = 0.0f;
	} else if (progress > 1.0f) {
		progress = 1.0f;
	}

	const char *block = opts->use_utf8 ? UTF_BLOCK : "#";

	if (!opts->use_color) {
		if (progress <= 0.0f) {
			rz_strbuf_append(sb, ". ");
		} else if (progress < 0.33f) {
			rz_strbuf_append(sb, "- ");
		} else if (progress < 0.66f) {
			rz_strbuf_append(sb, "+ ");
		} else if (progress < 1.0f) {
			rz_strbuf_append(sb, "* ");
		} else {
			rz_strbuf_append(sb, "# ");
		}
		return;
	}

	if (progress >= 1.0f) {
		// 100%: Green
		rz_strbuf_appendf(sb, "\x1b[38;5;82m%s\x1b[0m ", block);
	} else if (progress <= 0.0f) {
		// 0%: Dark grey dot/block
		rz_strbuf_appendf(sb, "\x1b[38;5;236m%s\x1b[0m ", block);
	} else if (progress < 0.25f) {
		// Dark blue
		rz_strbuf_appendf(sb, "\x1b[38;5;19m%s\x1b[0m ", block);
	} else if (progress < 0.50f) {
		// Medium blue
		rz_strbuf_appendf(sb, "\x1b[38;5;27m%s\x1b[0m ", block);
	} else if (progress < 0.75f) {
		// Light / Sky blue
		rz_strbuf_appendf(sb, "\x1b[38;5;33m%s\x1b[0m ", block);
	} else {
		// Bright cyan/blue
		rz_strbuf_appendf(sb, "\x1b[38;5;45m%s\x1b[0m ", block);
	}
}

RZ_API void rz_heatmap_options_init(RZ_NONNULL RzHeatmapOptions *opts, size_t total_cells) {
	rz_return_if_fail(opts);
	memset(opts, 0, sizeof(RzHeatmapOptions));
	opts->total_cells = total_cells;
	opts->term_width = DEFAULT_TERM_WIDTH;
	opts->term_height = DEFAULT_TERM_HEIGHT;
	opts->use_color = true;
	opts->use_utf8 = true;
	opts->palette = RZ_HEATMAP_PALETTE_BLUE_GREEN;
}

RZ_API RZ_OWN RzHeatmap *rz_heatmap_new(
	RZ_NONNULL const RzHeatmapOptions *opts,
	RZ_NONNULL RzHeatmapProgressCb progress_cb,
	RZ_NULLABLE void *user_data) {
	rz_return_val_if_fail(opts, NULL);
	rz_return_val_if_fail(progress_cb, NULL);

	RzHeatmap *hm = RZ_NEW0(RzHeatmap);
	if (!hm) {
		return NULL;
	}

	hm->opts = *opts;
	hm->progress_cb = progress_cb;
	hm->user_data = user_data;

	compute_layout(hm);
	return hm;
}

RZ_API void rz_heatmap_free(RZ_NULLABLE RzHeatmap *hm) {
	if (!hm) {
		return;
	}
	free(hm);
}

RZ_API void rz_heatmap_set_row_label_cb(RZ_NONNULL RzHeatmap *hm, RZ_NULLABLE RzHeatmapRowLabelCb cb) {
	rz_return_if_fail(hm);
	hm->row_label_cb = cb;
	compute_layout(hm);
}

RZ_API void rz_heatmap_set_update_cb(RZ_NONNULL RzHeatmap *hm, RZ_NULLABLE RzHeatmapUpdateCb cb) {
	rz_return_if_fail(hm);
	hm->update_cb = cb;
}

RZ_API void rz_heatmap_set_user_data(RZ_NONNULL RzHeatmap *hm, RZ_NULLABLE void *user_data) {
	rz_return_if_fail(hm);
	hm->user_data = user_data;
}

RZ_API void rz_heatmap_get_dimensions(RZ_NONNULL const RzHeatmap *hm, RZ_OUT size_t *rows, RZ_OUT size_t *cols) {
	rz_return_if_fail(hm);
	if (rows) {
		*rows = hm->computed_rows;
	}
	if (cols) {
		*cols = hm->computed_cols;
	}
}

RZ_API RZ_OWN char *rz_heatmap_render(RZ_NONNULL RzHeatmap *hm) {
	rz_return_val_if_fail(hm, NULL);

	RzStrBuf *sb = rz_strbuf_new("");
	if (!sb) {
		return NULL;
	}

	compute_layout(hm);

	// Title
	if (hm->opts.title && *hm->opts.title) {
		rz_strbuf_appendf(sb, "%s\n\n", hm->opts.title);
	}

	// Rows
	for (size_t r = 0; r < hm->computed_rows; r++) {
		if (hm->row_label_cb) {
			const char *lbl = hm->row_label_cb(r, hm->user_data);
			if (lbl) {
				rz_strbuf_appendf(sb, "%-*s   ", (int)hm->max_row_label_len, lbl);
			}
		}

		for (size_t c = 0; c < hm->computed_cols; c++) {
			size_t idx = r * hm->computed_cols + c;
			if (idx >= hm->opts.total_cells) {
				break;
			}
			RzHeatmapCoord coord = { .row = r, .col = c, .index = idx };
			float prog = hm->progress_cb(&coord, hm->user_data);
			append_cell(sb, &hm->opts, prog);
		}
		rz_strbuf_append(sb, "\n");
	}

	// Legend
	if (hm->opts.legend && *hm->opts.legend) {
		rz_strbuf_appendf(sb, "\n%s\n", hm->opts.legend);
	}

	return rz_strbuf_drain(sb);
}

RZ_API RZ_OWN char *rz_heatmap_render_dynamic_update(RZ_NONNULL RzHeatmap *hm) {
	rz_return_val_if_fail(hm, NULL);

	if (!hm->update_cb) {
		return rz_heatmap_render(hm);
	}

	RzIterator it = hm->update_cb(hm->user_data);
	if (rz_iterator_is_uninit(&it)) {
		return rz_heatmap_render(hm);
	}

	RzStrBuf *sb = rz_strbuf_new("");
	if (!sb) {
		rz_iterator_fini(&it);
		return NULL;
	}

	// Save cursor position
	rz_strbuf_append(sb, "\x1b[s");

	void *item;
	rz_iterator_foreach (&it, item) {
		RzHeatmapCoord *coord = (RzHeatmapCoord *)item;
		if (!coord) {
			continue;
		}

		// Calculate terminal line relative to heatmap origin
		size_t header_lines = (hm->opts.title && *hm->opts.title) ? 2 : 0;
		size_t target_row = header_lines + coord->row + 1;
		size_t prefix_len = hm->max_row_label_len ? hm->max_row_label_len + 3 : 0;
		size_t target_col = prefix_len + (coord->col * CELL_STR_WIDTH) + 1;

		// Move cursor directly to target cell
		rz_strbuf_appendf(sb, "\x1b[%zu;%zuH", target_row, target_col);

		float prog = hm->progress_cb(coord, hm->user_data);
		append_cell(sb, &hm->opts, prog);
	}

	// Restore cursor position
	rz_strbuf_append(sb, "\x1b[u");

	rz_iterator_fini(&it);
	return rz_strbuf_drain(sb);
}

