// SPDX-FileCopyrightText: 2026 Shivam Chaudhary <sc31122004@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_util/rz_heatmap.h>
#include "minunit.h"

static float mock_progress_cb(void *cell, void *user_data) {
	RzHeatmapCoord *coord = (RzHeatmapCoord *)cell;
	if (!coord) {
		return 0.0f;
	}
	// Give each cell a progress proportional to its index
	size_t total = user_data ? *(size_t *)user_data : 100;
	if (total == 0) {
		return 0.0f;
	}
	return (float)coord->index / (float)total;
}

static const char *mock_row_label_cb(size_t row, void *user_data) {
	static char labels[8][32];
	if (row >= 8) {
		return "0xFFFFFFFF";
	}
	snprintf(labels[row], sizeof(labels[row]), "0x%08zx", row * 0x300000);
	return labels[row];
}

bool test_heatmap_init_and_dimensions(void) {
	RzHeatmapOptions opts;
	rz_heatmap_options_init(&opts, 32);
	opts.cols = 8;
	opts.term_width = 80;

	size_t total = 32;
	RzHeatmap *hm = rz_heatmap_new(&opts, mock_progress_cb, &total);
	mu_assert_notnull(hm, "heatmap creation failed");

	size_t rows = 0, cols = 0;
	rz_heatmap_get_dimensions(hm, &rows, &cols);
	mu_assert_eq((ut64)cols, 8, "columns mismatch");
	mu_assert_eq((ut64)rows, 4, "rows mismatch (32 / 8 = 4)");

	rz_heatmap_free(hm);
	mu_end;
}

bool test_heatmap_render_ascii(void) {
	RzHeatmapOptions opts;
	rz_heatmap_options_init(&opts, 10);
	opts.cols = 5;
	opts.use_color = false;
	opts.use_utf8 = false;
	opts.title = "Test Heatmap";
	opts.legend = "Legend: . - + * #";

	size_t total = 10;
	RzHeatmap *hm = rz_heatmap_new(&opts, mock_progress_cb, &total);
	mu_assert_notnull(hm, "heatmap creation failed");

	char *rendered = rz_heatmap_render(hm);
	mu_assert_notnull(rendered, "rendered string is NULL");

	// Ensure title and legend are present in the output
	mu_assert("title present", strstr(rendered, "Test Heatmap") != NULL);
	mu_assert("legend present", strstr(rendered, "Legend: . - + * #") != NULL);

	free(rendered);
	rz_heatmap_free(hm);
	mu_end;
}

bool test_heatmap_with_row_labels(void) {
	RzHeatmapOptions opts;
	rz_heatmap_options_init(&opts, 24);
	opts.cols = 6;
	opts.use_color = false;

	size_t total = 24;
	RzHeatmap *hm = rz_heatmap_new(&opts, mock_progress_cb, &total);
	mu_assert_notnull(hm, "heatmap creation failed");

	rz_heatmap_set_row_label_cb(hm, mock_row_label_cb);

	char *rendered = rz_heatmap_render(hm);
	mu_assert_notnull(rendered, "rendered string is NULL");

	// Check that row 0 label "0x00000000" is included
	mu_assert("row 0 label present", strstr(rendered, "0x00000000") != NULL);

	free(rendered);
	rz_heatmap_free(hm);
	mu_end;
}

typedef struct {
	RzHeatmapCoord coords[2];
	size_t index;
} UpdateContext;

static void *update_iter_next(RzIterator *it) {
	UpdateContext *ctx = (UpdateContext *)it->u;
	if (ctx->index < 2) {
		return &ctx->coords[ctx->index++];
	}
	return NULL;
}

static RzIterator mock_update_cb(void *user_data) {
	UpdateContext *ctx = (UpdateContext *)user_data;
	RzIterator it;
	rz_iterator_init(update_iter_next, NULL, NULL, ctx, &it);
	return it;
}

bool test_heatmap_dynamic_update(void) {
	RzHeatmapOptions opts;
	rz_heatmap_options_init(&opts, 16);
	opts.cols = 4;
	opts.use_color = true;

	size_t total = 16;
	RzHeatmap *hm = rz_heatmap_new(&opts, mock_progress_cb, &total);
	mu_assert_notnull(hm, "heatmap creation failed");

	UpdateContext ctx = {
		.coords = {
			{ .row = 0, .col = 1, .index = 1 },
			{ .row = 1, .col = 2, .index = 6 },
		},
		.index = 0,
	};

	rz_heatmap_set_update_cb(hm, mock_update_cb);
	rz_heatmap_set_user_data(hm, &ctx);

	char *update_str = rz_heatmap_render_dynamic_update(hm);
	mu_assert_notnull(update_str, "update string is NULL");

	// Should contain ANSI cursor save '\x1b[s' and restore '\x1b[u'
	mu_assert("contains ANSI cursor save", strstr(update_str, "\x1b[s") != NULL);
	mu_assert("contains ANSI cursor restore", strstr(update_str, "\x1b[u") != NULL);

	free(update_str);
	rz_heatmap_free(hm);
	mu_end;
}

bool test_heatmap_null_safety(void) {
	// Calling APIs with NULL should safely return NULL or avoid crash
	RzHeatmapOptions opts;
	rz_heatmap_options_init(&opts, 10);

	RzHeatmap *hm = rz_heatmap_new(NULL, mock_progress_cb, NULL);
	mu_assert_null(hm, "expected NULL for NULL opts");

	hm = rz_heatmap_new(&opts, NULL, NULL);
	mu_assert_null(hm, "expected NULL for NULL progress_cb");

	char *out = rz_heatmap_render(NULL);
	mu_assert_null(out, "expected NULL for NULL heatmap render");

	rz_heatmap_free(NULL); // Should safely do nothing
	mu_end;
}

static bool all_tests(void) {
	mu_run_test(test_heatmap_init_and_dimensions);
	mu_run_test(test_heatmap_render_ascii);
	mu_run_test(test_heatmap_with_row_labels);
	mu_run_test(test_heatmap_dynamic_update);
	mu_run_test(test_heatmap_null_safety);
	return tests_passed != tests_run;
}

mu_main(all_tests)

