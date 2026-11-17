// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include <rz_util.h>
#include "minunit.h"

#define SLOW_BUF_SIZE  0x40000
#define PATTERN_PERIOD 0x1000
#define SLOW_N_HITS    (SLOW_BUF_SIZE / PATTERN_PERIOD)
// makes the search last about 640 ms, much longer than the cancel check interval
#define SLOW_READ_USEC_PER_KIB 2500

typedef struct {
	ut64 offset;
} SlowBufCtx;

static bool slow_buf_init(RzBuffer *b, const void *user) {
	b->priv = (void *)user;
	return true;
}

static st64 slow_buf_seek(RzBuffer *b, st64 addr, int whence) {
	SlowBufCtx *ctx = b->priv;
	ctx->offset = rz_seek_offset(ctx->offset, SLOW_BUF_SIZE, addr, whence);
	return ctx->offset;
}

static ut64 slow_buf_get_size(RzBuffer *b) {
	return SLOW_BUF_SIZE;
}

static st64 slow_buf_read(RzBuffer *b, ut8 *buf, ut64 len) {
	SlowBufCtx *ctx = b->priv;
	ut64 size = ctx->offset < SLOW_BUF_SIZE ? RZ_MIN(len, SLOW_BUF_SIZE - ctx->offset) : 0;
	rz_sys_usleep(SLOW_READ_USEC_PER_KIB * (size / 1024));
	for (ut64 i = 0; i < size; i++) {
		buf[i] = (ctx->offset + i) % PATTERN_PERIOD ? 0 : 'R';
	}
	ctx->offset += size;
	return size;
}

static const RzBufferMethods slow_buf_methods = {
	.init = slow_buf_init,
	.read = slow_buf_read,
	.get_size = slow_buf_get_size,
	.seek = slow_buf_seek,
};

static RzList /*<RzSearchHit *>*/ *slow_search(RzInterrupt *intr) {
	SlowBufCtx buf_ctx = { 0 };
	RzBuffer *buf = rz_buf_new_with_methods(&slow_buf_methods, &buf_ctx, RZ_BUFFER_CUSTOM);
	RzSearchOpt *opt = rz_search_opt_new();
	RzSearchCollection *col = rz_search_collection_bytes();
	RzList *hits = NULL;
	if (buf && opt && col &&
		rz_search_opt_set_find_options(opt, rz_search_find_opt_new()) &&
		rz_search_opt_get_find_options(opt) &&
		rz_search_opt_set_max_threads(opt, 1) &&
		rz_search_opt_set_chunk_size(opt, 1) &&
		rz_search_opt_set_show_progress(opt, RZ_SEARCH_PROGRESS_DISABLED) &&
		rz_search_opt_set_interrupt(opt, intr) &&
		rz_search_collection_bytes_add(col, "R", (const ut8 *)"R", (const ut8 *)"\xff", 1)) {
		hits = rz_search_on_buffer(opt, col, buf, NULL);
	}
	rz_search_collection_free(col);
	rz_search_opt_free(opt);
	rz_buf_free(buf);
	return hits;
}

static bool test_search_not_interrupted(void) {
	RzInterrupt *intr = rz_interrupt_new();
	mu_assert_notnull(intr, "interrupt");
	RzList *hits = slow_search(intr);
	rz_interrupt_free(intr);
	mu_assert_notnull(hits, "search failed");
	size_t n_hits = rz_list_length(hits);
	rz_list_free(hits);
	mu_assert_eq(n_hits, SLOW_N_HITS, "hits");
	mu_end;
}

static bool test_search_interrupted(void) {
	RzInterrupt *intr = rz_interrupt_new();
	mu_assert_notnull(intr, "interrupt");
	rz_interrupt_raise(intr);
	RzList *hits = slow_search(intr);
	rz_interrupt_free(intr);
	mu_assert_notnull(hits, "search failed");
	size_t n_hits = rz_list_length(hits);
	rz_list_free(hits);
	mu_assert_true(n_hits < SLOW_N_HITS, "search stops when interrupted");
	mu_end;
}

typedef struct {
	ut64 addr;
	ut32 len;
	int kwidx;
} RegexpHitRecord;

typedef struct {
	RegexpHitRecord hits[16];
	size_t count;
	int cb_ret;
} RegexpHitRecorder;

static int regexp_hit_cb(RzSearchKeyword *kw, void *user, ut64 where) {
	RegexpHitRecorder *rec = user;
	if (rec->count < RZ_ARRAY_SIZE(rec->hits)) {
		rec->hits[rec->count].addr = where;
		rec->hits[rec->count].len = kw->keyword_length;
		rec->hits[rec->count].kwidx = kw->kwidx;
	}
	rec->count++;
	return rec->cb_ret;
}

static bool test_search_regexp_update(void) {
	// Single keyword with capturing groups: only group 0 matches should be reported.
	const char *text = "xx foo1 yy foo22 zz";
	RzSearch *s = rz_search_new(RZ_SEARCH_REGEXP);
	mu_assert_notnull(s, "search new");

	RegexpHitRecorder rec = { .cb_ret = 1 };
	rz_search_set_callback(s, regexp_hit_cb, &rec);

	RzSearchKeyword *kw = rz_search_keyword_new_regexp("/(fo(o)[0-9]+)/", NULL);
	mu_assert_notnull(kw, "regexp kw");
	mu_assert_true(rz_search_kw_add(s, kw), "kw add");
	rz_search_begin(s);

	int n = rz_search_regexp_update(s, 0x1000, (const ut8 *)text, (int)strlen(text));
	mu_assert_eq(n, 2, "single kw hit count");
	mu_assert_eq(rec.count, 2, "callback count (capture groups skipped)");
	mu_assert_eq(rec.hits[0].addr, 0x1003, "hit 0 addr");
	mu_assert_eq(rec.hits[0].len, 4, "hit 0 len");
	mu_assert_eq(rec.hits[0].kwidx, 0, "hit 0 kwidx");
	mu_assert_eq(rec.hits[1].addr, 0x100b, "hit 1 addr");
	mu_assert_eq(rec.hits[1].len, 5, "hit 1 len");
	mu_assert_eq(rec.hits[1].kwidx, 0, "hit 1 kwidx");
	rz_search_free(s);

	// Multiple keywords + case-insensitive matching.
	const char *multi_text = "xx foo1 yy BAR zz foo22 bar";
	s = rz_search_new(RZ_SEARCH_REGEXP);
	mu_assert_notnull(s, "search new multi");
	rec = (RegexpHitRecorder){ .cb_ret = 1 };
	rz_search_set_callback(s, regexp_hit_cb, &rec);

	RzSearchKeyword *kw0 = rz_search_keyword_new_regexp("/(fo(o)[0-9]+)/", NULL);
	RzSearchKeyword *kw1 = rz_search_keyword_new_regexp("/bar/i", NULL);
	mu_assert_notnull(kw0, "kw0");
	mu_assert_notnull(kw1, "kw1");
	mu_assert_true(rz_search_kw_add(s, kw0), "kw0 add");
	mu_assert_true(rz_search_kw_add(s, kw1), "kw1 add");
	rz_search_begin(s);

	n = rz_search_regexp_update(s, 0x2000, (const ut8 *)multi_text, (int)strlen(multi_text));
	mu_assert_eq(n, 4, "multi kw hit count");
	mu_assert_eq(rec.count, 4, "multi kw cb count");
	mu_assert_eq(rec.hits[0].addr, 0x2003, "multi hit 0 addr");
	mu_assert_eq(rec.hits[0].len, 4, "multi hit 0 len");
	mu_assert_eq(rec.hits[0].kwidx, 0, "multi hit 0 kwidx");
	mu_assert_eq(rec.hits[1].addr, 0x2012, "multi hit 1 addr");
	mu_assert_eq(rec.hits[1].len, 5, "multi hit 1 len");
	mu_assert_eq(rec.hits[1].kwidx, 0, "multi hit 1 kwidx");
	mu_assert_eq(rec.hits[2].addr, 0x200b, "multi hit 2 addr");
	mu_assert_eq(rec.hits[2].len, 3, "multi hit 2 len");
	mu_assert_eq(rec.hits[2].kwidx, 1, "multi hit 2 kwidx");
	mu_assert_eq(rec.hits[3].addr, 0x2018, "multi hit 3 addr");
	mu_assert_eq(rec.hits[3].len, 3, "multi hit 3 len");
	mu_assert_eq(rec.hits[3].kwidx, 1, "multi hit 3 kwidx");

	// Early stop via maxhits (stops mid-second keyword).
	rz_search_reset(s, RZ_SEARCH_REGEXP);
	s->maxhits = 3;
	rec = (RegexpHitRecorder){ .cb_ret = 1 };
	rz_search_set_callback(s, regexp_hit_cb, &rec);
	rz_search_begin(s);

	n = rz_search_regexp_update(s, 0x2000, (const ut8 *)multi_text, (int)strlen(multi_text));
	mu_assert_eq(n, 3, "maxhits return count");
	mu_assert_eq(rec.count, 3, "maxhits stopped at 3");
	mu_assert_eq(s->nhits, 3, "maxhits s->nhits");

	// Callback returning 0 aborts search with -1 and cleans up iterator cleanly.
	rz_search_reset(s, RZ_SEARCH_REGEXP);
	s->maxhits = 0;
	rec = (RegexpHitRecorder){ .cb_ret = 0 };
	rz_search_set_callback(s, regexp_hit_cb, &rec);
	rz_search_begin(s);

	n = rz_search_regexp_update(s, 0x2000, (const ut8 *)multi_text, (int)strlen(multi_text));
	mu_assert_eq(n, -1, "callback abort returns -1");
	mu_assert_eq(rec.count, 1, "callback abort stopped after 1st hit");
	rz_search_free(s);

	// Invalid regexp returns -1 cleanly.
	s = rz_search_new(RZ_SEARCH_REGEXP);
	mu_assert_notnull(s, "search new invalid");
	RzSearchKeyword *bad_kw = rz_search_keyword_new_regexp("/[unclosed/", NULL);
	mu_assert_notnull(bad_kw, "bad regexp kw");
	mu_assert_true(rz_search_kw_add(s, bad_kw), "bad kw add");
	rz_search_begin(s);
	n = rz_search_regexp_update(s, 0, (const ut8 *)text, (int)strlen(text));
	mu_assert_eq(n, -1, "invalid regexp returns -1");
	rz_search_free(s);

	mu_end;
}

static RzList /*<RzSearchHit *>*/ *run_bytes_regex_search(const char *data, const char *pattern,
	bool overlap, size_t alignment) {
	RzBuffer *buf = rz_buf_new_with_bytes((const ut8 *)data, strlen(data));
	RzSearchOpt *opt = rz_search_opt_new();
	RzSearchFindOpt *fopt = rz_search_find_opt_new();
	RzSearchCollection *col = rz_search_collection_bytes();
	char *pat_copy = rz_str_dup(pattern);
	RzList *hits = NULL;
	if (!buf || !opt || !fopt || !col || !pat_copy) {
		free(pat_copy);
		rz_search_find_opt_free(fopt);
		rz_search_collection_free(col);
		rz_search_opt_free(opt);
		rz_buf_free(buf);
		return NULL;
	}
	RzSearchBytesPattern *pat = rz_search_bytes_pattern_new((ut8 *)pat_copy, NULL,
		strlen(pattern), "re", true);
	if (pat &&
		rz_search_find_opt_set_overlap_match(fopt, overlap) &&
		rz_search_find_opt_set_alignment(fopt, alignment) &&
		rz_search_opt_set_find_options(opt, fopt)) {
		fopt = NULL;
		if (rz_search_opt_set_max_threads(opt, 1) &&
			rz_search_opt_set_chunk_size(opt, 1) &&
			rz_search_opt_set_show_progress(opt, RZ_SEARCH_PROGRESS_DISABLED)) {
			RzSearchBytesPattern *owned_pat = pat;
			pat = NULL;
			if (rz_search_collection_bytes_add_pattern(col, owned_pat)) {
				hits = rz_search_on_buffer(opt, col, buf, NULL);
			}
		}
	}
	rz_search_bytes_pattern_free(pat);
	rz_search_find_opt_free(fopt);
	rz_search_collection_free(col);
	rz_search_opt_free(opt);
	rz_buf_free(buf);
	return hits;
}

static RzList /*<RzSearchHit *>*/ *run_string_regex_search_bytes(const ut8 *data, size_t len,
	const char *pattern, RzStrEnc encoding, bool overlap, size_t alignment) {
	RzBuffer *buf = rz_buf_new_with_bytes(data, len);
	RzSearchOpt *opt = rz_search_opt_new();
	RzSearchFindOpt *fopt = rz_search_find_opt_new();
	RzUtilStrScanOptions scan_opts = {
		.max_str_length = 64,
		.min_str_length = 4,
		.prefer_big_endian = false,
	};
	RzSearchCollection *col = rz_search_collection_strings(&scan_opts, 1);
	RzList *hits = NULL;
	if (buf && opt && fopt && col &&
		rz_search_find_opt_set_overlap_match(fopt, overlap) &&
		rz_search_find_opt_set_alignment(fopt, alignment) &&
		rz_search_opt_set_find_options(opt, fopt)) {
		fopt = NULL;
		if (rz_search_opt_set_max_threads(opt, 1) &&
			rz_search_opt_set_chunk_size(opt, 1) &&
			rz_search_opt_set_show_progress(opt, RZ_SEARCH_PROGRESS_DISABLED) &&
			rz_search_collection_string_add(col, pattern, RZ_REGEX_EXTENDED, alignment,
				encoding)) {
			hits = rz_search_on_buffer(opt, col, buf, NULL);
		}
	}
	rz_search_find_opt_free(fopt);
	rz_search_collection_free(col);
	rz_search_opt_free(opt);
	rz_buf_free(buf);
	return hits;
}

static RzList /*<RzSearchHit *>*/ *run_string_regex_search(const char *data, const char *pattern,
	RzStrEnc encoding, bool overlap) {
	return run_string_regex_search_bytes((const ut8 *)data, strlen(data), pattern, encoding,
		overlap, 1);
}

static bool test_search_bytes_and_strings_regex(void) {
	const char *data = "xx aaaa yy";

	// Bytes regex search: non-overlapping with capturing groups skipped.
	RzList *hits = run_bytes_regex_search(data, "(a(a))", false, 1);
	mu_assert_notnull(hits, "bytes regex non-overlap");
	mu_assert_eq(rz_list_length(hits), 2, "bytes regex non-overlap count");
	RzSearchHit *h0 = rz_list_get_n(hits, 0);
	RzSearchHit *h1 = rz_list_get_n(hits, 1);
	mu_assert_eq(h0->address, 3, "bytes non-overlap h0 addr");
	mu_assert_eq(h0->size, 2, "bytes non-overlap h0 size");
	mu_assert_eq(h1->address, 5, "bytes non-overlap h1 addr");
	mu_assert_eq(h1->size, 2, "bytes non-overlap h1 size");
	rz_list_free(hits);

	// Bytes regex search: overlapping with capturing groups skipped.
	hits = run_bytes_regex_search(data, "(a(a))", true, 1);
	mu_assert_notnull(hits, "bytes regex overlap");
	mu_assert_eq(rz_list_length(hits), 3, "bytes regex overlap count");
	h0 = rz_list_get_n(hits, 0);
	h1 = rz_list_get_n(hits, 1);
	RzSearchHit *h2 = rz_list_get_n(hits, 2);
	mu_assert_eq(h0->address, 3, "bytes overlap h0 addr");
	mu_assert_eq(h1->address, 4, "bytes overlap h1 addr");
	mu_assert_eq(h2->address, 5, "bytes overlap h2 addr");
	rz_list_free(hits);

	// Bytes regex search: alignment filter skips unaligned hits.
	hits = run_bytes_regex_search(data, "(a(a))", true, 2);
	mu_assert_notnull(hits, "bytes regex aligned");
	mu_assert_eq(rz_list_length(hits), 1, "bytes regex aligned count");
	h0 = rz_list_get_n(hits, 0);
	mu_assert_eq(h0->address, 4, "bytes aligned h0 addr");
	rz_list_free(hits);

	// Bytes regex search: no matches returns empty list.
	hits = run_bytes_regex_search(data, "zzzz", false, 1);
	mu_assert_notnull(hits, "bytes regex nomatch");
	mu_assert_eq(rz_list_length(hits), 0, "bytes regex nomatch count");
	rz_list_free(hits);

	// String regex search (direct UTF-8): non-overlapping and overlapping.
	hits = run_string_regex_search(data, "(a(a))", RZ_STRING_ENC_UTF8, false);
	mu_assert_notnull(hits, "string utf8 non-overlap");
	mu_assert_eq(rz_list_length(hits), 2, "string utf8 non-overlap count");
	rz_list_free(hits);

	hits = run_string_regex_search(data, "(a(a))", RZ_STRING_ENC_UTF8, true);
	mu_assert_notnull(hits, "string utf8 overlap");
	mu_assert_eq(rz_list_length(hits), 3, "string utf8 overlap count");
	rz_list_free(hits);

	// String regex search (direct UTF-8): alignment filtering.
	hits = run_string_regex_search_bytes((const ut8 *)data, strlen(data), "(a(a))",
		RZ_STRING_ENC_UTF8, true, 2);
	mu_assert_notnull(hits, "string utf8 aligned");
	mu_assert_eq(rz_list_length(hits), 1, "string utf8 aligned count");
	h0 = rz_list_get_n(hits, 0);
	mu_assert_eq(h0->address, 4, "string utf8 aligned addr");
	rz_list_free(hits);

	// String regex search (UTF-16LE and UTF-16BE): direct and byte-swapped iterator paths.
	static const ut8 utf16le[] = {
		'x', 0, 'a', 0, 'a', 0, 'a', 0, 'a', 0, 'y', 0
	};
	hits = run_string_regex_search_bytes(utf16le, sizeof(utf16le), "(a(a))",
		RZ_STRING_ENC_UTF16LE, false, 2);
	mu_assert_notnull(hits, "string utf16le non-overlap");
	mu_assert_eq(rz_list_length(hits), 2, "string utf16le non-overlap count");
	h0 = rz_list_get_n(hits, 0);
	mu_assert_eq(h0->address, 2, "string utf16le h0 addr");
	mu_assert_eq(h0->size, 4, "string utf16le h0 size");
	rz_list_free(hits);

	static const ut8 utf16be[] = {
		0, 'x', 0, 'a', 0, 'a', 0, 'a', 0, 'a', 0, 'y'
	};
	hits = run_string_regex_search_bytes(utf16be, sizeof(utf16be), "(a(a))",
		RZ_STRING_ENC_UTF16BE, true, 2);
	mu_assert_notnull(hits, "string utf16be overlap");
	mu_assert_eq(rz_list_length(hits), 3, "string utf16be overlap count");
	rz_list_free(hits);

	// String regex search (UTF-32LE and UTF-32BE).
	static const ut8 utf32le[] = {
		'a', 0, 0, 0, 'a', 0, 0, 0, 'a', 0, 0, 0, 'a', 0, 0, 0
	};
	hits = run_string_regex_search_bytes(utf32le, sizeof(utf32le), "(a(a))",
		RZ_STRING_ENC_UTF32LE, false, 4);
	mu_assert_notnull(hits, "string utf32le non-overlap");
	mu_assert_eq(rz_list_length(hits), 2, "string utf32le non-overlap count");
	h0 = rz_list_get_n(hits, 0);
	mu_assert_eq(h0->address, 0, "string utf32le h0 addr");
	mu_assert_eq(h0->size, 8, "string utf32le h0 size");
	rz_list_free(hits);

	static const ut8 utf32be[] = {
		0, 0, 0, 'a', 0, 0, 0, 'a', 0, 0, 0, 'a', 0, 0, 0, 'a'
	};
	hits = run_string_regex_search_bytes(utf32be, sizeof(utf32be), "(a(a))",
		RZ_STRING_ENC_UTF32BE, true, 4);
	mu_assert_notnull(hits, "string utf32be overlap");
	mu_assert_eq(rz_list_length(hits), 3, "string utf32be overlap count");
	rz_list_free(hits);

	// String regex search (scanned GUESS encoding): non-overlapping, overlapping, and aligned.
	hits = run_string_regex_search(data, "(a(a))", RZ_STRING_ENC_GUESS, false);
	mu_assert_notnull(hits, "string guess non-overlap");
	mu_assert_eq(rz_list_length(hits), 2, "string guess non-overlap count");
	rz_list_free(hits);

	hits = run_string_regex_search(data, "(a(a))", RZ_STRING_ENC_GUESS, true);
	mu_assert_notnull(hits, "string guess overlap");
	mu_assert_eq(rz_list_length(hits), 3, "string guess overlap count");
	rz_list_free(hits);

	hits = run_string_regex_search_bytes((const ut8 *)data, strlen(data), "(a(a))",
		RZ_STRING_ENC_GUESS, true, 2);
	mu_assert_notnull(hits, "string guess aligned");
	mu_assert_eq(rz_list_length(hits), 1, "string guess aligned count");
	rz_list_free(hits);

	mu_end;
}

int all_tests() {
	mu_run_test(test_search_not_interrupted);
	mu_run_test(test_search_interrupted);
	mu_run_test(test_search_regexp_update);
	mu_run_test(test_search_bytes_and_strings_regex);
	return tests_passed != tests_run;
}

mu_main(all_tests)
