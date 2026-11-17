// SPDX-FileCopyrightText: 2026 Rizin contributors
// SPDX-License-Identifier: LGPL-3.0-only

#include "bench_utils.h"
#include <rz_util.h>

#define REGEX_BENCH_REPEATS 10000
#define REGEX_BENCH_ITERS   100

static char *make_repeated_text(const char *unit, size_t repeats, size_t *out_len) {
	size_t ulen = strlen(unit);
	size_t total = ulen * repeats;
	char *buf = malloc(total + 1);
	if (!buf) {
		return NULL;
	}
	for (size_t i = 0; i < repeats; i++) {
		memcpy(buf + i * ulen, unit, ulen);
	}
	buf[total] = '\0';
	if (out_len) {
		*out_len = total;
	}
	return buf;
}

static void bench_regex_plain(RzTable *t_out) {
	size_t len = 0;
	char *text = make_repeated_text("Text", REGEX_BENCH_REPEATS, &len);
	RzRegex *re = rz_regex_new("Text", RZ_REGEX_EXTENDED, 0, NULL);
	if (!text || !re) {
		rz_regex_free(re);
		free(text);
		return;
	}

	RZ_BENCH_RUN("rz_regex_match_all (10k matches)", t_out, REGEX_BENCH_ITERS, {
		RzPVector *matches = rz_regex_match_all(re, text, len, 0, RZ_REGEX_DEFAULT);
		size_t count = matches ? rz_pvector_len(matches) : 0;
		RZ_DONT_OPTIMIZE(size_t, count);
		rz_pvector_free(matches);
	});

	RZ_BENCH_RUN("rz_regex_match_iter (10k matches)", t_out, REGEX_BENCH_ITERS, {
		RzIterator it;
		size_t sum = 0;
		if (rz_regex_match_iter(re, text, len, 0, RZ_REGEX_DEFAULT, &it)) {
			RzRegexMatch *m;
			rz_iterator_foreach(&it, m) {
				sum += m->start;
			}
			rz_iterator_fini(&it);
		}
		RZ_DONT_OPTIMIZE(size_t, sum);
	});

	rz_regex_free(re);
	free(text);
}

static void bench_regex_groups(RzTable *t_out) {
	size_t len = 0;
	char *text = make_repeated_text("Text", REGEX_BENCH_REPEATS, &len);
	RzRegex *re = rz_regex_new("(Te(x)t)", RZ_REGEX_EXTENDED, 0, NULL);
	if (!text || !re) {
		rz_regex_free(re);
		free(text);
		return;
	}

	RZ_BENCH_RUN("rz_regex_match_all (10k x 3 groups)", t_out, REGEX_BENCH_ITERS, {
		RzPVector *matches = rz_regex_match_all(re, text, len, 0, RZ_REGEX_DEFAULT);
		size_t count = matches ? rz_pvector_len(matches) : 0;
		RZ_DONT_OPTIMIZE(size_t, count);
		rz_pvector_free(matches);
	});

	RZ_BENCH_RUN("rz_regex_match_iter (10k x 3 groups)", t_out, REGEX_BENCH_ITERS, {
		RzIterator it;
		size_t sum = 0;
		if (rz_regex_match_iter(re, text, len, 0, RZ_REGEX_DEFAULT, &it)) {
			RzRegexMatch *m;
			rz_iterator_foreach(&it, m) {
				sum += m->match_idx + m->group_idx;
			}
			rz_iterator_fini(&it);
		}
		RZ_DONT_OPTIMIZE(size_t, sum);
	});

	rz_regex_free(re);
	free(text);
}

static void bench_regex_overlap(RzTable *t_out) {
	size_t len = 0;
	char *text = make_repeated_text("a", REGEX_BENCH_REPEATS, &len);
	RzRegex *re = rz_regex_new("aa", RZ_REGEX_EXTENDED, 0, NULL);
	if (!text || !re) {
		rz_regex_free(re);
		free(text);
		return;
	}

	RZ_BENCH_RUN("rz_regex_match_all_overlap (9999 matches)", t_out, REGEX_BENCH_ITERS, {
		RzPVector *matches = rz_regex_match_all_overlap(re, text, len, 0, RZ_REGEX_DEFAULT);
		size_t count = matches ? rz_pvector_len(matches) : 0;
		RZ_DONT_OPTIMIZE(size_t, count);
		rz_pvector_free(matches);
	});

	RZ_BENCH_RUN("rz_regex_match_iter_overlap (9999 matches)", t_out, REGEX_BENCH_ITERS, {
		RzIterator it;
		size_t sum = 0;
		if (rz_regex_match_iter_overlap(re, text, len, 0, RZ_REGEX_DEFAULT, &it)) {
			RzRegexMatch *m;
			rz_iterator_foreach(&it, m) {
				sum += m->start;
			}
			rz_iterator_fini(&it);
		}
		RZ_DONT_OPTIMIZE(size_t, sum);
	});

	rz_regex_free(re);
	free(text);
}

static void bench_regex_early_exit(RzTable *t_out) {
	size_t len = 0;
	char *text = make_repeated_text("Text", REGEX_BENCH_REPEATS, &len);
	RzRegex *re = rz_regex_new("Text", RZ_REGEX_EXTENDED, 0, NULL);
	if (!text || !re) {
		rz_regex_free(re);
		free(text);
		return;
	}

	RZ_BENCH_RUN("rz_regex_match_all (first 10 of 10k)", t_out, REGEX_BENCH_ITERS, {
		RzPVector *matches = rz_regex_match_all(re, text, len, 0, RZ_REGEX_DEFAULT);
		size_t limit = matches ? RZ_MIN((size_t)10, rz_pvector_len(matches)) : 0;
		RZ_DONT_OPTIMIZE(size_t, limit);
		rz_pvector_free(matches);
	});

	RZ_BENCH_RUN("rz_regex_match_iter (first 10 of 10k)", t_out, REGEX_BENCH_ITERS, {
		RzIterator it;
		size_t count = 0;
		if (rz_regex_match_iter(re, text, len, 0, RZ_REGEX_DEFAULT, &it)) {
			RzRegexMatch *m;
			rz_iterator_foreach(&it, m) {
				if (++count >= 10) {
					break;
				}
			}
			rz_iterator_fini(&it);
		}
		RZ_DONT_OPTIMIZE(size_t, count);
	});

	rz_regex_free(re);
	free(text);
}

int main(void) {
	RzTable *t = rz_table_new();
	if (!t) {
		return 1;
	}
	RZ_BENCH_TABLE_INIT(t);

	bench_regex_plain(t);
	bench_regex_groups(t);
	bench_regex_overlap(t);
	bench_regex_early_exit(t);

	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	return 0;
}
