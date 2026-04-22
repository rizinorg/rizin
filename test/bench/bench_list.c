// SPDX-FileCopyrightText: 2026 Farhan-25 <shadowfinder1799@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "bench_utils.h"
#include <rz_list.h>

/**
 * \file bench_list.c
 * \brief Benchmarks for core RzList operations.
 */

static void _fill(RzList *l, int count) {
	for (int j = 0; j < count; j++) {
		rz_list_append(l, (void *)(intptr_t)j);
	}
}

static void bench_append(RzTable *t_out) {
	RZ_BENCH_RUN_I("[append] 10k", i, t_out, 1000, {
		RzList *l = rz_list_new();
		_fill(l, 10000);
		rz_list_free(l);
	});
	RZ_BENCH_RUN_I("[append] 100k", i, t_out, 100, {
		RzList *l = rz_list_new();
		_fill(l, 100000);
		rz_list_free(l);
	});
	RZ_BENCH_RUN_I("[append] 1m", i, t_out, 10, {
		RzList *l = rz_list_new();
		_fill(l, 1000000);
		rz_list_free(l);
	});
}

static void bench_prepend(RzTable *t_out) {
	RZ_BENCH_RUN_I("[prepend] 10k", i, t_out, 1000, {
		RzList *l = rz_list_new();
		for (int j = 0; j < 10000; j++) {
			rz_list_prepend(l, (void *)(intptr_t)j);
		}
		rz_list_free(l);
	});
	RZ_BENCH_RUN_I("[prepend] 100k", i, t_out, 100, {
		RzList *l = rz_list_new();
		for (int j = 0; j < 100000; j++) {
			rz_list_prepend(l, (void *)(intptr_t)j);
		}
		rz_list_free(l);
	});
	RZ_BENCH_RUN_I("[prepend] 1m", i, t_out, 10, {
		RzList *l = rz_list_new();
		for (int j = 0; j < 1000000; j++) {
			rz_list_prepend(l, (void *)(intptr_t)j);
		}
		rz_list_free(l);
	});
}

static void bench_pop(RzTable *t_out) {
	RZ_BENCH_RUN_I("[pop] 1k", i, t_out, 1000, {
		RzList *l = rz_list_new();
		_fill(l, 1000);
		while (l->length) {
			rz_list_pop(l);
		}
		rz_list_free(l);
	});
	RZ_BENCH_RUN_I("[pop] 100k", i, t_out, 100, {
		RzList *l = rz_list_new();
		_fill(l, 100000);
		while (l->length) {
			rz_list_pop(l);
		}
		rz_list_free(l);
	});
	RZ_BENCH_RUN_I("[pop] 1m", i, t_out, 10, {
		RzList *l = rz_list_new();
		_fill(l, 1000000);
		while (l->length) {
			rz_list_pop(l);
		}
		rz_list_free(l);
	});
}

static void bench_pop_head(RzTable *t_out) {
	RZ_BENCH_RUN_I("[pop_head] 1k", i, t_out, 1000, {
		RzList *l = rz_list_new();
		_fill(l, 1000);
		while (l->length) {
			rz_list_pop_head(l);
		}
		rz_list_free(l);
	});
	RZ_BENCH_RUN_I("[pop_head] 100k", i, t_out, 100, {
		RzList *l = rz_list_new();
		_fill(l, 100000);
		while (l->length) {
			rz_list_pop_head(l);
		}
		rz_list_free(l);
	});
	RZ_BENCH_RUN_I("[pop_head] 1m", i, t_out, 10, {
		RzList *l = rz_list_new();
		_fill(l, 1000000);
		while (l->length) {
			rz_list_pop_head(l);
		}
		rz_list_free(l);
	});
}

static void bench_del_n(RzTable *t_out) {
	RZ_BENCH_RUN_I("[del_n@0] 1k", i, t_out, 1000, {
		RzList *l = rz_list_new();
		_fill(l, 1000);
		for (int j = 0; j < 1000; j++) {
			rz_list_del_n(l, 0);
		}
		rz_list_free(l);
	});
	RZ_BENCH_RUN_I("[del_n@0] 100k", i, t_out, 10, {
		RzList *l = rz_list_new();
		_fill(l, 100000);
		for (int j = 0; j < 100000; j++) {
			rz_list_del_n(l, 0);
		}
		rz_list_free(l);
	});
	RZ_BENCH_RUN_I("[del_n@0] 1m", i, t_out, 1, {
		RzList *l = rz_list_new();
		_fill(l, 1000000);
		for (int j = 0; j < 1000000; j++) {
			rz_list_del_n(l, 0);
		}
		rz_list_free(l);
	});
	RZ_BENCH_RUN_I("[del_n@tail] 100k", i, t_out, 10, {
		RzList *l = rz_list_new();
		_fill(l, 100000);
		while (l->length) {
			rz_list_del_n(l, l->length - 1);
		}
		rz_list_free(l);
	});
	RZ_BENCH_RUN_I("[del_n@mid] 10k", i, t_out, 10, {
		RzList *l = rz_list_new();
		_fill(l, 10000);
		while (l->length) {
			rz_list_del_n(l, l->length / 2);
		}
		rz_list_free(l);
	});
}

static void bench_purge(RzTable *t_out) {
	RZ_BENCH_RUN_I("[purge] 10k", i, t_out, 1000, {
		RzList *l = rz_list_new();
		_fill(l, 10000);
		rz_list_purge(l);
		rz_list_free(l);
	});
	RZ_BENCH_RUN_I("[purge] 100k", i, t_out, 100, {
		RzList *l = rz_list_new();
		_fill(l, 100000);
		rz_list_purge(l);
		rz_list_free(l);
	});
	RZ_BENCH_RUN_I("[purge] 1m", i, t_out, 10, {
		RzList *l = rz_list_new();
		_fill(l, 1000000);
		rz_list_purge(l);
		rz_list_free(l);
	});
}

static void bench_mixed_append_pop(RzTable *t_out) {
	RZ_BENCH_RUN_I("[mixed append+pop] 100k", i, t_out, 100, {
		RzList *l = rz_list_new();
		for (int j = 0; j < 100000; j++) {
			rz_list_append(l, (void *)(intptr_t)j);
			if (j % 2 == 0)
				rz_list_pop(l);
		}
		rz_list_free(l);
	});
	RZ_BENCH_RUN_I("[mixed append+pop] 1m", i, t_out, 10, {
		RzList *l = rz_list_new();
		for (int j = 0; j < 1000000; j++) {
			rz_list_append(l, (void *)(intptr_t)j);
			if (j % 2 == 0)
				rz_list_pop(l);
		}
		rz_list_free(l);
	});
}

static void bench_mixed_purge_refill(RzTable *t_out) {
	RZ_BENCH_RUN_I("[mixed purge+refill] 10k", i, t_out, 500, {
		RzList *l = rz_list_new();
		_fill(l, 10000);
		rz_list_purge(l);
		_fill(l, 10000);
		rz_list_free(l);
	});
	RZ_BENCH_RUN_I("[mixed purge+refill] 100k", i, t_out, 50, {
		RzList *l = rz_list_new();
		_fill(l, 100000);
		rz_list_purge(l);
		_fill(l, 100000);
		rz_list_free(l);
	});
}

int main(void) {
	RzTable *t = rz_table_new();
	RZ_BENCH_TABLE_INIT(t);

	bench_append(t);
	bench_prepend(t);
	bench_pop(t);
	bench_pop_head(t);
	bench_del_n(t);
	bench_purge(t);
	bench_mixed_append_pop(t);
	bench_mixed_purge_refill(t);
	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	return 0;
}
