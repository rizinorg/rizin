// SPDX-FileCopyrightText: 2026 Farhan-25 <shadowfinder1799@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#include "bench_utils.h"
#include <rz_list.h>

/**
 * \file bench_list.c
 * \brief Benchmark comparing two versions of rz_list_del_n
 */

static ut32 rz_list_del_n_v1(RZ_NONNULL RzList *list, ut32 n) {
	RzListIter *it;
	ut32 i;
	rz_return_val_if_fail(list, false);
	for (it = list->head, i = 0; it && it->val; it = it->next, i++) {
		if (i == n) {
			if (!it->prev && !it->next) {
				list->head = list->tail = NULL;
			} else if (!it->prev) {
				it->next->prev = NULL;
				list->head = it->next;
			} else if (!it->next) {
				it->prev->next = NULL;
				list->tail = it->prev;
			} else {
				it->prev->next = it->next;
				it->next->prev = it->prev;
			}
			rz_list_delete(list, it);
			return true;
		}
	}
	return false;
}

static ut32 rz_list_del_n_v2(RZ_NONNULL RzList *list, ut32 n) {
	rz_return_val_if_fail(list, false);
	RzListIter *it;
	ut32 i;
	for (it = list->head, i = 0; it; it = it->next, i++) {
		if (i == n) {
			rz_list_delete(list, it);
			return true;
		}
	}
	return false;
}

static void bench_rz_list_del_n(RzTable *t_out) {
	intptr_t data = 0x1337;

	RZ_BENCH_RUN_I("[rz_list_del_n] v1 - 1k", i, t_out, 1000, {
		RzList *l = rz_list_new();
		for (int j = 0; j < 1000; j++)
			rz_list_append(l, (void *)data);
		for (int j = 0; j < 1000; j++)
			rz_list_del_n_v1(l, 0);
		rz_list_free(l);
	});

	RZ_BENCH_RUN_I("[rz_list_del_n] v2 - 1k", i, t_out, 1000, {
		RzList *l = rz_list_new();
		for (int j = 0; j < 1000; j++)
			rz_list_append(l, (void *)data);
		for (int j = 0; j < 1000; j++)
			rz_list_del_n_v2(l, 0);
		rz_list_free(l);
	});

	RZ_BENCH_RUN_I("[rz_list_del_n] v1 - 100k", i, t_out, 10, {
		RzList *l = rz_list_new();
		for (int j = 0; j < 100000; j++)
			rz_list_append(l, (void *)data);
		for (int j = 0; j < 100000; j++)
			rz_list_del_n_v1(l, 0);
		rz_list_free(l);
	});

	RZ_BENCH_RUN_I("[rz_list_del_n] v2 - 100k", i, t_out, 10, {
		RzList *l = rz_list_new();
		for (int j = 0; j < 100000; j++)
			rz_list_append(l, (void *)data);
		for (int j = 0; j < 100000; j++)
			rz_list_del_n_v2(l, 0);
		rz_list_free(l);
	});

	RZ_BENCH_RUN_I("[rz_list_del_n] v1 - 1m", i, t_out, 1, {
		RzList *l = rz_list_new();
		for (int j = 0; j < 1000000; j++)
			rz_list_append(l, (void *)data);
		for (int j = 0; j < 1000000; j++)
			rz_list_del_n_v1(l, 0);
		rz_list_free(l);
	});

	RZ_BENCH_RUN_I("[rz_list_del_n] v2 - 1m", i, t_out, 1, {
		RzList *l = rz_list_new();
		for (int j = 0; j < 1000000; j++)
			rz_list_append(l, (void *)data);
		for (int j = 0; j < 1000000; j++)
			rz_list_del_n_v2(l, 0);
		rz_list_free(l);
	});
}

int main() {
	RzTable *t = rz_table_new();
	RZ_BENCH_TABLE_INIT(t);
	bench_rz_list_del_n(t);
	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	return 0;
}