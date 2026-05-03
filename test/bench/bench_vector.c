// SPDX-FileCopyrightText: 2026 Jules
// SPDX-License-Identifier: LGPL-3.0-only

#include "bench_utils.h"
#include <rz_vector.h>

/**
 * \file bench_vector.c
 * \brief Benchmarks for core RzVector and RzPVector operations.
 */

/* Use a fixed seed so runs are reproducible across PRs/CI. */
#define RZ_BENCH_SEED 0xC0FFEE

static int cmp_ptr(const void *a, const void *b, void *user) {
    (void)user;
    uintptr_t ua = (uintptr_t)a;
    uintptr_t ub = (uintptr_t)b;
    return (ua > ub) - (ua < ub);
}

static int cmp_int(const void *a, const void *b, void *user) {
    (void)user;
    int ia = *(const int *)a;
    int ib = *(const int *)b;
    return (ia > ib) - (ia < ib);
}

/* ---------- pvector uniq: O(n^2) -> O(n log n) win ---------- */

static void bench_pvector_uniq(RzTable *t_out) {
    /* 100k elements, ~100 unique values => ~1000-fold duplication.
     * Old implementation: O(n^2) ~= 10^10 ops, expected to be very slow.
     * New implementation (sort + adjacent-dedup): O(n log n). */
    RZ_BENCH_RUN_I("[pvector uniq] 100k x100 dup", i, t_out, 50, {
        RzPVector *v = rz_pvector_new(NULL);
        for (int j = 0; j < 100000; j++) {
            rz_pvector_push(v, (void *)(intptr_t)(rand() % 100));
        }
        rz_pvector_uniq(v, cmp_ptr, NULL);
        rz_pvector_free(v);
    });

    /* Worst case for the OLD code: every element unique => O(n^2) full scan.
     * The new sort-based path keeps O(n log n) here too. */
    RZ_BENCH_RUN_I("[pvector uniq] 20k all-unique", i, t_out, 20, {
        RzPVector *v = rz_pvector_new(NULL);
        for (int j = 0; j < 20000; j++) {
            rz_pvector_push(v, (void *)(intptr_t)j);
        }
        rz_pvector_uniq(v, cmp_ptr, NULL);
        rz_pvector_free(v);
    });
}

/* ---------- vector remove_if: bulk removal in O(n) ---------- */

static bool pred_even(const void *elem, void *user) {
    return (*(int *)elem & 1) == 0;
}

static void bench_vector_remove_if(RzTable *t_out) {
    /* 1m ints, predicate true on ~50% of them. Old per-element rz_vector_remove_at
     * pattern was O(n^2); new bulk path should be O(n). */
    RZ_BENCH_RUN_I("[vector remove_if] 1m, 50%", i, t_out, 10, {
        RzVector *v = rz_vector_new(sizeof(int), NULL, NULL);
        for (int j = 0; j < 1000000; j++) {
            rz_vector_push(v, &j);
        }
        rz_vector_remove_if(v, pred_even, NULL);
        rz_vector_free(v);
    });

    /* Worst case for naive removal: predicate always true (full clear via shifts). */
    RZ_BENCH_RUN_I("[vector remove_if] 100k, 100%", i, t_out, 50, {
        RzVector *v = rz_vector_new(sizeof(int), NULL, NULL);
        for (int j = 0; j < 100000; j++) {
            rz_vector_push(v, &j);
        }
        rz_vector_remove_if(v, pred_even, NULL); /* will need pred_true variant */
        rz_vector_free(v);
    });
}

/* ---------- pvector sort: adversarial inputs ---------- */

static void fill_random(RzPVector *v, int n) {
    for (int j = 0; j < n; j++) {
        rz_pvector_push(v, (void *)(intptr_t)rand());
    }
}
static void fill_sorted(RzPVector *v, int n) {
    for (int j = 0; j < n; j++) {
        rz_pvector_push(v, (void *)(intptr_t)j);
    }
}
static void fill_reverse(RzPVector *v, int n) {
    for (int j = 0; j < n; j++) {
        rz_pvector_push(v, (void *)(intptr_t)(n - j));
    }
}
static void fill_organ_pipe(RzPVector *v, int n) {
    /* 1,2,...,n/2,n/2,...,2,1 — a classic median-of-three pessimization. */
    for (int j = 0; j < n / 2; j++) {
        rz_pvector_push(v, (void *)(intptr_t)j);
    }
    for (int j = n / 2; j > 0; j--) {
        rz_pvector_push(v, (void *)(intptr_t)j);
    }
}
static void fill_all_equal(RzPVector *v, int n) {
    for (int j = 0; j < n; j++) {
        rz_pvector_push(v, (void *)(intptr_t)42);
    }
}

#define BENCH_PVECTOR_SORT_PATTERN(label, filler, count, iters)              \
    RZ_BENCH_RUN_I(label, i, t_out, iters, {                                 \
        RzPVector *v = rz_pvector_new(NULL);                                 \
        filler(v, count);                                                    \
        rz_pvector_sort(v, cmp_ptr, NULL);                                   \
        rz_pvector_free(v);                                                  \
    })

static void bench_pvector_sort_adversarial(RzTable *t_out) {
    BENCH_PVECTOR_SORT_PATTERN("[pvector sort] 10k sorted",     fill_sorted,     10000, 100);
    BENCH_PVECTOR_SORT_PATTERN("[pvector sort] 10k reverse",    fill_reverse,    10000, 100);
    BENCH_PVECTOR_SORT_PATTERN("[pvector sort] 10k organ-pipe", fill_organ_pipe, 10000, 100);
    BENCH_PVECTOR_SORT_PATTERN("[pvector sort] 10k all-equal",  fill_all_equal,  10000, 100);
}

/* ---------- large-input sorts: surface constant-factor differences ---------- */

static void bench_sort_large(RzTable *t_out) {
    RZ_BENCH_RUN_I("[vector sort] 1m random", i, t_out, 5, {
        RzVector *v = rz_vector_new(sizeof(int), NULL, NULL);
        for (int j = 0; j < 1000000; j++) {
            int val = rand();
            rz_vector_push(v, &val);
        }
        rz_vector_sort(v, cmp_int, false, NULL);
        rz_vector_free(v);
    });

    BENCH_PVECTOR_SORT_PATTERN("[pvector sort] 1m random",      fill_random,     1000000, 5);
    BENCH_PVECTOR_SORT_PATTERN("[pvector sort] 1m sorted",      fill_sorted,     1000000, 5);
    BENCH_PVECTOR_SORT_PATTERN("[pvector sort] 1m reverse",     fill_reverse,    1000000, 5);
    BENCH_PVECTOR_SORT_PATTERN("[pvector sort] 1m organ-pipe",  fill_organ_pipe, 1000000, 5);
}


static void bench_vector_push(RzTable *t_out) {
	RZ_BENCH_RUN_I("[vector push] 100k", i, t_out, 100, {
		RzVector *v = rz_vector_new(sizeof(int), NULL, NULL);
		for (int j = 0; j < 100000; j++) {
			rz_vector_push(v, &j);
		}
		rz_vector_free(v);
	});
	RZ_BENCH_RUN_I("[vector push] 1m", i, t_out, 10, {
		RzVector *v = rz_vector_new(sizeof(int), NULL, NULL);
		for (int j = 0; j < 1000000; j++) {
			rz_vector_push(v, &j);
		}
		rz_vector_free(v);
	});
}

static void bench_pvector_push(RzTable *t_out) {
	RZ_BENCH_RUN_I("[pvector push] 100k", i, t_out, 100, {
		RzPVector *v = rz_pvector_new(NULL);
		for (int j = 0; j < 100000; j++) {
			rz_pvector_push(v, (void *)(intptr_t)j);
		}
		rz_pvector_free(v);
	});
	RZ_BENCH_RUN_I("[pvector push] 1m", i, t_out, 10, {
		RzPVector *v = rz_pvector_new(NULL);
		for (int j = 0; j < 1000000; j++) {
			rz_pvector_push(v, (void *)(intptr_t)j);
		}
		rz_pvector_free(v);
	});
}

static void bench_vector_sort(RzTable *t_out) {
	int count = 10000;
	RZ_BENCH_RUN_I("[vector sort] 10k", i, t_out, 100, {
		RzVector *v = rz_vector_new(sizeof(int), NULL, NULL);
		for (int j = 0; j < count; j++) {
			int val = rand();
			rz_vector_push(v, &val);
		}
		rz_vector_sort(v, cmp_int, false, NULL);
		rz_vector_free(v);
	});
}

static void bench_pvector_sort(RzTable *t_out) {
	int count = 10000;
	RZ_BENCH_RUN_I("[pvector sort] 10k", i, t_out, 100, {
		RzPVector *v = rz_pvector_new(NULL);
		for (int j = 0; j < count; j++) {
			rz_pvector_push(v, (void *)(intptr_t)rand());
		}
		rz_pvector_sort(v, cmp_ptr, NULL);
		rz_pvector_free(v);
	});
}

/* ----- pvector find / find_index: linear scan + prefetch ----- */

static void bench_pvector_find(RzTable *t_out) {
    /* 10k elements: target at the end (worst case for a forward linear scan). */
    RZ_BENCH_RUN_I("[pvector find] 10k worst", i, t_out, 100, {
        RzPVector *v = rz_pvector_new(NULL);
        for (int j = 0; j < 10000; j++) {
            rz_pvector_push(v, (void *)(intptr_t)j);
        }
        void *val = (void *)(intptr_t)9999;
        RZ_DONT_OPTIMIZE(void **, rz_pvector_find(v, val, cmp_ptr, NULL));
        rz_pvector_free(v);
    });

    /* 10k elements: target at the start (best case). */
    RZ_BENCH_RUN_I("[pvector find] 10k best", i, t_out, 100, {
        RzPVector *v = rz_pvector_new(NULL);
        for (int j = 0; j < 10000; j++) {
            rz_pvector_push(v, (void *)(intptr_t)j);
        }
        void *val = (void *)(intptr_t)0;
        RZ_DONT_OPTIMIZE(void **, rz_pvector_find(v, val, cmp_ptr, NULL));
        rz_pvector_free(v);
    });

    /* 10k elements: value not present (full scan, returns NULL). */
    RZ_BENCH_RUN_I("[pvector find] 10k miss", i, t_out, 100, {
        RzPVector *v = rz_pvector_new(NULL);
        for (int j = 0; j < 10000; j++) {
            rz_pvector_push(v, (void *)(intptr_t)j);
        }
        void *val = (void *)(intptr_t)-1;
        RZ_DONT_OPTIMIZE(void **, rz_pvector_find(v, val, cmp_ptr, NULL));
        rz_pvector_free(v);
    });

    /* 1m elements: stresses the prefetch path past RZ_PVECTOR_PREFETCH_THRESHOLD. */
    RZ_BENCH_RUN_I("[pvector find] 1m worst", i, t_out, 10, {
        RzPVector *v = rz_pvector_new(NULL);
        for (int j = 0; j < 1000000; j++) {
            rz_pvector_push(v, (void *)(intptr_t)j);
        }
        void *val = (void *)(intptr_t)999999;
        RZ_DONT_OPTIMIZE(void **, rz_pvector_find(v, val, cmp_ptr, NULL));
        rz_pvector_free(v);
    });

    RZ_BENCH_RUN_I("[pvector find] 1m miss", i, t_out, 10, {
        RzPVector *v = rz_pvector_new(NULL);
        for (int j = 0; j < 1000000; j++) {
            rz_pvector_push(v, (void *)(intptr_t)j);
        }
        void *val = (void *)(intptr_t)-1;
        RZ_DONT_OPTIMIZE(void **, rz_pvector_find(v, val, cmp_ptr, NULL));
        rz_pvector_free(v);
    });
}

static void bench_pvector_find_index(RzTable *t_out) {
    /* Mirror the find benchmarks for the index-returning variant. */
    RZ_BENCH_RUN_I("[pvector find_index] 10k worst", i, t_out, 100, {
        RzPVector *v = rz_pvector_new(NULL);
        for (int j = 0; j < 10000; j++) {
            rz_pvector_push(v, (void *)(intptr_t)j);
        }
        void *val = (void *)(intptr_t)9999;
        RZ_DONT_OPTIMIZE(size_t, rz_pvector_find_index(v, val, cmp_ptr, NULL));
        rz_pvector_free(v);
    });

    RZ_BENCH_RUN_I("[pvector find_index] 10k best", i, t_out, 100, {
        RzPVector *v = rz_pvector_new(NULL);
        for (int j = 0; j < 10000; j++) {
            rz_pvector_push(v, (void *)(intptr_t)j);
        }
        void *val = (void *)(intptr_t)0;
        RZ_DONT_OPTIMIZE(size_t, rz_pvector_find_index(v, val, cmp_ptr, NULL));
        rz_pvector_free(v);
    });

    RZ_BENCH_RUN_I("[pvector find_index] 10k miss", i, t_out, 100, {
        RzPVector *v = rz_pvector_new(NULL);
        for (int j = 0; j < 10000; j++) {
            rz_pvector_push(v, (void *)(intptr_t)j);
        }
        void *val = (void *)(intptr_t)-1;
        RZ_DONT_OPTIMIZE(size_t, rz_pvector_find_index(v, val, cmp_ptr, NULL));
        rz_pvector_free(v);
    });

    RZ_BENCH_RUN_I("[pvector find_index] 1m worst", i, t_out, 10, {
        RzPVector *v = rz_pvector_new(NULL);
        for (int j = 0; j < 1000000; j++) {
            rz_pvector_push(v, (void *)(intptr_t)j);
        }
        void *val = (void *)(intptr_t)999999;
        RZ_DONT_OPTIMIZE(size_t, rz_pvector_find_index(v, val, cmp_ptr, NULL));
        rz_pvector_free(v);
    });

    RZ_BENCH_RUN_I("[pvector find_index] 1m miss", i, t_out, 10, {
        RzPVector *v = rz_pvector_new(NULL);
        for (int j = 0; j < 1000000; j++) {
            rz_pvector_push(v, (void *)(intptr_t)j);
        }
        void *val = (void *)(intptr_t)-1;
        RZ_DONT_OPTIMIZE(size_t, rz_pvector_find_index(v, val, cmp_ptr, NULL));
        rz_pvector_free(v);
    });
}

int main(void) {
	srand(RZ_BENCH_SEED);

	RzTable *t_out = rz_table_new();
	RZ_BENCH_TABLE_INIT(t_out);

	bench_vector_push(t_out);
	bench_pvector_push(t_out);
	bench_vector_sort(t_out);
	bench_pvector_sort(t_out);
	bench_pvector_uniq(t_out);
    bench_vector_remove_if(t_out);
    bench_pvector_sort_adversarial(t_out);
    bench_sort_large(t_out);
	bench_pvector_find(t_out);
	bench_pvector_find_index(t_out);

	RZ_BENCH_RUN_I("[vector contains] 10k", i, t_out, 100, {
		RzVector *v = rz_vector_new(sizeof(int), NULL, NULL);
		for (int j = 0; j < 10000; j++) {
			rz_vector_push(v, &j);
		}
		int val = 9999;
		RZ_DONT_OPTIMIZE(bool, rz_vector_contains(v, &val));
		rz_vector_free(v);
	});

	RZ_BENCH_RUN_I("[pvector contains] 10k", i, t_out, 100, {
		RzPVector *v = rz_pvector_new(NULL);
		for (int j = 0; j < 10000; j++) {
			rz_pvector_push(v, (void *)(intptr_t)j);
		}
		void *val = (void *)(intptr_t)9999;
		RZ_DONT_OPTIMIZE(void **, rz_pvector_contains(v, val));
		rz_pvector_free(v);
	});

	RZ_BENCH_TABLE_PRINT_AND_FREE(t_out);
	return 0;
}
