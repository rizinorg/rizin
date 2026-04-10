// SPDX-FileCopyrightText: 2026 Farhan-25 <shadowfinder1799@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "bench_utils.h"
#include <rz_list.h>

/**
 * \file bench_list_pool.c
 * \brief Benchmark comparing v1 (plain malloc/free per node) vs
 *        v2 (slab pool allocator) across the core RzList operations.
 *
 * Every pair of benchmarks is labelled "v1" (old) / "v2" (new) so the
 * table output mirrors the style of bench_list.c.
 *
 * Self-contained mini-implementations
 * ------------------------------------
 * Rather than relying on two separately-linked objects, this file embeds
 * trimmed versions of the allocation primitives for both strategies so a
 * single binary produces all numbers.
 *
 *   _v1_*  /  use_pool=false  →  plain malloc/free  (Document 2 / old)
 *   _v2_*  /  use_pool=true   →  slab pool          (Document 1 / new)
 *
 * Only the node-lifecycle functions differ; list link/unlink logic is
 * shared and called identically by both variants.
 */

#define BENCH_SLAB_SIZE 256

typedef struct BenchNode {
	struct BenchNode *next;
	struct BenchNode *prev;
	void *val;
} BenchNode;

typedef struct BenchSlab {
	BenchNode nodes[BENCH_SLAB_SIZE];
	struct BenchSlab *next_slab;
} BenchSlab;

typedef struct BenchPool {
	BenchNode *freelist;
	BenchSlab *slabs;
} BenchPool;

typedef struct BenchList {
	BenchNode *head;
	BenchNode *tail;
	ut32 length;
	BenchPool *pool; /* NULL for v1, non-NULL for v2 */
} BenchList;

static BenchList *_v1_list_new(void) {
	return RZ_NEW0(BenchList);
}

static BenchNode *_v1_node_alloc(void) {
	return RZ_NEW0(BenchNode);
}

static void _v1_node_free(BenchNode *n) {
	free(n);
}

static void _v1_list_free(BenchList *l) {
	if (!l)
		return;
	BenchNode *it = l->head;
	while (it) {
		BenchNode *nx = it->next;
		_v1_node_free(it);
		it = nx;
	}
	free(l);
}

static BenchPool *_v2_pool_new(void) {
	return RZ_NEW0(BenchPool);
}

static void _v2_pool_destroy(BenchPool *pool) {
	if (!pool) {
		return;
	}
	BenchSlab *s = pool->slabs;
	while (s) {
		BenchSlab *nx = s->next_slab;
		free(s);
		s = nx;
	}
	free(pool);
}

static BenchNode *_v2_node_alloc(BenchPool *pool) {
	if (!pool->freelist) {
		BenchSlab *slab = RZ_NEW0(BenchSlab);
		if (!slab)
			return NULL;
		slab->next_slab = pool->slabs;
		pool->slabs = slab;
		for (int i = 0; i < BENCH_SLAB_SIZE - 1; i++) {
			slab->nodes[i].next = &slab->nodes[i + 1];
		}
		slab->nodes[BENCH_SLAB_SIZE - 1].next = NULL;
		pool->freelist = &slab->nodes[0];
	}
	BenchNode *n = pool->freelist;
	pool->freelist = n->next;
	n->next = n->prev = NULL;
	n->val = NULL;
	return n;
}

static void _v2_node_free(BenchPool *pool, BenchNode *n) {
	if (!n)
		return;
	n->val = NULL;
	n->prev = NULL;
	n->next = pool->freelist;
	pool->freelist = n;
}

static BenchList *_v2_list_new(void) {
	BenchList *l = RZ_NEW0(BenchList);
	if (!l)
		return NULL;
	l->pool = _v2_pool_new();
	if (!l->pool) {
		free(l);
		return NULL;
	}
	return l;
}

static void _v2_list_free(BenchList *l) {
	if (!l)
		return;
	_v2_pool_destroy(l->pool);
	free(l);
}

static BenchNode *_bench_iter_at(BenchList *l, ut32 n) {
	if (n >= l->length)
		return NULL;
	BenchNode *it;
	if (n < l->length / 2) {
		it = l->head;
		for (ut32 i = 0; i < n; i++)
			it = it->next;
	} else {
		it = l->tail;
		for (ut32 i = l->length - 1; i > n; i--)
			it = it->prev;
	}
	return it;
}

static void _bench_append(BenchList *l, void *data, bool use_pool) {
	BenchNode *n = use_pool ? _v2_node_alloc(l->pool) : _v1_node_alloc();
	if (!n)
		return;
	n->val = data;
	n->prev = l->tail;
	n->next = NULL;
	if (l->tail)
		l->tail->next = n;
	l->tail = n;
	if (!l->head)
		l->head = n;
	l->length++;
}

static void _bench_prepend(BenchList *l, void *data, bool use_pool) {
	BenchNode *n = use_pool ? _v2_node_alloc(l->pool) : _v1_node_alloc();
	if (!n)
		return;
	n->val = data;
	n->next = l->head;
	n->prev = NULL;
	if (l->head)
		l->head->prev = n;
	l->head = n;
	if (!l->tail)
		l->tail = n;
	l->length++;
}

static void _bench_node_delete(BenchList *l, BenchNode *n, bool use_pool) {
	if (l->head == n)
		l->head = n->next;
	if (l->tail == n)
		l->tail = n->prev;
	if (n->prev)
		n->prev->next = n->next;
	if (n->next)
		n->next->prev = n->prev;
	l->length--;
	if (use_pool)
		_v2_node_free(l->pool, n);
	else
		_v1_node_free(n);
}

static void *_bench_pop(BenchList *l, bool use_pool) {
	if (!l->tail)
		return NULL;
	BenchNode *n = l->tail;
	void *val = n->val;
	if (l->head == l->tail) {
		l->head = l->tail = NULL;
	} else {
		l->tail = n->prev;
		l->tail->next = NULL;
	}
	l->length--;
	if (use_pool)
		_v2_node_free(l->pool, n);
	else
		_v1_node_free(n);
	return val;
}

static void *_bench_pop_head(BenchList *l, bool use_pool) {
	if (!l->head)
		return NULL;
	BenchNode *n = l->head;
	void *val = n->val;
	if (l->head == l->tail) {
		l->head = l->tail = NULL;
	} else {
		l->head = n->next;
		l->head->prev = NULL;
	}
	l->length--;
	if (use_pool)
		_v2_node_free(l->pool, n);
	else
		_v1_node_free(n);
	return val;
}

static void _bench_purge(BenchList *l, bool use_pool) {
	BenchNode *it = l->head;
	while (it) {
		BenchNode *nx = it->next;
		if (use_pool)
			_v2_node_free(l->pool, it);
		else
			_v1_node_free(it);
		it = nx;
	}
	l->head = l->tail = NULL;
	l->length = 0;
}

static bool _bench_del_n(BenchList *l, ut32 n, bool use_pool) {
	BenchNode *it = _bench_iter_at(l, n);
	if (!it)
		return false;
	_bench_node_delete(l, it, use_pool);
	return true;
}

/* convenience fill helpers */
#define _fill_v1(l, count) \
	do { \
		for (int _j = 0; _j < (count); _j++) \
			_bench_append(l, (void *)(intptr_t)_j, false); \
	} while (0)
#define _fill_v2(l, count) \
	do { \
		for (int _j = 0; _j < (count); _j++) \
			_bench_append(l, (void *)(intptr_t)_j, true); \
	} while (0)

static void bench_append(RzTable *t_out) {
	RZ_BENCH_RUN_I("[append] v1 - 10k", i, t_out, 1000, {
		BenchList *l = _v1_list_new();
		_fill_v1(l, 10000);
		_v1_list_free(l);
	});
	RZ_BENCH_RUN_I("[append] v2 - 10k", i, t_out, 1000, {
		BenchList *l = _v2_list_new();
		_fill_v2(l, 10000);
		_v2_list_free(l);
	});
	RZ_BENCH_RUN_I("[append] v1 - 100k", i, t_out, 100, {
		BenchList *l = _v1_list_new();
		_fill_v1(l, 100000);
		_v1_list_free(l);
	});
	RZ_BENCH_RUN_I("[append] v2 - 100k", i, t_out, 100, {
		BenchList *l = _v2_list_new();
		_fill_v2(l, 100000);
		_v2_list_free(l);
	});
	RZ_BENCH_RUN_I("[append] v1 - 1m", i, t_out, 10, {
		BenchList *l = _v1_list_new();
		_fill_v1(l, 1000000);
		_v1_list_free(l);
	});
	RZ_BENCH_RUN_I("[append] v2 - 1m", i, t_out, 10, {
		BenchList *l = _v2_list_new();
		_fill_v2(l, 1000000);
		_v2_list_free(l);
	});
}

static void bench_prepend(RzTable *t_out) {
	RZ_BENCH_RUN_I("[prepend] v1 - 10k", i, t_out, 1000, {
		BenchList *l = _v1_list_new();
		for (int j = 0; j < 10000; j++)
			_bench_prepend(l, (void *)(intptr_t)j, false);
		_v1_list_free(l);
	});
	RZ_BENCH_RUN_I("[prepend] v2 - 10k", i, t_out, 1000, {
		BenchList *l = _v2_list_new();
		for (int j = 0; j < 10000; j++)
			_bench_prepend(l, (void *)(intptr_t)j, true);
		_v2_list_free(l);
	});
	RZ_BENCH_RUN_I("[prepend] v1 - 100k", i, t_out, 100, {
		BenchList *l = _v1_list_new();
		for (int j = 0; j < 100000; j++)
			_bench_prepend(l, (void *)(intptr_t)j, false);
		_v1_list_free(l);
	});
	RZ_BENCH_RUN_I("[prepend] v2 - 100k", i, t_out, 100, {
		BenchList *l = _v2_list_new();
		for (int j = 0; j < 100000; j++)
			_bench_prepend(l, (void *)(intptr_t)j, true);
		_v2_list_free(l);
	});
	RZ_BENCH_RUN_I("[prepend] v1 - 1m", i, t_out, 10, {
		BenchList *l = _v1_list_new();
		for (int j = 0; j < 1000000; j++)
			_bench_prepend(l, (void *)(intptr_t)j, false);
		_v1_list_free(l);
	});
	RZ_BENCH_RUN_I("[prepend] v2 - 1m", i, t_out, 10, {
		BenchList *l = _v2_list_new();
		for (int j = 0; j < 1000000; j++)
			_bench_prepend(l, (void *)(intptr_t)j, true);
		_v2_list_free(l);
	});
}

static void bench_pop(RzTable *t_out) {
	RZ_BENCH_RUN_I("[pop] v1 - 1k", i, t_out, 1000, {
		BenchList *l = _v1_list_new();
		_fill_v1(l, 1000);
		while (l->length)
			_bench_pop(l, false);
		_v1_list_free(l);
	});
	RZ_BENCH_RUN_I("[pop] v2 - 1k", i, t_out, 1000, {
		BenchList *l = _v2_list_new();
		_fill_v2(l, 1000);
		while (l->length)
			_bench_pop(l, true);
		_v2_list_free(l);
	});
	RZ_BENCH_RUN_I("[pop] v1 - 100k", i, t_out, 100, {
		BenchList *l = _v1_list_new();
		_fill_v1(l, 100000);
		while (l->length)
			_bench_pop(l, false);
		_v1_list_free(l);
	});
	RZ_BENCH_RUN_I("[pop] v2 - 100k", i, t_out, 100, {
		BenchList *l = _v2_list_new();
		_fill_v2(l, 100000);
		while (l->length)
			_bench_pop(l, true);
		_v2_list_free(l);
	});
	RZ_BENCH_RUN_I("[pop] v1 - 1m", i, t_out, 10, {
		BenchList *l = _v1_list_new();
		_fill_v1(l, 1000000);
		while (l->length)
			_bench_pop(l, false);
		_v1_list_free(l);
	});
	RZ_BENCH_RUN_I("[pop] v2 - 1m", i, t_out, 10, {
		BenchList *l = _v2_list_new();
		_fill_v2(l, 1000000);
		while (l->length)
			_bench_pop(l, true);
		_v2_list_free(l);
	});
}

static void bench_pop_head(RzTable *t_out) {
	RZ_BENCH_RUN_I("[pop_head] v1 - 1k", i, t_out, 1000, {
		BenchList *l = _v1_list_new();
		_fill_v1(l, 1000);
		while (l->length)
			_bench_pop_head(l, false);
		_v1_list_free(l);
	});
	RZ_BENCH_RUN_I("[pop_head] v2 - 1k", i, t_out, 1000, {
		BenchList *l = _v2_list_new();
		_fill_v2(l, 1000);
		while (l->length)
			_bench_pop_head(l, true);
		_v2_list_free(l);
	});
	RZ_BENCH_RUN_I("[pop_head] v1 - 100k", i, t_out, 100, {
		BenchList *l = _v1_list_new();
		_fill_v1(l, 100000);
		while (l->length)
			_bench_pop_head(l, false);
		_v1_list_free(l);
	});
	RZ_BENCH_RUN_I("[pop_head] v2 - 100k", i, t_out, 100, {
		BenchList *l = _v2_list_new();
		_fill_v2(l, 100000);
		while (l->length)
			_bench_pop_head(l, true);
		_v2_list_free(l);
	});
	RZ_BENCH_RUN_I("[pop_head] v1 - 1m", i, t_out, 10, {
		BenchList *l = _v1_list_new();
		_fill_v1(l, 1000000);
		while (l->length)
			_bench_pop_head(l, false);
		_v1_list_free(l);
	});
	RZ_BENCH_RUN_I("[pop_head] v2 - 1m", i, t_out, 10, {
		BenchList *l = _v2_list_new();
		_fill_v2(l, 1000000);
		while (l->length)
			_bench_pop_head(l, true);
		_v2_list_free(l);
	});
}

static void bench_del_n(RzTable *t_out) {
	RZ_BENCH_RUN_I("[del_n@0] v1 - 100k", i, t_out, 10, {
		BenchList *l = _v1_list_new();
		_fill_v1(l, 100000);
		for (int j = 0; j < 100000; j++)
			_bench_del_n(l, 0, false);
		_v1_list_free(l);
	});
	RZ_BENCH_RUN_I("[del_n@0] v2 - 100k", i, t_out, 10, {
		BenchList *l = _v2_list_new();
		_fill_v2(l, 100000);
		for (int j = 0; j < 100000; j++)
			_bench_del_n(l, 0, true);
		_v2_list_free(l);
	});
	RZ_BENCH_RUN_I("[del_n@tail] v2 - 100k", i, t_out, 10, {
		BenchList *l = _v2_list_new();
		_fill_v2(l, 100000);
		while (l->length)
			_bench_del_n(l, l->length - 1, true);
		_v2_list_free(l);
	});
	RZ_BENCH_RUN_I("[del_n@mid] v2 - 10k", i, t_out, 10, {
		BenchList *l = _v2_list_new();
		_fill_v2(l, 10000);
		while (l->length)
			_bench_del_n(l, l->length / 2, true);
		_v2_list_free(l);
	});
}

static void bench_purge(RzTable *t_out) {
	RZ_BENCH_RUN_I("[purge] v1 - 10k", i, t_out, 1000, {
		BenchList *l = _v1_list_new();
		_fill_v1(l, 10000);
		_bench_purge(l, false);
		_v1_list_free(l);
	});
	RZ_BENCH_RUN_I("[purge] v2 - 10k", i, t_out, 1000, {
		BenchList *l = _v2_list_new();
		_fill_v2(l, 10000);
		_bench_purge(l, true);
		_v2_list_free(l);
	});
	RZ_BENCH_RUN_I("[purge] v1 - 100k", i, t_out, 100, {
		BenchList *l = _v1_list_new();
		_fill_v1(l, 100000);
		_bench_purge(l, false);
		_v1_list_free(l);
	});
	RZ_BENCH_RUN_I("[purge] v2 - 100k", i, t_out, 100, {
		BenchList *l = _v2_list_new();
		_fill_v2(l, 100000);
		_bench_purge(l, true);
		_v2_list_free(l);
	});
	RZ_BENCH_RUN_I("[purge] v1 - 1m", i, t_out, 10, {
		BenchList *l = _v1_list_new();
		_fill_v1(l, 1000000);
		_bench_purge(l, false);
		_v1_list_free(l);
	});
	RZ_BENCH_RUN_I("[purge] v2 - 1m", i, t_out, 10, {
		BenchList *l = _v2_list_new();
		_fill_v2(l, 1000000);
		_bench_purge(l, true);
		_v2_list_free(l);
	});
}

static void bench_mixed_append_pop(RzTable *t_out) {
	RZ_BENCH_RUN_I("[mixed append+pop] v1 - 100k", i, t_out, 100, {
		BenchList *l = _v1_list_new();
		for (int j = 0; j < 100000; j++) {
			_bench_append(l, (void *)(intptr_t)j, false);
			if (j % 2 == 0)
				_bench_pop(l, false);
		}
		_v1_list_free(l);
	});
	RZ_BENCH_RUN_I("[mixed append+pop] v2 - 100k", i, t_out, 100, {
		BenchList *l = _v2_list_new();
		for (int j = 0; j < 100000; j++) {
			_bench_append(l, (void *)(intptr_t)j, true);
			if (j % 2 == 0)
				_bench_pop(l, true);
		}
		_v2_list_free(l);
	});
	RZ_BENCH_RUN_I("[mixed append+pop] v1 - 1m", i, t_out, 10, {
		BenchList *l = _v1_list_new();
		for (int j = 0; j < 1000000; j++) {
			_bench_append(l, (void *)(intptr_t)j, false);
			if (j % 2 == 0)
				_bench_pop(l, false);
		}
		_v1_list_free(l);
	});
	RZ_BENCH_RUN_I("[mixed append+pop] v2 - 1m", i, t_out, 10, {
		BenchList *l = _v2_list_new();
		for (int j = 0; j < 1000000; j++) {
			_bench_append(l, (void *)(intptr_t)j, true);
			if (j % 2 == 0)
				_bench_pop(l, true);
		}
		_v2_list_free(l);
	});
}

static void bench_mixed_purge_refill(RzTable *t_out) {
	RZ_BENCH_RUN_I("[mixed purge+refill] v1 - 10k", i, t_out, 500, {
		BenchList *l = _v1_list_new();
		_fill_v1(l, 10000);
		_bench_purge(l, false);
		_fill_v1(l, 10000);
		_v1_list_free(l);
	});
	RZ_BENCH_RUN_I("[mixed purge+refill] v2 - 10k", i, t_out, 500, {
		BenchList *l = _v2_list_new();
		_fill_v2(l, 10000);
		_bench_purge(l, true);
		_fill_v2(l, 10000); /* warm pool */
		_v2_list_free(l);
	});
	RZ_BENCH_RUN_I("[mixed purge+refill] v1 - 100k", i, t_out, 50, {
		BenchList *l = _v1_list_new();
		_fill_v1(l, 100000);
		_bench_purge(l, false);
		_fill_v1(l, 100000);
		_v1_list_free(l);
	});
	RZ_BENCH_RUN_I("[mixed purge+refill] v2 - 100k", i, t_out, 50, {
		BenchList *l = _v2_list_new();
		_fill_v2(l, 100000);
		_bench_purge(l, true);
		_fill_v2(l, 100000);
		_v2_list_free(l);
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