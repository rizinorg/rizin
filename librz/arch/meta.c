// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_core.h>

static bool item_matches_filter(RzAnalysisMetaItem *item, RzAnalysisMetaType type, RZ_NULLABLE const RzSpace *space) {
	return (type == RZ_META_TYPE_ANY || item->type == type) && (!space || item->space == space);
}

typedef struct {
	RzAnalysisMetaType type;
	const RzSpace *space;

	RzIntervalNode *node;
} FindCtx;

static bool find_node_cb(RzIntervalNode *node, void *user) {
	FindCtx *ctx = user;
	if (item_matches_filter(node->data, ctx->type, ctx->space)) {
		ctx->node = node;
		return false;
	}
	return true;
}

static RzIntervalNode *find_node_at(RzAnalysis *analysis, RzAnalysisMetaType type, RZ_NULLABLE const RzSpace *space, ut64 addr) {
	FindCtx ctx = {
		.type = type,
		.space = space,
		.node = NULL
	};
	rz_interval_tree_all_at(&analysis->meta, addr, find_node_cb, &ctx);
	return ctx.node;
}

static RzIntervalNode *find_node_in(RzAnalysis *analysis, RzAnalysisMetaType type, RZ_NULLABLE const RzSpace *space, ut64 addr) {
	FindCtx ctx = {
		.type = type,
		.space = space,
		.node = NULL
	};
	rz_interval_tree_all_in(&analysis->meta, addr, true, find_node_cb, &ctx);
	return ctx.node;
}

typedef struct {
	RzAnalysisMetaType type;
	const RzSpace *space;

	RzPVector /*<RzIntervalNode *>*/ *result;
} CollectCtx;

static bool collect_nodes_cb(RzIntervalNode *node, void *user) {
	CollectCtx *ctx = user;
	if (item_matches_filter(node->data, ctx->type, ctx->space)) {
		rz_pvector_push(ctx->result, node);
	}
	return true;
}

static RzPVector /*<RzIntervalNode *>*/ *collect_nodes_at(RzAnalysis *analysis, RzAnalysisMetaType type, RZ_NULLABLE const RzSpace *space, ut64 addr) {
	CollectCtx ctx = {
		.type = type,
		.space = space,
		.result = rz_pvector_new(NULL)
	};
	if (!ctx.result) {
		return NULL;
	}
	rz_interval_tree_all_at(&analysis->meta, addr, collect_nodes_cb, &ctx);
	return ctx.result;
}

static RzPVector /*<RzIntervalNode *>*/ *collect_nodes_in(RzAnalysis *analysis, RzAnalysisMetaType type, RZ_NULLABLE const RzSpace *space, ut64 addr) {
	CollectCtx ctx = {
		.type = type,
		.space = space,
		.result = rz_pvector_new(NULL)
	};
	if (!ctx.result) {
		return NULL;
	}
	rz_interval_tree_all_in(&analysis->meta, addr, true, collect_nodes_cb, &ctx);
	return ctx.result;
}

static RzPVector /*<RzIntervalNode *>*/ *collect_nodes_intersect(RzAnalysis *analysis, RzAnalysisMetaType type, RZ_NULLABLE const RzSpace *space, ut64 start, ut64 end) {
	CollectCtx ctx = {
		.type = type,
		.space = space,
		.result = rz_pvector_new(NULL)
	};
	if (!ctx.result) {
		return NULL;
	}
	rz_interval_tree_all_intersect(&analysis->meta, start, end, true, collect_nodes_cb, &ctx);
	return ctx.result;
}

static inline bool is_string_with_zeroes(RzAnalysisMetaType type, int subtype) {
	return type == RZ_META_TYPE_STRING && subtype != RZ_STRING_ENC_8BIT && subtype != RZ_STRING_ENC_UTF8;
}

static bool meta_set(RzAnalysis *a, RzAnalysisMetaType type, int subtype, ut64 from, ut64 to, const char *str) {
	if (to < from) {
		return false;
	}
	RzSpace *space = rz_spaces_current(&a->meta_spaces);
	RzIntervalNode *node = find_node_at(a, type, space, from);
	RzAnalysisMetaItem *item = node ? node->data : RZ_NEW0(RzAnalysisMetaItem);
	if (!item) {
		return false;
	}
	item->type = type;
	item->subtype = subtype;
	item->space = space;
	item->size = to - from + 1;
	free(item->str);
	if (is_string_with_zeroes(type, subtype)) {
		item->str = rz_str_ndup(str, item->size);
	} else {
		item->str = rz_str_dup(str);
	}
	if (str && !item->str) {
		if (!node) { // If we just created this
			free(item);
		}
		return false;
	}
	if (!node) {
		rz_interval_tree_insert(&a->meta, from, to, item);
	} else if (node->end != to) {
		rz_interval_tree_resize(&a->meta, node, from, to);
	}
	return true;
}

RZ_API bool rz_meta_set_string(RzAnalysis *a, RzAnalysisMetaType type, ut64 addr, RZ_NULLABLE const char *s) {
	rz_return_val_if_fail(a, false);
	// By default all strings are UTF-8
	return meta_set(a, type, RZ_STRING_ENC_UTF8, addr, addr, s);
}

RZ_API const char *rz_meta_get_string(RzAnalysis *a, RzAnalysisMetaType type, ut64 addr) {
	RzIntervalNode *node = find_node_at(a, type, rz_spaces_current(&a->meta_spaces), addr);
	if (!node) {
		return NULL;
	}
	RzAnalysisMetaItem *item = node->data;
	return item->str;
}

static void del(RzAnalysis *a, RzAnalysisMetaType type, const RzSpace *space, ut64 addr, ut64 size) {
	RzPVector *victims = NULL;
	if (size == UT64_MAX) {
		// delete everything
		victims = rz_pvector_new(NULL);
		if (!victims) {
			return;
		}
		RzIntervalTreeIter it;
		RzAnalysisMetaItem *item;
		rz_interval_tree_foreach (&a->meta, it, item) {
			if (item_matches_filter(item, type, space)) {
				rz_pvector_push(victims, rz_interval_tree_iter_get(&it));
			}
		}
	} else {
		ut64 end = size ? addr + size - 1 : addr;
		if (end < addr) {
			end = UT64_MAX;
		}
		victims = collect_nodes_intersect(a, type, space, addr, end);
		if (!victims) {
			return;
		}
	}
	void **it;
	rz_pvector_foreach (victims, it) {
		rz_interval_tree_delete(&a->meta, *it, true);
	}
	rz_pvector_free(victims);
}

RZ_API void rz_meta_del(RzAnalysis *a, RzAnalysisMetaType type, ut64 addr, ut64 size) {
	del(a, type, rz_spaces_current(&a->meta_spaces), addr, size);
}

RZ_API bool rz_meta_set(RzAnalysis *a, RzAnalysisMetaType type, ut64 addr, ut64 size, const char *str) {
	int subtype = type == RZ_META_TYPE_STRING ? RZ_STRING_ENC_UTF8 : 0;
	return rz_meta_set_with_subtype(a, type, subtype, addr, size, str);
}

RZ_API bool rz_meta_set_with_subtype(RzAnalysis *m, RzAnalysisMetaType type, int subtype, ut64 addr, ut64 size, const char *str) {
	rz_return_val_if_fail(m, false);
	if (size < 1) {
		return false;
	}
	ut64 end = addr + size - 1;
	if (end < addr) {
		end = UT64_MAX;
	}
	return meta_set(m, type, subtype, addr, end, str);
}

RZ_API RzAnalysisMetaItem *rz_meta_get_at(RzAnalysis *a, ut64 addr, RzAnalysisMetaType type, RZ_OUT RZ_NULLABLE ut64 *size) {
	RzIntervalNode *node = find_node_at(a, type, rz_spaces_current(&a->meta_spaces), addr);
	if (node && size) {
		*size = rz_meta_item_size(node->start, node->end);
	}
	return node ? node->data : NULL;
}

RZ_API RzIntervalNode *rz_meta_get_in(RzAnalysis *a, ut64 addr, RzAnalysisMetaType type) {
	return find_node_in(a, type, rz_spaces_current(&a->meta_spaces), addr);
}

RZ_API RzPVector /*<RzIntervalNode<RMetaItem> *>*/ *rz_meta_get_all_at(RzAnalysis *a, ut64 at) {
	return collect_nodes_at(a, RZ_META_TYPE_ANY, rz_spaces_current(&a->meta_spaces), at);
}

RZ_API RzPVector /*<RzIntervalNode<RMetaItem> *>*/ *rz_meta_get_all_in(RzAnalysis *a, ut64 at, RzAnalysisMetaType type) {
	return collect_nodes_in(a, type, rz_spaces_current(&a->meta_spaces), at);
}

RZ_API RzPVector /*<RzIntervalNode<RMetaItem> *>*/ *rz_meta_get_all_intersect(RzAnalysis *a, ut64 start, ut64 size, RzAnalysisMetaType type) {
	rz_return_val_if_fail(size, NULL);
	ut64 end = start + size - 1;
	if (end < start) {
		end = UT64_MAX;
	}
	return collect_nodes_intersect(a, type, rz_spaces_current(&a->meta_spaces), start, end);
}

RZ_API const char *rz_meta_type_to_string(int type) {
	switch (type) {
	case RZ_META_TYPE_DATA: return "Cd";
	case RZ_META_TYPE_CODE: return "Cc";
	case RZ_META_TYPE_STRING: return "Cs";
	case RZ_META_TYPE_FORMAT: return "Cf";
	case RZ_META_TYPE_MAGIC: return "Cm";
	case RZ_META_TYPE_HIDE: return "Ch";
	case RZ_META_TYPE_COMMENT: return "CCu";
	case RZ_META_TYPE_HIGHLIGHT: return "ecHi"; // not in C?
	case RZ_META_TYPE_VARTYPE: return "Ct";
	}
	return "# unknown meta # ";
}

RZ_API void rz_meta_rebase(RzAnalysis *analysis, ut64 diff) {
	if (!diff) {
		return;
	}
	RzIntervalTree old = analysis->meta;
	rz_interval_tree_init(&analysis->meta, old.free);
	RzIntervalTreeIter it;
	RzAnalysisMetaItem *item;
	rz_interval_tree_foreach (&old, it, item) {
		RzIntervalNode *node = rz_interval_tree_iter_get(&it);
		ut64 newstart = node->start + diff;
		ut64 newend = node->end + diff;
		if (newend < newstart) {
			// Can't rebase this
			newstart = node->start;
			newend = node->end;
		}
		rz_interval_tree_insert(&analysis->meta, newstart, newend, item);
	}
	old.free = NULL;
	rz_interval_tree_fini(&old);
}

RZ_API void rz_meta_space_unset_for(RzAnalysis *a, const RzSpace *space) {
	del(a, RZ_META_TYPE_ANY, space, 0, UT64_MAX);
}

RZ_API ut64 rz_meta_get_size(RzAnalysis *a, RzAnalysisMetaType type) {
	ut64 sum = 0;
	RzIntervalTreeIter it;
	RzAnalysisMetaItem *item;
	RzIntervalNode *prev = NULL;
	rz_interval_tree_foreach (&a->meta, it, item) {
		RzIntervalNode *node = rz_interval_tree_iter_get(&it);
		if (type != RZ_META_TYPE_ANY && item->type != type) {
			continue;
		}
		ut64 start = RZ_MAX(prev ? prev->end : 0, node->start);
		sum += node->end - start + 1;
		prev = node;
	}
	return sum;
}

RZ_API int rz_meta_space_count_for(RzAnalysis *a, const RzSpace *space) {
	int r = 0;
	RzIntervalTreeIter it;
	RzAnalysisMetaItem *item;
	rz_interval_tree_foreach (&a->meta, it, item) {
		if (item->space == space) {
			r++;
		}
	}
	return r;
}

RZ_API void rz_meta_set_data_at(RzAnalysis *a, ut64 addr, ut64 wordsz) {
	rz_return_if_fail(wordsz);
	rz_meta_set(a, RZ_META_TYPE_DATA, addr, wordsz, NULL);
}
