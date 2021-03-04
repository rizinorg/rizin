// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

#include "minunit.h"

bool test_meta_set() {
	RzAnalysis *analysis = rz_analysis_new();

	rz_meta_set(analysis, RZ_META_TYPE_DATA, 0x100, 4, NULL);
	rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, 0x100, "summer of love");
	rz_meta_set_with_subtype(analysis, RZ_META_TYPE_STRING, RZ_STRING_ENC_UTF8, 0x200, 0x30, "true confessions");

	bool found[3] = { 0 };
	size_t count = 0;
	RzIntervalTreeIter it;
	RzAnalysisMetaItem *item;
	rz_interval_tree_foreach (&analysis->meta, it, item) {
		count++;
		RzIntervalNode *node = rz_interval_tree_iter_get(&it);
		switch (item->type) {
		case RZ_META_TYPE_DATA:
			mu_assert_eq(node->start, 0x100, "node start");
			mu_assert_eq(node->end, 0x103, "node end (inclusive)");
			mu_assert_null(item->str, "no string");
			mu_assert_eq(item->subtype, 0, "no subtype");
			found[0] = true;
			break;
		case RZ_META_TYPE_COMMENT:
			mu_assert_eq(node->start, 0x100, "node start");
			mu_assert_eq(node->end, 0x100, "node end (inclusive)");
			mu_assert_streq(item->str, "summer of love", "comment string");
			mu_assert_eq(item->subtype, 0, "no subtype");
			found[1] = true;
			break;
		case RZ_META_TYPE_STRING:
			mu_assert_eq(node->start, 0x200, "node start");
			mu_assert_eq(node->end, 0x22f, "node end (inclusive)");
			mu_assert_streq(item->str, "true confessions", "string string");
			mu_assert_eq(item->subtype, RZ_STRING_ENC_UTF8, "subtype");
			found[2] = true;
			break;
		default:
			break;
		}
	}
	mu_assert_eq(count, 3, "set count");
	mu_assert("meta 0", found[0]);
	mu_assert("meta 1", found[1]);
	mu_assert("meta 2", found[2]);

	// Override an item, changing only its size
	rz_meta_set(analysis, RZ_META_TYPE_DATA, 0x100, 8, NULL);

	count = 0;
	found[0] = found[1] = found[2] = false;
	rz_interval_tree_foreach (&analysis->meta, it, item) {
		count++;
		RzIntervalNode *node = rz_interval_tree_iter_get(&it);
		switch (item->type) {
		case RZ_META_TYPE_DATA:
			mu_assert_eq(node->start, 0x100, "node start");
			mu_assert_eq(node->end, 0x107, "node end (inclusive)");
			mu_assert_null(item->str, "no string");
			mu_assert_eq(item->subtype, 0, "no subtype");
			found[0] = true;
			break;
		case RZ_META_TYPE_COMMENT:
			mu_assert_eq(node->start, 0x100, "node start");
			mu_assert_eq(node->end, 0x100, "node end (inclusive)");
			mu_assert_streq(item->str, "summer of love", "comment string");
			mu_assert_eq(item->subtype, 0, "no subtype");
			found[1] = true;
			break;
		case RZ_META_TYPE_STRING:
			mu_assert_eq(node->start, 0x200, "node start");
			mu_assert_eq(node->end, 0x22f, "node end (inclusive)");
			mu_assert_streq(item->str, "true confessions", "string string");
			mu_assert_eq(item->subtype, RZ_STRING_ENC_UTF8, "subtype");
			found[2] = true;
			break;
		default:
			break;
		}
	}
	mu_assert_eq(count, 3, "set count");
	mu_assert("meta 0", found[0]);
	mu_assert("meta 1", found[1]);
	mu_assert("meta 2", found[2]);

	// Override items, changing their contents
	rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, 0x100, "this ain't the summer of love");
	rz_meta_set_with_subtype(analysis, RZ_META_TYPE_STRING, RZ_STRING_ENC_UTF16LE, 0x200, 0x40, "e.t.i. (extra terrestrial intelligence)");

	count = 0;
	found[0] = found[1] = found[2] = false;
	rz_interval_tree_foreach (&analysis->meta, it, item) {
		count++;
		RzIntervalNode *node = rz_interval_tree_iter_get(&it);
		switch (item->type) {
		case RZ_META_TYPE_DATA:
			mu_assert_eq(node->start, 0x100, "node start");
			mu_assert_eq(node->end, 0x107, "node end (inclusive)");
			mu_assert_null(item->str, "no string");
			mu_assert_eq(item->subtype, 0, "no subtype");
			found[0] = true;
			break;
		case RZ_META_TYPE_COMMENT:
			mu_assert_eq(node->start, 0x100, "node start");
			mu_assert_eq(node->end, 0x100, "node end (inclusive)");
			mu_assert_streq(item->str, "this ain't the summer of love", "comment string");
			mu_assert_eq(item->subtype, 0, "no subtype");
			found[1] = true;
			break;
		case RZ_META_TYPE_STRING:
			mu_assert_eq(node->start, 0x200, "node start");
			mu_assert_eq(node->end, 0x23f, "node end (inclusive)");
			mu_assert_streq(item->str, "e.t.i. (extra terrestrial intelligence)", "string string");
			mu_assert_eq(item->subtype, RZ_STRING_ENC_UTF16LE, "subtype");
			found[2] = true;
			break;
		default:
			break;
		}
	}
	mu_assert_eq(count, 3, "set count");
	mu_assert("meta 0", found[0]);
	mu_assert("meta 1", found[1]);
	mu_assert("meta 2", found[2]);

	rz_analysis_free(analysis);
	mu_end;
}

bool test_meta_get_at() {
	RzAnalysis *analysis = rz_analysis_new();

	rz_meta_set(analysis, RZ_META_TYPE_DATA, 0x100, 4, NULL);
	rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, 0x100, "vera gemini");
	rz_meta_set_with_subtype(analysis, RZ_META_TYPE_STRING, RZ_STRING_ENC_UTF8, 0x200, 0x30, "true confessions");

	RzAnalysisMetaItem *item = rz_meta_get_at(analysis, 0x100, RZ_META_TYPE_COMMENT, NULL);
	mu_assert_notnull(item, "get item");
	mu_assert_streq(item->str, "vera gemini", "get contents");

	ut64 size;
	item = rz_meta_get_at(analysis, 0x100, RZ_META_TYPE_DATA, &size);
	mu_assert_notnull(item, "get item");
	mu_assert_eq(item->type, RZ_META_TYPE_DATA, "get contents");
	mu_assert_eq(size, 4, "get size");

	item = rz_meta_get_at(analysis, 0x200, RZ_META_TYPE_ANY, NULL);
	mu_assert_notnull(item, "get item");
	mu_assert_streq(item->str, "true confessions", "get contents");

	item = rz_meta_get_at(analysis, 0x100, RZ_META_TYPE_ANY, NULL);
	mu_assert_notnull(item, "get item");
	// which one we get is undefined here (intended)

	item = rz_meta_get_at(analysis, 0x1ff, RZ_META_TYPE_ANY, NULL);
	mu_assert_null(item, "get item");
	item = rz_meta_get_at(analysis, 0x201, RZ_META_TYPE_ANY, NULL);
	mu_assert_null(item, "get item");
	item = rz_meta_get_at(analysis, 0xff, RZ_META_TYPE_ANY, NULL);
	mu_assert_null(item, "get item");
	item = rz_meta_get_at(analysis, 0x101, RZ_META_TYPE_ANY, NULL);
	mu_assert_null(item, "get item");

	rz_analysis_free(analysis);
	mu_end;
}

bool test_meta_get_in() {
	RzAnalysis *analysis = rz_analysis_new();

	rz_meta_set(analysis, RZ_META_TYPE_DATA, 0x100, 4, NULL);
	rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, 0x100, "vera gemini");

	RzIntervalNode *node = rz_meta_get_in(analysis, 0x100, RZ_META_TYPE_COMMENT);
	mu_assert_notnull(node, "get item");
	RzAnalysisMetaItem *item = node->data;
	mu_assert_streq(item->str, "vera gemini", "get contents");
	node = rz_meta_get_in(analysis, 0xff, RZ_META_TYPE_COMMENT);
	mu_assert_null(node, "get item");
	node = rz_meta_get_in(analysis, 0x101, RZ_META_TYPE_COMMENT);
	mu_assert_null(node, "get item");

	node = rz_meta_get_in(analysis, 0x100, RZ_META_TYPE_DATA);
	mu_assert_notnull(node, "get item");
	item = node->data;
	mu_assert_eq(item->type, RZ_META_TYPE_DATA, "get contents");
	node = rz_meta_get_in(analysis, 0xff, RZ_META_TYPE_DATA);
	mu_assert_null(node, "get item");
	node = rz_meta_get_in(analysis, 0x103, RZ_META_TYPE_DATA);
	mu_assert_notnull(node, "get item");
	item = node->data;
	mu_assert_eq(item->type, RZ_META_TYPE_DATA, "get contents");
	node = rz_meta_get_in(analysis, 0x104, RZ_META_TYPE_DATA);
	mu_assert_null(node, "get item");

	node = rz_meta_get_in(analysis, 0x103, RZ_META_TYPE_ANY);
	mu_assert_notnull(node, "get item");
	item = node->data;
	mu_assert_eq(item->type, RZ_META_TYPE_DATA, "get contents");

	node = rz_meta_get_in(analysis, 0x100, RZ_META_TYPE_ANY);
	mu_assert_notnull(node, "get item");
	// which one we get is undefined here (intended)

	rz_analysis_free(analysis);
	mu_end;
}

bool test_meta_get_all_at() {
	RzAnalysis *analysis = rz_analysis_new();

	rz_meta_set(analysis, RZ_META_TYPE_DATA, 0x100, 4, NULL);
	rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, 0x100, "vera gemini");
	rz_meta_set_with_subtype(analysis, RZ_META_TYPE_STRING, RZ_STRING_ENC_UTF8, 0x200, 0x30, "true confessions");

	RzPVector *items = rz_meta_get_all_at(analysis, 0x100);
	mu_assert_eq(rz_pvector_len(items), 2, "all count");
	void **it;
	bool found[2] = { 0 };
	rz_pvector_foreach (items, it) {
		RzAnalysisMetaItem *item = ((RzIntervalNode *)*it)->data;
		switch (item->type) {
		case RZ_META_TYPE_DATA:
			found[0] = true;
			break;
		case RZ_META_TYPE_COMMENT:
			found[1] = true;
			break;
		default:
			break;
		}
	}
	mu_assert("meta 0", found[0]);
	mu_assert("meta 1", found[1]);
	rz_pvector_free(items);

	items = rz_meta_get_all_at(analysis, 0xff);
	mu_assert_eq(rz_pvector_len(items), 0, "all count");
	rz_pvector_free(items);

	items = rz_meta_get_all_at(analysis, 0x101);
	mu_assert_eq(rz_pvector_len(items), 0, "all count");
	rz_pvector_free(items);

	rz_analysis_free(analysis);
	mu_end;
}

bool test_meta_get_all_in() {
	RzAnalysis *analysis = rz_analysis_new();

	rz_meta_set(analysis, RZ_META_TYPE_DATA, 0x100, 4, NULL);
	rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, 0x100, "vera gemini");
	rz_meta_set_with_subtype(analysis, RZ_META_TYPE_STRING, RZ_STRING_ENC_UTF8, 0x200, 0x30, "true confessions");

	RzPVector *items = rz_meta_get_all_in(analysis, 0x100, RZ_META_TYPE_ANY);
	mu_assert_eq(rz_pvector_len(items), 2, "all count");
	void **it;
	bool found[2] = { 0 };
	rz_pvector_foreach (items, it) {
		RzAnalysisMetaItem *item = ((RzIntervalNode *)*it)->data;
		switch (item->type) {
		case RZ_META_TYPE_DATA:
			found[0] = true;
			break;
		case RZ_META_TYPE_COMMENT:
			found[1] = true;
			break;
		default:
			break;
		}
	}
	mu_assert("meta 0", found[0]);
	mu_assert("meta 1", found[1]);
	rz_pvector_free(items);

	items = rz_meta_get_all_in(analysis, 0x100, RZ_META_TYPE_COMMENT);
	mu_assert_eq(rz_pvector_len(items), 1, "all count");
	RzAnalysisMetaItem *item = ((RzIntervalNode *)rz_pvector_at(items, 0))->data;
	mu_assert_streq(item->str, "vera gemini", "contents");
	rz_pvector_free(items);

	items = rz_meta_get_all_in(analysis, 0x100, RZ_META_TYPE_DATA);
	mu_assert_eq(rz_pvector_len(items), 1, "all count");
	item = ((RzIntervalNode *)rz_pvector_at(items, 0))->data;
	mu_assert_eq(item->type, RZ_META_TYPE_DATA, "contents");
	rz_pvector_free(items);

	items = rz_meta_get_all_in(analysis, 0xff, RZ_META_TYPE_ANY);
	mu_assert_eq(rz_pvector_len(items), 0, "all count");
	rz_pvector_free(items);

	items = rz_meta_get_all_in(analysis, 0x101, RZ_META_TYPE_COMMENT);
	mu_assert_eq(rz_pvector_len(items), 0, "all count");
	rz_pvector_free(items);

	items = rz_meta_get_all_in(analysis, 0x103, RZ_META_TYPE_DATA);
	mu_assert_eq(rz_pvector_len(items), 1, "all count");
	item = ((RzIntervalNode *)rz_pvector_at(items, 0))->data;
	mu_assert_eq(item->type, RZ_META_TYPE_DATA, "contents");
	rz_pvector_free(items);

	items = rz_meta_get_all_in(analysis, 0x104, RZ_META_TYPE_DATA);
	mu_assert_eq(rz_pvector_len(items), 0, "all count");
	rz_pvector_free(items);

	rz_analysis_free(analysis);
	mu_end;
}

bool test_meta_get_all_intersect() {
	RzAnalysis *analysis = rz_analysis_new();

	rz_meta_set(analysis, RZ_META_TYPE_DATA, 0x100, 4, NULL);
	rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, 0x100, "vera gemini");
	rz_meta_set_with_subtype(analysis, RZ_META_TYPE_STRING, RZ_STRING_ENC_UTF8, 0x200, 0x30, "true confessions");

	RzPVector *items = rz_meta_get_all_intersect(analysis, 0x100, 1, RZ_META_TYPE_ANY);
	mu_assert_eq(rz_pvector_len(items), 2, "all count");
	void **it;
	bool found[2] = { 0 };
	rz_pvector_foreach (items, it) {
		RzAnalysisMetaItem *item = ((RzIntervalNode *)*it)->data;
		switch (item->type) {
		case RZ_META_TYPE_DATA:
			found[0] = true;
			break;
		case RZ_META_TYPE_COMMENT:
			found[1] = true;
			break;
		default:
			break;
		}
	}
	mu_assert("meta 0", found[0]);
	mu_assert("meta 1", found[1]);
	rz_pvector_free(items);

	items = rz_meta_get_all_intersect(analysis, 0x100, 1, RZ_META_TYPE_DATA);
	mu_assert_eq(rz_pvector_len(items), 1, "all count");
	RzAnalysisMetaItem *item = ((RzIntervalNode *)rz_pvector_at(items, 0))->data;
	mu_assert_eq(item->type, RZ_META_TYPE_DATA, "contents");
	rz_pvector_free(items);

	items = rz_meta_get_all_intersect(analysis, 0x100, 0x300, RZ_META_TYPE_DATA);
	mu_assert_eq(rz_pvector_len(items), 1, "all count");
	item = ((RzIntervalNode *)rz_pvector_at(items, 0))->data;
	mu_assert_eq(item->type, RZ_META_TYPE_DATA, "contents");
	rz_pvector_free(items);

	items = rz_meta_get_all_intersect(analysis, 0x0, 0x300, RZ_META_TYPE_DATA);
	mu_assert_eq(rz_pvector_len(items), 1, "all count");
	item = ((RzIntervalNode *)rz_pvector_at(items, 0))->data;
	mu_assert_eq(item->type, RZ_META_TYPE_DATA, "contents");
	rz_pvector_free(items);

	items = rz_meta_get_all_intersect(analysis, 0x0, 0x100, RZ_META_TYPE_DATA);
	mu_assert_eq(rz_pvector_len(items), 0, "all count");
	rz_pvector_free(items);

	items = rz_meta_get_all_intersect(analysis, 0x103, 0x300, RZ_META_TYPE_DATA);
	mu_assert_eq(rz_pvector_len(items), 1, "all count");
	item = ((RzIntervalNode *)rz_pvector_at(items, 0))->data;
	mu_assert_eq(item->type, RZ_META_TYPE_DATA, "contents");
	rz_pvector_free(items);

	items = rz_meta_get_all_intersect(analysis, 0x104, 0x300, RZ_META_TYPE_DATA);
	mu_assert_eq(rz_pvector_len(items), 0, "all count");
	rz_pvector_free(items);

	rz_analysis_free(analysis);
	mu_end;
}

bool test_meta_del() {
	RzAnalysis *analysis = rz_analysis_new();

	rz_meta_set(analysis, RZ_META_TYPE_DATA, 0x100, 4, NULL);
	rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, 0x100, "vera gemini");
	rz_meta_set_with_subtype(analysis, RZ_META_TYPE_STRING, RZ_STRING_ENC_UTF8, 0x200, 0x30, "true confessions");

	rz_meta_del(analysis, RZ_META_TYPE_COMMENT, 0x100, 1);
	RzAnalysisMetaItem *item = rz_meta_get_at(analysis, 0x100, RZ_META_TYPE_COMMENT, NULL);
	mu_assert_null(item, "item deleted");
	item = rz_meta_get_at(analysis, 0x100, RZ_META_TYPE_DATA, NULL);
	mu_assert_notnull(item, "item not deleted");
	item = rz_meta_get_at(analysis, 0x200, RZ_META_TYPE_STRING, NULL);
	mu_assert_notnull(item, "item not deleted");

	// reset
	rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, 0x100, "vera gemini");

	rz_meta_del(analysis, RZ_META_TYPE_COMMENT, 0x0, 0x500);
	item = rz_meta_get_at(analysis, 0x100, RZ_META_TYPE_COMMENT, NULL);
	mu_assert_null(item, "item deleted");
	item = rz_meta_get_at(analysis, 0x100, RZ_META_TYPE_DATA, NULL);
	mu_assert_notnull(item, "item not deleted");
	item = rz_meta_get_at(analysis, 0x200, RZ_META_TYPE_STRING, NULL);
	mu_assert_notnull(item, "item not deleted");

	// reset
	rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, 0x100, "vera gemini");

	rz_meta_del(analysis, RZ_META_TYPE_COMMENT, 0, UT64_MAX);
	item = rz_meta_get_at(analysis, 0x100, RZ_META_TYPE_COMMENT, NULL);
	mu_assert_null(item, "item deleted");
	item = rz_meta_get_at(analysis, 0x100, RZ_META_TYPE_DATA, NULL);
	mu_assert_notnull(item, "item not deleted");
	item = rz_meta_get_at(analysis, 0x200, RZ_META_TYPE_STRING, NULL);
	mu_assert_notnull(item, "item not deleted");

	// reset
	rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, 0x100, "vera gemini");

	rz_meta_del(analysis, RZ_META_TYPE_ANY, 0, 0x500);
	item = rz_meta_get_at(analysis, 0x100, RZ_META_TYPE_COMMENT, NULL);
	mu_assert_null(item, "item deleted");
	item = rz_meta_get_at(analysis, 0x100, RZ_META_TYPE_DATA, NULL);
	mu_assert_null(item, "item deleted");
	item = rz_meta_get_at(analysis, 0x200, RZ_META_TYPE_STRING, NULL);
	mu_assert_null(item, "item deleted");

	// reset
	rz_meta_set(analysis, RZ_META_TYPE_DATA, 0x100, 4, NULL);
	rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, 0x100, "vera gemini");
	rz_meta_set_with_subtype(analysis, RZ_META_TYPE_STRING, RZ_STRING_ENC_UTF8, 0x200, 0x30, "true confessions");

	rz_meta_del(analysis, RZ_META_TYPE_ANY, 0, UT64_MAX);
	item = rz_meta_get_at(analysis, 0x100, RZ_META_TYPE_COMMENT, NULL);
	mu_assert_null(item, "item deleted");
	item = rz_meta_get_at(analysis, 0x100, RZ_META_TYPE_DATA, NULL);
	mu_assert_null(item, "item deleted");
	item = rz_meta_get_at(analysis, 0x200, RZ_META_TYPE_STRING, NULL);
	mu_assert_null(item, "item deleted");

	rz_analysis_free(analysis);
	mu_end;
}

bool test_meta_rebase() {
	RzAnalysis *analysis = rz_analysis_new();

	rz_meta_set(analysis, RZ_META_TYPE_DATA, 0x200, 4, NULL);
	rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, 0x200, "summer of love");
	rz_meta_set_with_subtype(analysis, RZ_META_TYPE_STRING, RZ_STRING_ENC_UTF8, 0x300, 0x30, "true confessions");
	rz_meta_rebase(analysis, -0x100);

	bool found[3] = { 0 };
	size_t count = 0;
	RzIntervalTreeIter it;
	RzAnalysisMetaItem *item;
	rz_interval_tree_foreach (&analysis->meta, it, item) {
		count++;
		RzIntervalNode *node = rz_interval_tree_iter_get(&it);
		switch (item->type) {
		case RZ_META_TYPE_DATA:
			mu_assert_eq(node->start, 0x100, "node start");
			mu_assert_eq(node->end, 0x103, "node end (inclusive)");
			mu_assert_null(item->str, "no string");
			mu_assert_eq(item->subtype, 0, "no subtype");
			found[0] = true;
			break;
		case RZ_META_TYPE_COMMENT:
			mu_assert_eq(node->start, 0x100, "node start");
			mu_assert_eq(node->end, 0x100, "node end (inclusive)");
			mu_assert_streq(item->str, "summer of love", "comment string");
			mu_assert_eq(item->subtype, 0, "no subtype");
			found[1] = true;
			break;
		case RZ_META_TYPE_STRING:
			mu_assert_eq(node->start, 0x200, "node start");
			mu_assert_eq(node->end, 0x22f, "node end (inclusive)");
			mu_assert_streq(item->str, "true confessions", "string string");
			mu_assert_eq(item->subtype, RZ_STRING_ENC_UTF8, "subtype");
			found[2] = true;
			break;
		default:
			break;
		}
	}
	mu_assert_eq(count, 3, "set count");
	mu_assert("meta 0", found[0]);
	mu_assert("meta 1", found[1]);
	mu_assert("meta 2", found[2]);

	rz_analysis_free(analysis);
	mu_end;
}

bool test_meta_spaces() {
	RzAnalysis *analysis = rz_analysis_new();

	rz_meta_set(analysis, RZ_META_TYPE_DATA, 0x100, 4, NULL);
	rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, 0x100, "summer of love");
	rz_meta_set_with_subtype(analysis, RZ_META_TYPE_STRING, RZ_STRING_ENC_UTF8, 0x200, 0x30, "true confessions");

	rz_spaces_set(&analysis->meta_spaces, "fear");

	rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, 0x100, "reaper");

	bool found[4] = { 0 };
	size_t count = 0;
	RzIntervalTreeIter it;
	RzAnalysisMetaItem *item;
	rz_interval_tree_foreach (&analysis->meta, it, item) {
		count++;
		switch (item->type) {
		case RZ_META_TYPE_DATA:
			mu_assert_null(item->space, "space");
			found[0] = true;
			break;
		case RZ_META_TYPE_COMMENT:
			if (item->space) {
				mu_assert_streq(item->str, "reaper", "comment string");
				mu_assert_ptreq(item->space, rz_spaces_get(&analysis->meta_spaces, "fear"), "space");
				found[3] = true;
			} else {
				mu_assert_streq(item->str, "summer of love", "comment string");
				found[1] = true;
			}
			break;
		case RZ_META_TYPE_STRING:
			mu_assert_null(item->space, "space");
			found[2] = true;
			break;
		default:
			break;
		}
	}
	mu_assert_eq(count, 4, "set count");
	mu_assert("meta 0", found[0]);
	mu_assert("meta 1", found[1]);
	mu_assert("meta 2", found[2]);
	mu_assert("meta 3", found[3]);

	RzAnalysisMetaItem *reaper_item = rz_meta_get_at(analysis, 0x100, RZ_META_TYPE_ANY, NULL);
	mu_assert_notnull(reaper_item, "get item");
	mu_assert_streq(reaper_item->str, "reaper", "comment string");

	item = rz_meta_get_at(analysis, 0x100, RZ_META_TYPE_DATA, NULL);
	mu_assert_null(item, "masked by space");

	RzIntervalNode *node = rz_meta_get_in(analysis, 0x100, RZ_META_TYPE_COMMENT);
	mu_assert_notnull(node, "get item");
	mu_assert_ptreq(node->data, reaper_item, "masked by space");
	node = rz_meta_get_in(analysis, 0x100, RZ_META_TYPE_DATA);
	mu_assert_null(node, "masked by space");

	RzPVector *nodes = rz_meta_get_all_at(analysis, 0x100);
	mu_assert_eq(rz_pvector_len(nodes), 1, "all count");
	mu_assert_ptreq(((RzIntervalNode *)rz_pvector_at(nodes, 0))->data, reaper_item, "all masked");
	rz_pvector_free(nodes);

	nodes = rz_meta_get_all_in(analysis, 0x100, RZ_META_TYPE_ANY);
	mu_assert_eq(rz_pvector_len(nodes), 1, "all count");
	mu_assert_ptreq(((RzIntervalNode *)rz_pvector_at(nodes, 0))->data, reaper_item, "all masked");
	rz_pvector_free(nodes);

	nodes = rz_meta_get_all_intersect(analysis, 0x0, 0x500, RZ_META_TYPE_ANY);
	mu_assert_eq(rz_pvector_len(nodes), 1, "all count");
	mu_assert_ptreq(((RzIntervalNode *)rz_pvector_at(nodes, 0))->data, reaper_item, "all masked");
	rz_pvector_free(nodes);

	// delete
	rz_meta_del(analysis, RZ_META_TYPE_ANY, 0, 0x500);
	item = rz_meta_get_at(analysis, 0x100, RZ_META_TYPE_ANY, NULL);
	mu_assert_null(item, "reaper deleted");
	count = 0;
	rz_interval_tree_foreach (&analysis->meta, it, item) {
		count++;
	}
	mu_assert_eq(count, 3, "masked untouched");

	// reset
	rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, 0x100, "reaper");

	rz_meta_del(analysis, RZ_META_TYPE_ANY, 0, UT64_MAX);
	item = rz_meta_get_at(analysis, 0x100, RZ_META_TYPE_ANY, NULL);
	mu_assert_null(item, "reaper deleted");
	count = 0;
	rz_interval_tree_foreach (&analysis->meta, it, item) {
		count++;
	}
	mu_assert_eq(count, 3, "masked untouched");

	rz_analysis_free(analysis);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_meta_set);
	mu_run_test(test_meta_get_at);
	mu_run_test(test_meta_get_in);
	mu_run_test(test_meta_get_all_at);
	mu_run_test(test_meta_get_all_in);
	mu_run_test(test_meta_get_all_intersect);
	mu_run_test(test_meta_del);
	mu_run_test(test_meta_rebase);
	mu_run_test(test_meta_spaces);
	return tests_passed != tests_run;
}

mu_main(all_tests)