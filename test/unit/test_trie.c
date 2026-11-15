// SPDX-FileCopyrightText: 2026 MrQuantum1915 <darshanpatelgdh@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_trie.h>
#include <rz_util/rz_bitvector.h>
#include "minunit.h"

static bool char_match(const RzTrieNode *n, const void *key, size_t idx) {
	rz_return_val_if_fail(n && n->data && key, false);
	const char *str = key;

	if (str[idx] == *(char *)(n->data)) {
		return true;
	}
	return false;
}

static void char_init(RzTrieNode *n, const void *key, size_t idx) {
	rz_return_if_fail(n && key);
	const char *str = key;
	n->data = RZ_NEW0(char);
	if (!n->data) {
		return;
	}
	*(char *)(n->data) = str[idx];
}

static void free_char_data(RzTrieNode *n) {
	rz_return_if_fail(n);
	RZ_FREE(n->data);
}

static void char_on_hit(RzTrieNode *n, RZ_UNUSED void *user) {
	rz_return_if_fail(n && n->data);
	char *c = n->data;
	*c = toupper(*c);
}

typedef struct {
	char *buf;
	size_t idx;
} dfsCtx;

static void pre_visit(RzTrieNode *n, void *user) {
	if (!n || !user) {
		return;
	}
	dfsCtx *ctx = user;
	if (n->data) {
		ctx->buf[ctx->idx++] = *(char *)(n->data);
	}
}

static void edge_visit(RzTrieNode *parent, RzTrieNode *child, void *user) {
	rz_return_if_fail(parent && child && child->data && user);
	dfsCtx *ctx = user;
	if (parent->data) {
		ctx->buf[ctx->idx++] = *(char *)(parent->data);
	}
	ctx->buf[ctx->idx++] = '>';
	if (child->data) {
		ctx->buf[ctx->idx++] = *(char *)(child->data);
	}
	ctx->buf[ctx->idx++] = ' ';
}

bool main_test_trie_string() {

	// new
	RzTrie *t = rz_trie_new(NULL, char_init, free_char_data);
	mu_assert_null(t, "NULL match callback should be rejected");
	t = rz_trie_new(char_match, NULL, free_char_data);
	mu_assert_null(t, "NULL init callback should be rejected");
	t = rz_trie_new(char_match, char_init, NULL);
	mu_assert_notnull(t, "NULL free callback should be allowed");
	rz_trie_free(t);
	t = rz_trie_new(char_match, char_init, free_char_data);
	mu_assert_notnull(t, "Failed to create new trie");

	// insert
	const char *key1 = "Virgo Supercluster";
	mu_assert_notnull(rz_trie_insert(t, key1, strlen(key1), NULL, NULL), "Failed to insert key into trie");

	// search
	RzTrieNode *n = rz_trie_find_prefix(t, key1, strlen(key1), false);
	mu_assert_notnull(n, "Failed to find full key in trie");
	n = rz_trie_find_prefix(t, "Virgo", strlen("Virgo"), false);
	mu_assert_null(n, "searching for partial key with partial_key=false should return NULL");
	n = rz_trie_find_prefix(t, "Virgo", strlen("Virgo"), true);
	mu_assert_notnull(n, "Failed to find partial key in trie");
	mu_assert_true(rz_trie_contains(t, key1, strlen(key1)), "contains key check failed");

	const char *key2 = "Virgo"; // prefix
	mu_assert_notnull(rz_trie_insert(t, key2, strlen(key2), NULL, NULL), "Failed to insert 2nd key into trie");
	mu_assert_true(rz_trie_contains(t, key2, strlen(key2)), "contains 2nd key check failed");

	const char *key3 = "Virgo has 200 trillion stars!"; // branch
	mu_assert_notnull(rz_trie_insert(t, key3, strlen(key3), NULL, NULL), "Failed to insert 3rd key into trie");
	mu_assert_true(rz_trie_contains(t, key3, strlen(key3)), "contains 3rd key check failed");

	mu_assert_eq(rz_trie_size(t), 3, "trie size should be 3");

	// longest prefix match
	size_t match_len = 0;
	n = rz_trie_longest_prefix_match(t, "Virgo S", strlen("Virgo S"), &match_len);
	mu_assert_notnull(n, "Failed to find longest prefix match");
	mu_assert_eq(match_len, strlen(key2), "Longest prefix match length should be equal to key2 length");
	n = rz_trie_longest_prefix_match(t, "Virg", strlen("Virg"), &match_len);
	mu_assert_null(n, "longest prefix match should return NULL for non complete key");

	// dfs
	const char *expected = "Virgo SuperclusterretsulcrepuShas 200 trillion stars!!srats noillirt 002 sah ogriV";
	char *actual = RZ_NEWS0(char, strlen(expected) + 1);
	dfsCtx ctx = { .buf = actual, .idx = 0 };
	rz_trie_dfs(t->root, pre_visit, NULL, pre_visit, &ctx); // same cb for pre/post
	actual[ctx.idx] = '\0';
	mu_assert_streq(actual, expected, "DFS traversal should produce same str as expected");

	rz_trie_dfs(t->root, pre_visit, NULL, NULL, NULL); // post_cb=null, user=null
	rz_trie_dfs(t->root, NULL, NULL, NULL, NULL); // no op

	RZ_FREE(actual);

	// delete
	mu_assert_false(rz_trie_delete(t, "TON 618", strlen("TON 618")), "delete should fail for non-existent key");
	mu_assert_false(rz_trie_delete(t, "Virgo S", strlen("Virgo S")), "delete should fail for non-complete key");
	mu_assert_true(rz_trie_delete(t, key1, strlen(key1)), "Failed to delete key1 from trie");
	mu_assert_false(rz_trie_contains(t, key1, strlen(key1)), "contains key1 check should fail after deletion");
	mu_assert_true(rz_trie_contains(t, key3, strlen(key3)), "deleting key1 should not delete other branch key (still have children)");
	mu_assert_true(rz_trie_delete(t, key3, strlen(key3)), "Failed to delete key3 from trie");
	mu_assert_false(rz_trie_contains(t, key3, strlen(key3)), "contains key3 check should fail after deletion");
	mu_assert_true(rz_trie_contains(t, key2, strlen(key2)), "deleting key1/key3 should not delete shorter complete key");

	// on_hit (note that other keys are deleted so inplace mod is fine)
	mu_assert_notnull(rz_trie_insert(t, key2, strlen(key2), char_on_hit, NULL), "Failed to insert key2 into trie");
	mu_assert_false(rz_trie_contains(t, key2, strlen(key2)), "contains key2 check should failed as key is modified");
	const char *key2_n = "VIRGO";
	mu_assert_true(rz_trie_contains(t, key2_n, strlen(key2_n)), "char_on_hit should be called and hence this check should pass");

	// manipulating root (also for trie_clear test)
	t->root->data = RZ_NEW0(char);
	mu_assert_notnull(t->root->data, "root data should be allocated");
	*(char *)t->root->data = 'a';
	t->root->is_end = true;

	// clear
	rz_trie_clear(t);
	mu_assert_false(rz_trie_contains(t, key2_n, strlen(key2_n)), "contains key2 check should fail after clear");
	mu_assert_eq(rz_trie_size(t), 0, "trie size should be 0 after clear");
	mu_assert_notnull(t->root, "trie root should not be freed by clear");
	mu_assert_null(t->root->data, "trie root data should be reset after clear, no matter whether it was manipulated or not");
	rz_trie_clear(NULL); // should not crash

	// reinsert
	mu_assert_notnull(rz_trie_insert(t, "ab", 2, NULL, NULL), "Reinsert should work after clear");
	mu_assert_notnull(rz_trie_insert(t, "ac", 2, NULL, NULL), "Reinsert should work after clear");

	// edge_cb
	const char *edges = ">a a>b a>c ";
	char *buf = RZ_NEWS0(char, strlen(edges) + 1);
	dfsCtx ectx = { .buf = buf, .idx = 0 };
	rz_trie_dfs(t->root, NULL, edge_visit, NULL, &ectx);
	buf[ectx.idx] = '\0';
	mu_assert_streq(buf, edges, "edge cb should record parent->child pairs in DFS order");
	RZ_FREE(buf);

	// free
	rz_trie_free(t);
	t = NULL;
	rz_trie_free(t); // handle null gracefully

	mu_end;
}

static bool bit_match(const RzTrieNode *n, const void *key, size_t idx) {
	rz_return_val_if_fail(n && n->data && key, false);
	const RzBitVector *bv = key;
	bool val = rz_bv_get(bv, idx);
	bool *d = n->data;
	return !(val ^ (*d));
}
static void bit_init(RzTrieNode *n, const void *key, size_t idx) {
	rz_return_if_fail(n && key);
	const RzBitVector *bv = key;
	bool *d = RZ_NEW0(bool);
	if (!d) {
		return;
	}
	*d = rz_bv_get(bv, idx);
	n->data = d;
}

static void bit_on_hit(RzTrieNode *n, void *user) {
	rz_return_if_fail(n && n->data);
	int *cnt = user;
	(*cnt)++;
}

static void free_bit_data(RzTrieNode *n) {
	rz_return_if_fail(n);
	RZ_FREE(n->data);
}

bool test_trie_bitvector() {
	// x86
	// 01010101 ; 0x55 ; push ebp
	RzBitVector *key1 = rz_bv_new(8);
	rz_bv_set(key1, 1, true);
	rz_bv_set(key1, 3, true);
	rz_bv_set(key1, 5, true);
	rz_bv_set(key1, 7, true);

	// 01011101 ; 0x5D ; pop ebp
	RzBitVector *key2 = rz_bv_new(8);
	rz_bv_set(key2, 1, true);
	rz_bv_set(key2, 3, true);
	rz_bv_set(key2, 4, true);
	rz_bv_set(key2, 5, true);
	rz_bv_set(key2, 7, true);

	// 11000011 ; 0xC3 ; ret
	RzBitVector *key3 = rz_bv_new(8);
	rz_bv_set(key3, 0, true);
	rz_bv_set(key3, 1, true);
	rz_bv_set(key3, 6, true);
	rz_bv_set(key3, 7, true);

	// insert
	RzTrie *t = rz_trie_new(bit_match, bit_init, free_bit_data);
	mu_assert_notnull(t, "Failed to create bitvector trie");
	mu_assert_notnull(rz_trie_insert(t, key1, 8, NULL, NULL), "Failed to insert key1");
	mu_assert_notnull(rz_trie_insert(t, key2, 8, NULL, NULL), "Failed to insert key2");
	mu_assert_notnull(rz_trie_insert(t, key3, 8, NULL, NULL), "Failed to insert key3");

	// search
	RzTrieNode *n = rz_trie_find_prefix(t, key1, 8, false);
	mu_assert_notnull(n, "key1 should be present in trie");
	mu_assert_true(*(bool *)(n->data), "last bit should be 1");
	mu_assert_true(rz_trie_contains(t, key1, 8), "contains key1 check failed");

	// common prefix 0x5 in key1/2
	RzBitVector *target = rz_bv_new(4);
	rz_bv_set(target, 1, true);
	rz_bv_set(target, 3, true);
	n = rz_trie_find_prefix(t, target, 4, false);
	mu_assert_null(n, "searching for partial key with partial_key=false should return NULL");
	n = rz_trie_find_prefix(t, target, 4, true);
	mu_assert_notnull(n, "searching for partial key failed");

	n = rz_trie_find_prefix(t, key2, 8, false);
	mu_assert_notnull(n, "key2 should be present in trie");
	n = rz_trie_find_prefix(t, key3, 8, false);
	mu_assert_notnull(n, "key3 should be present in trie");

	mu_assert_eq(rz_trie_size(t), 3, "trie size should be 3");

	// longest prefix match
	size_t match_len = 0;
	n = rz_trie_longest_prefix_match(t, key1, 8, &match_len);
	mu_assert_notnull(n, "longest prefix match should find key1 itself");
	mu_assert_eq(match_len, 8, "longest prefix match length should be 8 for exact key");
	n = rz_trie_longest_prefix_match(t, target, 4, &match_len);
	mu_assert_null(n, "longest prefix match should return NULL for non-complete prefix");
	mu_assert_notnull(rz_trie_insert(t, target, 4, NULL, NULL), "Failed to insert target");
	n = rz_trie_longest_prefix_match(t, target, 4, &match_len);
	mu_assert_notnull(n, "longest prefix match should find target after insertion (now complete key)");

	// on_hit: re-inserting key3 should fire on_hit for each existing node along the path
	// key3 has 8 bits so on_hit fires 8 times (once per depth level)
	int cnt = 0;
	mu_assert_notnull(rz_trie_insert(t, key3, 8, bit_on_hit, &cnt), "Failed to re-insert key3 with on_hit");
	mu_assert_eq(cnt, 8, "on_hit should fire once per existing node along key3's path");

	// delete
	mu_assert_true(rz_trie_delete(t, target, 4), "delete should remove key");
	mu_assert_true(rz_trie_contains(t, key1, 8), "target being full prefix should not delete key1");
	mu_assert_false(rz_trie_delete(t, target, 4), "delete should fail for non-complete key");
	mu_assert_true(rz_trie_delete(t, key1, 8), "delete for existing key should pass");
	mu_assert_false(rz_trie_contains(t, key1, 8), "key1 should not exist after deletion");

	rz_bv_free(key1);
	rz_bv_free(key2);
	rz_bv_free(key3);
	rz_bv_free(target);
	rz_trie_free(t);

	mu_end;
}

bool all_tests() {
	mu_run_test(main_test_trie_string);
	mu_run_test(test_trie_bitvector);
	return tests_passed != tests_run;
}

mu_main(all_tests)
