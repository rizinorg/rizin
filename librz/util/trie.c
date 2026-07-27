// SPDX-FileCopyrightText: 2026 MrQuantum1915 <darshanpatelgdh@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_trie.h>

static RzTrieNode *trie_find_child(const RzTrie *t, const RzTrieNode *parent,
	const void *key, size_t idx) {
	void **it;
	rz_pvector_foreach (&parent->children, it) {
		RzTrieNode *child = *it;
		if (t->match(child, key, idx)) {
			return child;
		}
	}
	return NULL;
}

/**
 * \brief Inserts the \p key in the prefix tree.
 *
 * Calls \p on_hit if an existing node matches the key at the current traversal depth.
 * Otherwise inserts new node and calls `trie->init`
 *
 * \param[in,out] t 	 Trie in which key is to be inserted.
 * \param[in]	  key 	 Pointer to user-defined key structure.
 * \param[in]	  len 	 The total length (number of elements) of the key. Must be > 0.
 * \param[in] 	  on_hit [optional] Callback to be called when a existing node
 * 						 matches the key at the current traversal depth.
 * \param[in] 	  user   [optional] Arbitrary context pointer forwarded to \p on_hit.
 *
 * \return Pointer to the terminal node of the key if inserted successfully, else `NULL`.
 *
 * \note Caller MUST ensure \p key structure contains at least \p len elements.
 * \warning Modifying node data in-place using \p on_hit can corrupt the trie if
 *          the match callback depends on the mutated fields. Only do so if you
 * 			fully undersand the implications.
 */
RZ_API RZ_BORROW RzTrieNode *rz_trie_insert(RZ_NONNULL RZ_BORROW RzTrie *t, RZ_NONNULL const void *key,
	size_t len, RZ_NULLABLE RzTrieNodeOnHitCb on_hit, RZ_NULLABLE void *user) {
	rz_return_val_if_fail(t && t->root && key && len > 0, NULL);

	RzTrieNode *curr_node = t->root;

	for (size_t idx = 0; idx < len; idx++) {

		RzTrieNode *child = trie_find_child(t, curr_node, key, idx);
		if (child) {
			if (on_hit)
				on_hit(child, user);
			curr_node = child;
		} else {
			// target child not found, create new node and insert
			RzTrieNode *new_node = RZ_NEW0(RzTrieNode);
			if (!new_node) {
				RZ_LOG_ERROR("calloc failed for new trie node\n");
				return NULL;
			}
			rz_pvector_init(&new_node->children, NULL);

			t->init(new_node, key, idx);
			rz_pvector_push(&curr_node->children, new_node);
			curr_node = new_node;
		}
	}

	curr_node->is_end = true;

	return curr_node;
}

/**
 * \brief Allocates and initialises a new `RzTrie` and root node.
 *
 * \note Root node's data field is initialised to `NULL`.
 *
 * \param[in] match Callback used to match a node against the key at a specific traversal depth.
 * \param[in] init  Callback used to initialise a newly created node's data during insertion.
 * \param[in] free  [optional] Callback used to release a node's custom data when the node is deleted.
 * \return Newly allocated `RzTrie` on success, or `NULL` on failure.
 */
RZ_API RZ_OWN RzTrie *rz_trie_new(RZ_NONNULL RzTrieNodeMatchCb match,
	RZ_NONNULL RzTrieNodeInitCb init, RZ_NULLABLE RzTrieNodeFreeCb free) {
	if (!match || !init) {
		RZ_LOG_ERROR("match and init callbacks must not be NULL\n");
		return NULL;
	}

	RzTrie *trie = RZ_NEW0(RzTrie);
	if (!trie) {
		return NULL;
	}
	trie->root = RZ_NEW0(RzTrieNode);
	if (!trie->root) {
		RZ_FREE(trie);
		return NULL;
	}

	rz_pvector_init(&trie->root->children, NULL);

	trie->match = match;
	trie->init = init;
	trie->free = free;

	return trie;
}

static void trie_node_free(RzTrieNode *n, void *user) {
	if (!n) {
		return;
	}
	if (user) {
		RzTrieNodeFreeCb free_cb = (RzTrieNodeFreeCb)user;
		free_cb(n);
	}
	rz_pvector_fini(&n->children);
	RZ_FREE(n);
}

/**
 * \brief Performs a pre-order and/or post-order depth-first traversal of the
 *        subtree rooted at \p n.
 *
 * At each node, \p cb_pre is called before descending into children,
 * and \p cb_post is called after all children have been visited.
 *
 * \note relies on system call stack not stack on heap.
 *
 * \param[in] n       Root of the subtree to traverse.
 * \param[in] cb_pre  Pre-order callback, `NULL` to skip.
 * \param[in] cb_edge Edge visit callback, `NULL` to skip.
 * \param[in] cb_post Post-order callback, `NULL` to skip.
 * \param[in] user    Arbitrary context pointer forwarded to both callbacks.
 */
RZ_API void rz_trie_dfs(RZ_NONNULL RzTrieNode *n, RZ_NULLABLE RzTriePreVisitCb cb_pre,
	RZ_NULLABLE RzTrieEdgeVisitCb cb_edge, RZ_NULLABLE RzTriePostVisitCb cb_post, RZ_NULLABLE void *user) {
	rz_return_if_fail(n);

	if (cb_pre) {
		cb_pre(n, user);
	}

	void **it;
	rz_pvector_foreach (&n->children, it) {
		RzTrieNode *child = *it;
		if (cb_edge) {
			cb_edge(n, child, user);
		}
		rz_trie_dfs(child, cb_pre, cb_edge, cb_post, user);
	}

	if (cb_post) {
		cb_post(n, user);
	}
}

static void free_all_children(RzTrieNode *n, RzTrieNodeFreeCb free_cb) {
	if (!n) {
		return;
	}

	void **it;
	rz_pvector_foreach (&n->children, it) {
		RzTrieNode *child = *it;
		rz_trie_dfs(child, NULL, NULL, trie_node_free, free_cb);
	}
}

/**
 * \brief Frees all nodes (including root) and the `RzTrie` container itself.
 *
 * \param[in] t  The trie to free.
 * \note After this call, \p t is a dangling ptr and must not be used again.
 */
RZ_API void rz_trie_free(RZ_NULLABLE RZ_OWN RzTrie *t) {
	if (!t) {
		return;
	}
	if (t->root) {
		free_all_children(t->root, t->free);
		trie_node_free(t->root, t->free);
	}
	RZ_FREE(t);
}

/**
 * \brief Removes all non-root nodes from the trie, resetting it to an empty
 *        state suitable for reuse.
 *
 * \param[in,out] t  The trie to clear.
 * \note The root node is also reset to clean state, freeing the `data` field if any.
 */
RZ_API void rz_trie_clear(RZ_NULLABLE RZ_BORROW RzTrie *t) {
	if (!t || !t->root) {
		return;
	}
	free_all_children(t->root, t->free);
	rz_pvector_clear(&t->root->children);
	if (t->free) {
		t->free(t->root);
	}
	t->root->data = NULL;
	t->root->is_end = false;
}

/**
 * \brief Searches for \p key in the trie and returns the terminal node.
 *
 * \param[in] t           The trie to search in.
 * \param[in] key         The key to search for. Pointer to user-defined key structure.
 * \param[in] len         Number of elements in the key. Must be > 0.
 * \param[in] partial_key If `true`, returns the node even if `is_end` is false (prefix match).
 * \return Node at the end of the key path, or `NULL` if not found.
 *
 * \note If you manipulated root and set is_end=true for root,
 * still it will return NULL for empty key (len=0) as root is not a valid key.
 */
RZ_API RZ_BORROW RzTrieNode *rz_trie_find_prefix(RZ_NONNULL const RzTrie *t,
	RZ_NONNULL const void *key, size_t len, bool partial_key) {
	rz_return_val_if_fail(t && t->root && key && len > 0, NULL);

	RzTrieNode *curr = t->root;
	for (size_t idx = 0; idx < len; idx++) {
		curr = trie_find_child(t, curr, key, idx);
		if (!curr) {
			return NULL;
		}
	}
	return (curr->is_end || partial_key) ? curr : NULL;
}

/**
 * \brief Deletes a complete key from the trie and prunes unreachable nodes.
 *
 * Nodes shared with other keys are preserved; only leaf nodes that are
 * no longer part of any key are freed.
 *
 * \param[in,out] t   The trie to delete from.
 * \param[in]     key The key to delete. Pointer to user-defined key structure.
 * \param[in]     len Number of elements in the key. Must be > 0.
 * \return `true` if the key was found and deleted, else `false`.
 *
 * \note Root node is never deleted.
 */
RZ_API bool rz_trie_delete(RZ_NONNULL RZ_BORROW RzTrie *t, RZ_NONNULL const void *key, size_t len) {
	rz_return_val_if_fail(t && t->root && key && len > 0, false);

	RzTrieNode **path = RZ_NEWS0(RzTrieNode *, len + 1);
	if (!path) {
		RZ_LOG_ERROR("calloc failed for path array\n");
		return false;
	}
	path[0] = t->root;

	for (size_t i = 0; i < len; i++) {
		path[i + 1] = trie_find_child(t, path[i], key, i);
		if (!path[i + 1]) {
			free(path);
			return false;
		}
	}

	if (!path[len]->is_end) {
		free(path);
		return false; // key was never inserted
	}
	path[len]->is_end = false;

	// go reverse and free leaf nodes that have no children and is_end=false
	// except root
	for (size_t i = len; i > 0; i--) {
		RzTrieNode *node = path[i];
		if (node->is_end || rz_pvector_len(&node->children) > 0) {
			break;
		}
		rz_pvector_remove_data(&path[i - 1]->children, node);
		trie_node_free(node, t->free);
	}

	free(path);
	return true;
}

/**
 * \brief Checks whether a complete key exists in the trie.
 *
 * \param[in] t   The trie to search in.
 * \param[in] key The key to check. Pointer to user-defined key structure.
 * \param[in] len Number of elements in the key.
 * \return `true` if the key exists, `false` otherwise.
 */
RZ_API bool rz_trie_contains(RZ_NONNULL const RzTrie *t, RZ_NONNULL const void *key, size_t len) {
	return rz_trie_find_prefix(t, key, len, false) != NULL;
}

static void count_keys(RzTrieNode *n, void *user) {
	if (n->is_end) {
		(*(size_t *)user)++;
	}
}

/**
 * \brief Returns the number of complete keys stored in the trie.
 *
 * \param[in] t The trie to count keys in.
 * \return Number of complete keys (nodes with `is_end == true`).
 */
RZ_API size_t rz_trie_size(RZ_NONNULL const RzTrie *t) {
	rz_return_val_if_fail(t && t->root, 0);
	size_t count = 0;
	rz_trie_dfs(t->root, count_keys, NULL, NULL, &count);
	return count;
}

/**
 * \brief Finds the longest prefix of \p key that was inserted as a complete key.
 *
 * \param[in]  t         The trie to search in.
 * \param[in]  key       The key whose prefixes to search for. Pointer to user-defined key structure.
 * \param[in]  len       Number of elements in the key. Must be > 0.
 * \param[out] match_len Set to the length of the longest matching prefix, or 0 if none found.
 * \return Node at the end of the longest matching prefix, or `NULL` if no prefix matches.
 */
RZ_API RZ_BORROW RzTrieNode *rz_trie_longest_prefix_match(RZ_NONNULL const RzTrie *t,
	RZ_NONNULL const void *key, size_t len, RZ_NONNULL size_t *match_len) {
	rz_return_val_if_fail(t && t->root && key && len > 0 && match_len, NULL);

	*match_len = 0;
	RzTrieNode *curr = t->root;
	RzTrieNode *last_match = NULL;

	for (size_t i = 0; i < len; i++) {
		curr = trie_find_child(t, curr, key, i);
		if (!curr) {
			break;
		}
		if (curr->is_end) {
			last_match = curr;
			*match_len = i + 1;
		}
	}
	return last_match;
}
