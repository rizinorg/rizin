// SPDX-FileCopyrightText: 2026 MrQuantum1915 <darshanpatelgdh@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_TRIE_H
#define RZ_TRIE_H

/**
 * \file rz_trie.h
 * \brief Generic Trie (Prefix Tree) data structure.
 *
 * A tree structure that stores arbitrary sequences by sharing common prefixes,
 * enabling efficient insertion, lookup, deletion, and prefix-based queries.
 *
 * Trie's root node is meant to be empty(dummy). If caller manipulates `root->data`,
 * then its caller's responsibility to initialize it manually (or reinitialize after
 * trie clear as `rz_trie_clear` frees `root->data` using callback).Thus operations
 * on empty key are also not supported by APIs. And may have side effects not intended.
 * So its recommended not to manipulate root node manually if you arent sure of the
 * implications.
 *
 * `RzTrieEdgeVisitCb` can be used to access parent.
 */

#include <rz_types.h>
#include <rz_vector.h>

typedef struct rz_trie_node_t {
	RzPVector /*<RzTrieNode *>*/ children; ///< pointer vector pointing to child nodes
	void *data; ///< all custom data that you want to be in node, can be NULL if no data is associated.
	bool is_end; ///< flag to indicate if node is end of a sequence/key, to preserve shorter overlapping sequences
} RzTrieNode;

/**
 * \brief Matches a node against the key at a specific traversal depth.
 * \param[in] n   Pointer to the trie node.
 * \param[in] key Pointer to the user-defined key structure.
 * \param[in] idx Current depth level within the key traversal.
 * \return `true` if the node matches the key at \p idx, else `false`.
 */
typedef bool (*RzTrieNodeMatchCb)(RZ_NONNULL const RzTrieNode *n, RZ_NONNULL const void *key, size_t idx);

/**
 * \brief Initializes node's custom data when a new node is created during insertion.
 * \param[in,out] n   The newly created trie node.
 * \param[in]     key Pointer to the user-defined key structure.
 * \param[in]     idx Current depth level where the node was created.
 */
typedef void (*RzTrieNodeInitCb)(RZ_NONNULL RzTrieNode *n, RZ_NONNULL const void *key, size_t idx);

/**
 * \brief Frees only node->data when a node is deleted and must NOT call `free(n)`.
 * \param[in] n Trie node whose data is to be freed.
 */
typedef void (*RzTrieNodeFreeCb)(RZ_NONNULL RzTrieNode *n);

typedef struct rz_trie_t {
	RzTrieNode *root; ///< root node of trie (usually empty, but not a restriction)
	RzTrieNodeMatchCb match;
	RzTrieNodeInitCb init;
	RzTrieNodeFreeCb free;
} RzTrie;

/**
 * \brief Called before visiting the subtree of a node in DFS.
 * \param[in] n    The current node.
 * \param[in] user Arbitrary context pointer.
 */
typedef void (*RzTriePreVisitCb)(RZ_NONNULL RzTrieNode *n, RZ_NULLABLE void *user);

/**
 * \brief Called when visiting an edge between parent and child in DFS.
 * \param[in] parent Parent node (may be root with no data).
 * \param[in] child  Child node.
 * \param[in] user   Arbitrary context pointer.
 */
typedef void (*RzTrieEdgeVisitCb)(RZ_NONNULL RzTrieNode *parent, RZ_NONNULL RzTrieNode *child, RZ_NULLABLE void *user);

/**
 * \brief Called after visiting the subtree of a node in DFS.
 * \param[in] n    The current node.
 * \param[in] user Arbitrary context pointer.
 */
typedef void (*RzTriePostVisitCb)(RZ_NONNULL RzTrieNode *n, RZ_NULLABLE void *user);

/**
 * \brief Called when an existing node matches the key during insertion.
 * \param[in] n    The matched node.
 * \param[in] user Arbitrary context pointer.
 *
 * \warning Modifying `n->data` in-place can corrupt the trie if the match callback depends
 *  		on the mutated fields. Only do so if you fully undersand the implications.
 */
typedef void (*RzTrieNodeOnHitCb)(RZ_NONNULL RzTrieNode *n, RZ_NULLABLE void *user);

RZ_API RZ_OWN RzTrie *rz_trie_new(RZ_NONNULL RzTrieNodeMatchCb match, RZ_NONNULL RzTrieNodeInitCb init, RZ_NULLABLE RzTrieNodeFreeCb free);
RZ_API void rz_trie_clear(RZ_NULLABLE RZ_BORROW RzTrie *t);
RZ_API void rz_trie_free(RZ_NULLABLE RZ_OWN RzTrie *t);

RZ_API RZ_BORROW RzTrieNode *rz_trie_insert(RZ_NONNULL RZ_BORROW RzTrie *t, RZ_NONNULL const void *key, size_t len, RZ_NULLABLE RzTrieNodeOnHitCb on_hit, RZ_NULLABLE void *user);

RZ_API RZ_BORROW RzTrieNode *rz_trie_find_prefix(RZ_NONNULL const RzTrie *t, RZ_NONNULL const void *key, size_t len, bool partial_key);
RZ_API RZ_BORROW RzTrieNode *rz_trie_longest_prefix_match(RZ_NONNULL const RzTrie *t, RZ_NONNULL const void *key, size_t len, RZ_NONNULL size_t *match_len);
RZ_API bool rz_trie_contains(RZ_NONNULL const RzTrie *t, RZ_NONNULL const void *key, size_t len);

RZ_API size_t rz_trie_size(RZ_NONNULL const RzTrie *t);

RZ_API bool rz_trie_delete(RZ_NONNULL RZ_BORROW RzTrie *t, RZ_NONNULL const void *key, size_t len);

RZ_API void rz_trie_dfs(RZ_NONNULL RzTrieNode *n, RZ_NULLABLE RzTriePreVisitCb cb_pre,
	RZ_NULLABLE RzTrieEdgeVisitCb cb_edge, RZ_NULLABLE RzTriePostVisitCb cb_post, RZ_NULLABLE void *user);

#endif // RZ_TRIE_H
