// SPDX-FileCopyrightText: 2016 Jeffrey Crowell
// SPDX-License-Identifier: BSD-3-Clause

// Skiplists are a probabilistic datastructure than can be used as a k-v store
// with average case O(lg n) lookup time, and worst case O(n).

// https://en.wikipedia.org/wiki/Skip_list

#ifndef RZ_SKIP_LIST_H
#define RZ_SKIP_LIST_H

#include <rz_list.h>

typedef struct rz_skiplist_node_t {
	void *data; // pointer to the value
	struct rz_skiplist_node_t **forward; // forward pointer
} RzSkipListNode;

typedef struct rz_skiplist_t {
	RzSkipListNode *head; // list header
	int list_level; // current level of the list.
	int size;
	RzListFree freefn;
	RzListComparator compare;
} RzSkipList;

RZ_API RzSkipList *rz_skiplist_new(RzListFree freefn, RzListComparator comparefn);
RZ_API void rz_skiplist_free(RzSkipList *list);
RZ_API void rz_skiplist_purge(RzSkipList *list);
RZ_API RzSkipListNode *rz_skiplist_insert(RzSkipList *list, void *data);
RZ_API bool rz_skiplist_delete(RzSkipList *list, void *data);
RZ_API bool rz_skiplist_delete_node(RzSkipList *list, RzSkipListNode *node);
RZ_API RzSkipListNode *rz_skiplist_find(RzSkipList *list, void *data);
RZ_API RzSkipListNode *rz_skiplist_find_geq(RzSkipList *list, void *data);
RZ_API RzSkipListNode *rz_skiplist_find_leq(RzSkipList *list, void *data);
RZ_API void rz_skiplist_join(RzSkipList *l1, RzSkipList *l2);
RZ_API void *rz_skiplist_get_first(RzSkipList *list);
RZ_API void *rz_skiplist_get_n(RzSkipList *list, int n);
RZ_API void *rz_skiplist_get_geq(RzSkipList *list, void *data);
RZ_API void *rz_skiplist_get_leq(RzSkipList *list, void *data);
RZ_API bool rz_skiplist_empty(RzSkipList *list);
RZ_API RzList *rz_skiplist_to_list(RzSkipList *list);

#define rz_skiplist_islast(list, el) (el->forward[0] == list->head)

#define rz_skiplist_length(list) (list->size)

#define rz_skiplist_foreach(list, it, pos) \
	if (list) \
		for (it = list->head->forward[0]; it != list->head && ((pos = it->data) || 1); it = it->forward[0])

#define rz_skiplist_foreach_safe(list, it, tmp, pos) \
	if (list) \
		for (it = list->head->forward[0]; it != list->head && ((pos = it->data) || 1) && ((tmp = it->forward[0]) || 1); it = tmp)

#endif // RZ_SKIP_LIST_H
