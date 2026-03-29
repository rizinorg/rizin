// SPDX-FileCopyrightText: 2007-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2007-2019 alvarofe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <rz_util.h>

/**
 * \brief Global default pool shared by all lists that do not carry their own.
 *        Replace with a per-thread pool for lock-free use in threaded contexts.
 */
static RzListPool rz_list_default_pool = { NULL, NULL };

/**
 * \brief Frees all slabs owned by the pool. Does NOT free the pool struct itself.
 */
static inline void pool_destroy(RzListPool *pool) {
	RzListSlab *slab = pool->slabs;
	while (slab) {
		RzListSlab *next = slab->next_slab;
		free(slab);
		slab = next;
	}
	pool->slabs = NULL;
	pool->freelist = NULL;
}

/**
 * \brief Releases all slab memory held by the global default pool.
 *
 * Call this only when you are certain no RzList is live (e.g. at program exit
 * or after a full rz_core_free()). After this call rz_list_* functions will
 * transparently re-grow the pool on demand.
 **/
RZ_API void rz_list_pool_fini(void) {
	pool_destroy(&rz_list_default_pool);
}

/**
 * \brief Allocates an RzListIter from the pool, growing by one slab if needed.
 */
static inline RzListIter *pool_alloc(RzListPool *pool) {
	if (!pool->freelist) {
		RzListSlab *slab = calloc(1, sizeof(RzListSlab));
		if (!slab) {
			return NULL;
		}
		slab->next_slab = pool->slabs;
		pool->slabs = slab;
		for (int i = 0; i < RZ_LIST_SLAB_SIZE - 1; i++) {
			slab->nodes[i].next = &slab->nodes[i + 1];
		}
		slab->nodes[RZ_LIST_SLAB_SIZE - 1].next = NULL;
		pool->freelist = &slab->nodes[0];
	}
	RzListIter *n = pool->freelist;
	pool->freelist = n->next;
	n->next = NULL;
	n->prev = NULL;
	n->val = NULL;
	return n;
}

/**
 * \brief Returns an RzListIter back to the pool freelist.
 */
static inline void pool_free(RzListPool *pool, RzListIter *node) {
	node->val = NULL; // clear stale pointer
	node->prev = NULL;
	node->next = pool->freelist;
	pool->freelist = node;
}

// Helper: resolve the pool for a list (future: list could carry its own pool).
static inline RzListPool *_pool_of(RzList *list) {
	(void)list;
	return &rz_list_default_pool;
}

/**
 * \brief Returns the RzListIter at position \p n, traversing from whichever
 *        end is closer. Returns NULL if \p n is out of bounds.
 **/
static inline RzListIter *rz_list_iter_at(const RzList *list, ut32 n) {
	if (n >= list->length) {
		return NULL;
	}
	RzListIter *it;
	if (n < list->length / 2) {
		it = list->head;
		for (ut32 i = 0; i < n; i++) {
			it = it->next;
		}
	} else {
		it = list->tail;
		for (ut32 i = list->length - 1; i > n; i--) {
			it = it->prev;
		}
	}
	return it;
}

/**
 * \brief returns the value stored in the prev RzList iterator
 *
 **/
RZ_API RZ_BORROW void *rz_list_iter_get_prev_data(RZ_NONNULL RzListIter *iter) {
	rz_return_val_if_fail(iter, NULL);
	RzListIter *p = iter->prev;
	if (!p) {
		return NULL;
	}
	return p->val;
}

/**
 * \brief returns the value stored in the next RzList iterator
 *
 **/
RZ_API RZ_BORROW void *rz_list_iter_get_next_data(RZ_NONNULL RzListIter *iter) {
	rz_return_val_if_fail(iter, NULL);
	RzListIter *n = iter->next;
	if (!n) {
		return NULL;
	}
	return n->val;
}

/**
 * \brief Sets the value stored in the list iterator and returns true if succeeds
 *
 **/
RZ_API bool rz_list_iter_set_data(RZ_NONNULL RzListIter *iter, RZ_NULLABLE void *data) {
	rz_return_val_if_fail(iter, false);
	iter->val = data;
	return true;
}

/**
 * \brief swaps the data held by two iterators and returns true if succeeds
 *
 **/
RZ_API bool rz_list_iter_swap_data(RZ_NONNULL RzListIter *iter0, RZ_NONNULL RzListIter *iter1) {
	rz_return_val_if_fail(iter0 && iter1, false);
	void *tmp = iter0->val;
	iter0->val = iter1->val;
	iter1->val = tmp;
	return true;
}

/**
 * \brief returns the first RzList iterator in the list
 *
 **/
RZ_API RZ_BORROW RzListIter *rz_list_iterator(RZ_NONNULL const RzList *list) {
	rz_return_val_if_fail(list, NULL);
	return list->head;
}

/**
 * \brief Alias for rz_list_append
 *
 **/
RZ_API RZ_BORROW RzListIter *rz_list_push(RZ_NONNULL RzList *list, void *item) {
	return rz_list_append(list, item);
}

/**
 * \brief Returns the value stored in the first node of the list.
 *
 **/
RZ_API RZ_BORROW void *rz_list_first_val(RZ_NONNULL const RzList *list) {
	rz_return_val_if_fail(list, NULL);
	return list->head ? list->head->val : NULL;
}

/**
 * \brief Returns the value stored in the last node of the list.
 *
 **/
RZ_API RZ_BORROW void *rz_list_last_val(RZ_NONNULL const RzList *list) {
	rz_return_val_if_fail(list, NULL);
	return list->tail ? list->tail->val : NULL;
}

/**
 * \brief Initializes the RzList pointer
 *
 **/
RZ_API void rz_list_init(RZ_NONNULL RzList *list) {
	rz_return_if_fail(list);

	list->head = NULL;
	list->tail = NULL;
	list->free = NULL;
	list->length = 0;
	list->sorted = false;
}

/**
 * \brief Returns the length of the list
 *
 **/
RZ_API ut32 rz_list_length(RZ_NONNULL const RzList *list) {
	if (!list) {
		return 0;
	}
	return list->length;
}

/**
 * \brief Empties the list without freeing the list pointer
 *
 **/
RZ_API void rz_list_purge(RZ_NONNULL RzList *list) {
	rz_return_if_fail(list);
	RzListPool *pool = _pool_of(list);
	RzListIter *it = list->head;
	RzListFree fn = list->free;
	while (it) {
		RzListIter *next = it->next;
		if (fn && it->val) {
			fn(it->val);
		}
		pool_free(pool, it);
		it = next;
	}
	list->length = 0;
	list->head = list->tail = NULL;
}

/**
 * \brief Empties the list and frees the list pointer
 *
 **/
RZ_API void rz_list_free(RZ_NULLABLE RzList *list) {
	if (!list) {
		return;
	}
	rz_list_purge(list);
	free(list);
}

/**
 * \brief Deletes a node in the list by searching for a pointer value.
 *
 **/
RZ_API bool rz_list_delete_val(RZ_NONNULL RzList *list, void *val) {
	rz_return_val_if_fail(list, false);
	RzListIter *iter = rz_list_find_val(list, val);
	if (!iter) {
		return false;
	}
	rz_list_delete(list, iter);
	return true;
}

/**
 * \brief Deletes a node in the list by using an RzListIter pointer.
 *
 **/
RZ_API void rz_list_delete(RZ_NONNULL RzList *list, RZ_OWN RZ_NONNULL RzListIter *iter) {
	rz_return_if_fail(list && iter);
	if (list->head == iter) {
		list->head = iter->next;
	}
	if (list->tail == iter) {
		list->tail = iter->prev;
	}
	if (iter->prev) {
		iter->prev->next = iter->next;
	}
	if (iter->next) {
		iter->next->prev = iter->prev;
	}
	list->length--;
	if (list->free && iter->val) {
		list->free(iter->val);
	}
	iter->val = NULL;
	pool_free(_pool_of(list), iter);
}

/**
 * \brief Joins 2 list into one (list2 pointer needs to be freed by the user)
 *
 **/
RZ_API bool rz_list_join(RZ_NONNULL RzList *list1, RZ_NONNULL RzList *list2) {
	rz_return_val_if_fail(list1 && list2, 0);

	if (!(list2->length)) {
		return false;
	}
	if (!(list1->length)) {
		list1->head = list2->head;
		list1->tail = list2->tail;
	} else {
		list1->tail->next = list2->head;
		list2->head->prev = list1->tail;
		list1->tail = list2->tail;
		list1->tail->next = NULL;
		list1->sorted = false;
	}
	list1->length += list2->length;
	list2->length = 0;
	list2->head = list2->tail = NULL;
	return true;
}

/**
 * \brief Returns a new initialized RzList pointer (free method is not initialized)
 *
 **/
RZ_API RZ_OWN RzList *rz_list_new(void) {
	RzList *list = RZ_NEW0(RzList);
	if (!list) {
		return NULL;
	}
	rz_list_init(list);
	return list;
}

/**
 * \brief Returns a new initialized RzList pointer and sets the free method
 *
 **/
RZ_API RZ_OWN RzList *rz_list_newf(RZ_NULLABLE RzListFree f) {
	RzList *l = rz_list_new();
	if (l) {
		l->free = f;
	}
	return l;
}

/**
 * \brief Allocates a new RzList and adds an array elements to it
 *
 **/
RZ_API RZ_OWN RzList *rz_list_new_from_array(const void **arr, size_t arr_size) {
	RzList *l = rz_list_new();
	if (!l) {
		return NULL;
	}
	if (!arr) {
		return l;
	}
	size_t i;
	for (i = 0; i < arr_size; i++) {
		rz_list_append(l, (void *)arr[i]);
	}
	return l;
}

/**
 * \brief Allocates a new RzList and adds all elements of the iterator \p iter to it.
 * \p iter keeps the ownership over the values.
 *
 * \return The produced list. Or NULL in case of failure.
 **/
RZ_API RZ_OWN RzList *rz_list_new_from_iterator(RZ_BORROW RZ_NONNULL RzIterator *iter) {
	rz_return_val_if_fail(iter, NULL);
	RzList *l = rz_list_new();
	if (!l) {
		return NULL;
	}
	void **val;
	rz_iterator_foreach(iter, val) {
		rz_list_append(l, (void *)*val);
	}
	return l;
}

/**
 * \brief Creates a RzListIter element that can be inserted into a RzList
 *
 **/
RZ_API RZ_OWN RzListIter *rz_list_item_new(RZ_NULLABLE void *data) {
	RzListIter *item = pool_alloc(&rz_list_default_pool);
	if (item) {
		item->val = data;
	}
	return item;
}

/**
 * \brief Appends at the end of the list a new element
 *
 **/
RZ_API RZ_BORROW RzListIter *rz_list_append(RZ_NONNULL RzList *list, RZ_NONNULL void *data) {

	if (RZ_UNLIKELY(!list)) {
		return NULL;
	}
	RzListIter *item = pool_alloc(_pool_of(list));
	if (RZ_UNLIKELY(!item)) {
		return NULL;
	}
	if (list->tail) {
		list->tail->next = item;
	}
	item->val = data;
	item->prev = list->tail;
	item->next = NULL;
	list->tail = item;
	if (!list->head) {
		list->head = item;
	}
	list->length++;
	list->sorted = false;
	return item;
}

/**
 * \brief Appends at the beginning of the list a new element
 *
 **/
RZ_API RZ_BORROW RzListIter *rz_list_prepend(RZ_NONNULL RzList *list, RZ_NONNULL void *data) {
	rz_return_val_if_fail(list, NULL);

	RzListIter *item = pool_alloc(_pool_of(list));
	if (!item) {
		return NULL;
	}
	if (list->head) {
		list->head->prev = item;
	}
	item->val = data;
	item->next = list->head;
	item->prev = NULL;
	list->head = item;
	if (!list->tail) {
		list->tail = item;
	}
	list->length++;
	list->sorted = false;
	return item;
}

/**
 * \brief Inserts a new element at the N-th position
 *
 **/
RZ_API RZ_BORROW RzListIter *rz_list_insert(RZ_NONNULL RzList *list, ut32 n, RZ_NONNULL void *data) {
	rz_return_val_if_fail(list, NULL);
	if (!list->head || !n) {
		return rz_list_prepend(list, data);
	}
	RzListIter *it = rz_list_iter_at(list, n);
	if (!it) {
		return rz_list_append(list, data);
	}
	RzListIter *item = pool_alloc(_pool_of(list));
	if (!item) {
		return NULL;
	}
	item->val = data;
	item->next = it;
	item->prev = it->prev;
	if (it->prev) {
		it->prev->next = item;
	} else {
		list->head = item;
	}
	it->prev = item;
	list->length++;
	list->sorted = false;
	return item;
}

/**
 * \brief Removes and returns the last element of the list
 *
 **/
RZ_API RZ_OWN void *rz_list_pop(RZ_NONNULL RzList *list) {
	void *data = NULL;
	RzListIter *iter;

	rz_return_val_if_fail(list, NULL);

	if (list->tail) {
		iter = list->tail;
		if (list->head == list->tail) {
			list->head = list->tail = NULL;
		} else {
			list->tail = iter->prev;
			list->tail->next = NULL;
		}
		data = iter->val;
		pool_free(_pool_of(list), iter);
		list->length--;
	}
	return data;
}

/**
 * \brief Removes and returns the first element of the list
 *
 **/
RZ_API RZ_OWN void *rz_list_pop_head(RZ_NONNULL RzList *list) {
	void *data = NULL;

	rz_return_val_if_fail(list, NULL);

	if (list->head) {
		RzListIter *iter = list->head;
		if (list->head == list->tail) {
			list->head = list->tail = NULL;
		} else {
			list->head = iter->next;
			list->head->prev = NULL;
		}
		data = iter->val;
		pool_free(_pool_of(list), iter);
		list->length--;
	}
	return data;
}

/**
 * \brief Removes the N-th element of the list
 *
 **/
RZ_API ut32 rz_list_del_n(RZ_NONNULL RzList *list, ut32 n) {
	rz_return_val_if_fail(list, false);
	RzListIter *it = rz_list_iter_at(list, n);
	if (!it) {
		return false;
	}
	rz_list_delete(list, it);
	return true;
}

/**
 * \brief Reverses the list
 *
 **/
RZ_API void rz_list_reverse(RZ_NONNULL RzList *list) {
	RzListIter *it, *tmp;

	rz_return_if_fail(list);

	for (it = list->head; it; it = it->prev) {
		tmp = it->prev;
		it->prev = it->next;
		it->next = tmp;
	}
	tmp = list->head;
	list->head = list->tail;
	list->tail = tmp;
}

/**
 * \brief Shallow copies of the list (but doesn't free its elements)
 *
 **/
RZ_API RZ_OWN RzList *rz_list_clone(RZ_NONNULL const RzList *list) {
	RzListIter *iter;
	void *data;

	rz_return_val_if_fail(list, NULL);

	RzList *l = rz_list_new();
	if (!l) {
		return NULL;
	}
	l->free = NULL;
	rz_list_foreach (list, iter, data) {
		rz_list_append(l, data);
	}
	l->sorted = list->sorted;
	return l;
}

/**
 * \brief Adds an element to a sorted list via the RzListComparator
 *
 **/
RZ_API RZ_BORROW RzListIter *rz_list_add_sorted(RZ_NONNULL RzList *list, RZ_NONNULL void *data,
	RZ_NONNULL RzListComparator cmp, void *user) {
	rz_return_val_if_fail(list && data && cmp, NULL);

	RzListIter *it;
	for (it = list->head; it && cmp(data, it->val, user) > 0; it = it->next) {
	}
	if (it) {
		RzListIter *item = pool_alloc(_pool_of(list));
		if (!item) {
			return NULL;
		}
		item->next = it;
		item->prev = it->prev;
		item->val = data;
		item->next->prev = item;
		if (!item->prev) {
			list->head = item;
		} else {
			item->prev->next = item;
		}
		list->length++;
		list->sorted = true;
		return item;
	}
	/* data is greater than all existing elements — append */
	RzListIter *appended = rz_list_append(list, data);
	if (appended) {
		list->sorted = true;
	}
	return appended;
}

/**
 * \brief Sets the N-th element of the list
 *
 **/
RZ_API ut32 rz_list_set_n(RZ_NONNULL RzList *list, ut32 n, RZ_NONNULL void *data) {
	rz_return_val_if_fail(list, false);
	RzListIter *it = rz_list_iter_at(list, n);
	if (!it) {
		return false;
	}
	if (list->free) {
		list->free(it->val);
	}
	it->val = data;
	list->sorted = false;
	return true;
}

/**
 * \brief Returns the N-th element of the list
 *
 **/
RZ_API RZ_BORROW void *rz_list_get_n(RZ_NONNULL const RzList *list, ut32 n) {
	rz_return_val_if_fail(list, NULL);
	RzListIter *it = rz_list_iter_at(list, n);
	return it ? it->val : NULL;
}

/**
 * \brief Returns true if the given pointer value is found, false otherwise.
 *
 **/
RZ_API RZ_BORROW bool rz_list_contains(RZ_NONNULL const RzList *list, RZ_NONNULL const void *val) {
	return rz_list_find_val(list, val) != NULL;
}

/**
 * \brief Returns the RzListIter of the given pointer value, if found.
 *
 **/
RZ_API RZ_BORROW RzListIter *rz_list_find_val(RZ_NONNULL const RzList *list, RZ_NONNULL const void *val) {
	rz_return_val_if_fail(list, NULL);
	for (RzListIter *it = list->head; it; it = it->next) {
		if (RZ_UNLIKELY(it->next != NULL)) {
			RZ_PREFETCH(it->next);
		}
		if (it->val == val) {
			return it;
		}
	}
	return NULL;
}

/**
 * \brief Returns first RzListIter node that has a value that is RzListComparator-equal
 *        to the given value.
 * For searching by value equality, rz_list_find_val() provides a simpler interface.
 *
 * \return The first RzListIter node that matches `val` wrt `cmp`.
 */
RZ_API RZ_BORROW RzListIter *rz_list_find(RZ_NONNULL const RzList *list, const void *val,
	RZ_NONNULL RzListComparator cmp, void *user) {
	rz_return_val_if_fail(list && cmp, NULL);

	void *q;
	RzListIter *iter;
	rz_list_foreach (list, iter, q) {
		if (!cmp(val, q, user)) {
			return iter;
		}
	}
	return NULL;
}

static RzListIter *_merge(RzListIter *first, RzListIter *second, RzListComparator cmp, void *user) {
	RzListIter *next = NULL, *result = NULL, *head = NULL;
	while (first || second) {
		if (!second) {
			next = first;
			first = first->next;
		} else if (!first) {
			next = second;
			second = second->next;
		} else if (cmp(first->val, second->val, user) <= 0) {
			next = first;
			first = first->next;
		} else {
			next = second;
			second = second->next;
		}
		if (!head) {
			result = next;
			head = result;
			head->prev = NULL;
		} else {
			result->next = next;
			next->prev = result;
			result = result->next;
		}
	}
	head->prev = NULL;
	next->next = NULL;
	return head;
}

static RzListIter *_r_list_half_split(RzListIter *head) {
	RzListIter *tmp;
	RzListIter *fast;
	RzListIter *slow;
	if (!head || !head->next) {
		return head;
	}
	slow = head;
	fast = head;
	while (fast && fast->next && fast->next->next) {
		fast = fast->next->next;
		slow = slow->next;
	}
	tmp = slow->next;
	slow->next = NULL;
	return tmp;
}

static RzListIter *_merge_sort(RzListIter *head, RzListComparator cmp, void *user) {
	RzListIter *second;
	if (!head || !head->next) {
		return head;
	}
	second = _r_list_half_split(head);
	head = _merge_sort(head, cmp, user);
	second = _merge_sort(second, cmp, user);
	return _merge(head, second, cmp, user);
}

/**
 * \brief Merge sorts the list via the RzListComparator
 *
 **/
RZ_API void rz_list_merge_sort(RZ_NONNULL RzList *list, RZ_NONNULL RzListComparator cmp, void *user) {
	rz_return_if_fail(list && cmp);

	if (!list->sorted && list->head && cmp) {
		RzListIter *iter;
		list->head = _merge_sort(list->head, cmp, user);
		// update tail reference
		iter = list->head;
		while (iter && iter->next) {
			iter = iter->next;
		}
		list->tail = iter;
	}
	list->sorted = true;
}

/**
 * \brief Insertion sorts the list via the RzListComparator
 *
 **/
RZ_API void rz_list_insertion_sort(RZ_NONNULL RzList *list, RZ_NONNULL RzListComparator cmp, void *user) {
	rz_return_if_fail(list && cmp);

	if (list->sorted) {
		return;
	}
	RzListIter *it, *it2;
	for (it = list->head; it; it = it->next) {
		for (it2 = it->next; it2 && it2->val; it2 = it2->next) {
			if (cmp(it->val, it2->val, user) > 0) {
				void *t = it->val;
				it->val = it2->val;
				it2->val = t;
			}
		}
	}
	list->sorted = true;
}

/**
 * \brief Sorts via merge sort or via insertion sort a list
 *
 **/
RZ_API void rz_list_sort(RZ_NONNULL RzList *list, RZ_NONNULL RzListComparator cmp, void *user) {
	rz_return_if_fail(list && cmp);
	if (list->length > 43) {
		rz_list_merge_sort(list, cmp, user);
	} else {
		rz_list_insertion_sort(list, cmp, user);
	}
}

/**
 * \brief Returns a new RzList which contains only unique values
 *
 **/
RZ_API RZ_OWN RzList *rz_list_uniq(RZ_NONNULL const RzList *list, RZ_NONNULL RzListComparator cmp, void *user) {
	RzList *sorted = rz_list_clone(list);
	if (!sorted) {
		return NULL;
	}

	rz_list_sort(sorted, cmp, user);
	rz_list_sorted_uniq(sorted, cmp, user);
	return sorted;
}

/**
 * \brief Removes duplicate values from a sorted list in-place.
 *
 * Use only on a list that is sorted with respect to the RzListComparator.
 **/
RZ_API void rz_list_sorted_uniq(RZ_NONNULL RzList *list, RZ_NONNULL RzListComparator cmp, void *user) {
	rz_return_if_fail(list && cmp);

	RzListIter *iter, *tmp_iter;
	void *cur, *prev = NULL;
	rz_list_foreach_safe (list, iter, tmp_iter, cur) {
		if (prev && cmp(prev, cur, user) == 0) {
			rz_list_delete(list, iter);
			continue;
		}
		prev = cur;
	}
}

/**
 * \brief Casts a RzList containing strings into a concatenated string
 *
 * \param list The list of strings to concatenate.
 * \param ch char to separate the match strings.
 *
 * \return The concatenated string.
 **/
RZ_API RZ_OWN char *rz_list_to_str(RZ_NONNULL RzList *list, char ch) {
	RzListIter *iter;
	RzStrBuf *buf = rz_strbuf_new("");
	if (!buf) {
		return NULL;
	}
	char *item;
	rz_list_foreach (list, iter, item) {
		rz_strbuf_appendf(buf, "%s%c", item, ch);
	}
	return rz_strbuf_drain(buf);
}
