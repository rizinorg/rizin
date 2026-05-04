// SPDX-FileCopyrightText: 2007-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2007-2019 alvarofe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <rz_util.h>

#define RZ_LIST_SLAB_SIZE 1024

struct rz_list_slab_t {
	RzListIter elements[RZ_LIST_SLAB_SIZE];
	size_t e_current; ///< Index of the next new element
	RzListSlab *next_slab; ///< Next slab
};

static inline RzListSlab *list_slab_new(void) {
	RzListSlab *slab = RZ_NEW0(RzListSlab);
	if (!slab) {
		return NULL;
	}
	slab->e_current = 0;
	slab->next_slab = NULL;
	return slab;
}

static inline RzListIter *list_slab_first_unused(RzListSlab *slab) {
	RzListIter *elem = NULL;
	// if we have used all the elements, if return NULL.
	if (slab->e_current >= RZ_LIST_SLAB_SIZE) {
		return NULL;
	}

	elem = &slab->elements[slab->e_current];
	slab->e_current++;
	return elem;
}

static inline void list_value_free_and_set(RzList *list, RzListIter *elem, void *new_val) {
	if (list->free) {
		list->free(elem->val);
	}
	elem->val = new_val;
}

static inline void list_free_elem(RzList *list, RzListIter *elem) {
	list_value_free_and_set(list, elem, NULL);

	elem->next = list->unused;
	list->unused = elem;
	list->length--;
}

static inline RzListIter *list_new_elem_from_slab(RzList *list) {
	RzListIter *elem = list_slab_first_unused(list->slab);
	if (elem) {
		return elem;
	}

	RzListSlab *slab = list_slab_new();
	if (!slab) {
		return NULL;
	}
	slab->next_slab = list->slab;
	list->slab = slab;

	return list_slab_first_unused(list->slab);
}

static RzListIter *list_new_elem(RzList *list) {
	RzListIter *elem = NULL;
	// we check first if we have any elements that has been
	// recently freed, and we reuse them first.
	if (list->unused) {
		elem = list->unused;
		list->unused = elem->next;
	} else {
		// if not we need one from the slab
		elem = list_new_elem_from_slab(list);
		if (!elem) {
			rz_warn_if_reached();
			return NULL;
		}
	}

	list->length++;
	return elem;
}

/**
 * \brief Returns the RzListIter at position \p n, traversing from whichever
 *        end is closer. Returns NULL if \p n is out of bounds.
 **/
static inline RzListIter *list_iter_at(const RzList *list, ut32 n) {
	if (n >= list->length) {
		return NULL;
	}
	RzListIter *it = NULL;
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

	if (list->free) {
		// we need to free each element one by one.
		while (list->head) {
			rz_list_delete(list, list->head);
		}
	}
	// we need to free only the slabs.
	while (list->slab) {
		RzListSlab *slab = list->slab;
		list->slab = slab->next_slab;
		free(slab);
	}
	list->slab = list_slab_new();
	list->head = NULL;
	list->tail = NULL;
	list->unused = NULL;
	list->length = 0;
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
	free(list->slab);
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

	list_free_elem(list, iter);
}

/**
 * \brief Joins src_list into dst_list by copying all values; src_list is left empty
 *        but its structure (pool, free pointer) is preserved.
 *        The caller is responsible for freeing src_list afterward.
 *
 * \note  src_list's free callback is NOT called during the join so that values
 *        transferred to dst_list are not prematurely destroyed.
 **/
RZ_API bool rz_list_join(RZ_NONNULL RzList *dst_list, RZ_NONNULL RzList *src_list) {
	rz_return_val_if_fail(dst_list && src_list, false);
	if (rz_list_length(src_list) < 1) {
		return false;
	}

	void *data;
	RzListIter *iter;
	rz_list_foreach (src_list, iter, data) {
		rz_list_append(dst_list, data);
		iter->val = NULL;
	}
	dst_list->sorted = false;

	rz_list_purge(src_list);
	return true;
}

/**
 * \brief Returns a new initialized RzList pointer and sets the free method
 *
 **/
RZ_API RZ_OWN RzList *rz_list_newf(RZ_NULLABLE RzListFree f) {
	RzList *list = RZ_NEW0(RzList);
	if (!list) {
		return NULL;
	}
	list->free = f;
	list->slab = list_slab_new();
	if (!list->slab) {
		rz_list_free(list);
		return NULL;
	}
	return list;
}

/**
 * \brief Returns a new initialized RzList pointer (free method is not initialized)
 *
 **/
RZ_API RZ_OWN RzList *rz_list_new(void) {
	return rz_list_newf(NULL);
}

/**
 * \brief Allocates a new RzList and adds an array elements to it
 *
 **/
RZ_API RZ_OWN RzList *rz_list_new_from_array(const void **arr, size_t arr_size) {
	RzList *list = rz_list_new();
	if (!list || !arr) {
		return list;
	}

	for (size_t i = 0; i < arr_size; i++) {
		rz_list_append(list, (void *)arr[i]);
	}
	return list;
}

/**
 * \brief Allocates a new RzList and adds all elements of the iterator \p iter to it.
 * \p iter keeps the ownership over the values.
 *
 * \return The produced list. Or NULL in case of failure.
 **/
RZ_API RZ_OWN RzList *rz_list_new_from_iterator(RZ_BORROW RZ_NONNULL RzIterator *iter) {
	rz_return_val_if_fail(iter, NULL);
	RzList *list = rz_list_new();
	if (!list) {
		return NULL;
	}
	void **val;
	rz_iterator_foreach(iter, val) {
		rz_list_append(list, (void *)*val);
	}
	return list;
}

/**
 * \brief      Sets the RzListFree function to use
 *
 * \param      list  The list to modify
 * \param[in]  f     RzListFree function to set
 */
RZ_API void rz_list_set_free(RZ_NONNULL RzList *list, RZ_NULLABLE RzListFree f) {
	rz_return_if_fail(list);

	list->free = f;
}

/**
 * \brief      Gets the used RzListFree function
 *
 * \param      list  The list to modify
 *
 * \return     The RzListFree function (can be NULL).
 */
RZ_API RzListFree rz_list_get_free(RZ_NONNULL RzList *list) {
	rz_return_val_if_fail(list, NULL);

	return list->free;
}

/**
 * \brief Appends at the end of the list a new element
 *
 **/
RZ_API RZ_BORROW RzListIter *rz_list_append(RZ_NONNULL RzList *list, RZ_NONNULL void *data) {
	rz_return_val_if_fail(list, NULL);
	RzListIter *item = list_new_elem(list);
	if (!item) {
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
	list->sorted = false;
	return item;
}

/**
 * \brief Appends at the beginning of the list a new element
 *
 **/
RZ_API RZ_BORROW RzListIter *rz_list_prepend(RZ_NONNULL RzList *list, RZ_NONNULL void *data) {
	rz_return_val_if_fail(list, NULL);

	RzListIter *item = list_new_elem(list);
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
	list->sorted = false;
	return item;
}

/**
 * \brief Inserts a new element at the N-th position
 *
 **/
RZ_API RZ_BORROW RzListIter *rz_list_insert(RZ_NONNULL RzList *list, ut32 n, RZ_NONNULL void *data) {
	rz_return_val_if_fail(list, NULL);
	if (!n) {
		return rz_list_prepend(list, data);
	}

	RzListIter *it = list_iter_at(list, n);
	if (!it) {
		return rz_list_append(list, data);
	}

	RzListIter *item = list_new_elem(list);
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
	list->sorted = false;
	return item;
}

/**
 * \brief Removes and returns the last element of the list
 *
 **/
RZ_API RZ_OWN void *rz_list_pop(RZ_NONNULL RzList *list) {
	rz_return_val_if_fail(list, NULL);
	if (!list->tail) {
		return NULL;
	}
	void *data = rz_list_last_val(list);
	rz_list_set_val(list->tail, NULL);
	rz_list_delete(list, list->tail);
	return data;
}

RZ_API RZ_OWN void *rz_list_pop_head(RZ_NONNULL RzList *list) {
	rz_return_val_if_fail(list, NULL);
	if (!list->head) {
		return NULL;
	}
	void *data = rz_list_first_val(list);
	rz_list_set_val(list->head, NULL);
	rz_list_delete(list, list->head);
	return data;
}

/**
 * \brief Removes and returns the first element of the list
 *
 **/
RZ_API RZ_OWN void *rz_list_pop_first(RZ_NONNULL RzList *list) {
	rz_return_val_if_fail(list, NULL);
	if (!list->head) {
		return NULL;
	}
	void *data = rz_list_first_val(list);
	rz_list_set_val(list->head, NULL);
	rz_list_delete(list, list->head);
	return data;
}

/**
 * \brief Removes the N-th element of the list
 *
 **/
RZ_API ut32 rz_list_del_n(RZ_NONNULL RzList *list, ut32 n) {
	rz_return_val_if_fail(list, false);
	RzListIter *it = list_iter_at(list, n);
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
	rz_return_if_fail(list);

	RzListIter *it, *tmp;
	for (it = list->head; it; it = it->prev) {
		tmp = it->prev;
		it->prev = it->next;
		it->next = tmp;
	}
	tmp = list->head;
	list->head = list->tail;
	list->tail = tmp;
	list->sorted = false;
}

/**
 * \brief Shallow copies of the list (but doesn't free its elements)
 *
 **/
RZ_API RZ_OWN RzList *rz_list_clone(RZ_NONNULL const RzList *orig) {
	rz_return_val_if_fail(orig, NULL);
	RzList *list = rz_list_new();
	if (!list) {
		return NULL;
	}

	void *data;
	RzListIter *iter;
	rz_list_foreach (orig, iter, data) {
		rz_list_append(list, data);
	}

	list->sorted = orig->sorted;
	return list;
}

/**
 * \brief Adds an element to a sorted list via the RzListComparator
 *
 **/
RZ_API RZ_BORROW RzListIter *rz_list_add_sorted(RZ_NONNULL RzList *list, RZ_NONNULL void *data, RZ_NONNULL RzListComparator cmp, void *user) {
	rz_return_val_if_fail(list && data && cmp, NULL);

	if (!list->sorted) {
		// if not sorted we must sort it.
		rz_list_sort(list, cmp, user);
	}

	RzListIter *it, *item = NULL;
	for (it = list->head; it && it->val && cmp(data, it->val, user) > 0; it = it->next) {
	}

	if (!it) {
		item = rz_list_append(list, data);
		list->sorted = true;
		return item;
	}

	item = list_new_elem(list);
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
	list->sorted = true;
	return item;
}

/**
 * \brief Sets the N-th element of the list
 *
 **/
RZ_API ut32 rz_list_set_n(RZ_NONNULL RzList *list, ut32 n, RZ_NONNULL void *data) {
	rz_return_val_if_fail(list, false);
	RzListIter *iter = list_iter_at(list, n);
	if (!iter) {
		return false;
	}

	list_value_free_and_set(list, iter, data);
	list->sorted = false;
	return true;
}

/**
 * \brief Returns the N-th element of the list
 *
 **/
RZ_API RZ_BORROW void *rz_list_get_n(RZ_NONNULL const RzList *list, ut32 n) {
	rz_return_val_if_fail(list, NULL);
	RzListIter *it = list_iter_at(list, n);
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
	void *p;
	RzListIter *iter;
	rz_list_foreach (list, iter, p) {
		if (val == p) {
			return iter;
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

static RzListIter *list_merge(RzListIter *first, RzListIter *second, RzListComparator cmp, void *user) {
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

static RzListIter *list_half_split(RzListIter *head) {
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

static RzListIter *list_merge_sort(RzListIter *head, RzListComparator cmp, void *user) {
	RzListIter *second;
	if (!head || !head->next) {
		return head;
	}
	second = list_half_split(head);
	head = list_merge_sort(head, cmp, user);
	second = list_merge_sort(second, cmp, user);
	return list_merge(head, second, cmp, user);
}

/**
 * \brief Merge sorts the list via the RzListComparator
 *
 **/
RZ_API void rz_list_merge_sort(RZ_NONNULL RzList *list, RZ_NONNULL RzListComparator cmp, void *user) {
	rz_return_if_fail(list && cmp);

	if (!list->sorted && list->head && cmp) {
		RzListIter *iter;
		list->head = list_merge_sort(list->head, cmp, user);
		// update last reference
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
	RzListIter *it;
	RzListIter *it2;
	for (it = list->head; it && it->val; it = it->next) {
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
	if (rz_list_length(list) > 43) {
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
	rz_return_val_if_fail(list && cmp, NULL);

	RzListIter *iter, *iter2;
	void *item, *item2;
	RzList *nl = rz_list_newf(NULL);
	if (!nl) {
		return NULL;
	}
	rz_list_foreach (list, iter, item) {
		bool found = false;
		rz_list_foreach (nl, iter2, item2) {
			if (cmp(item, item2, user) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			rz_list_append(nl, item);
		}
	}
	return nl;
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
 * \param list         The list of strings to concatenate.
 * \param ch           Char to separate the match strings.
 * \param append_last  When true appends `ch` at the end.
 *
 * \return The concatenated string.
 **/
RZ_API RZ_OWN char *rz_list_to_str(RZ_NONNULL RzList /*<const char *>*/ *list, char ch, bool append_last) {
	rz_return_val_if_fail(list && ch > 0, NULL);

	RzListIter *iter;
	RzStrBuf *buf = rz_strbuf_new("");
	if (!buf) {
		return NULL;
	}
	const char *item;
	rz_list_foreach (list, iter, item) {
		if (rz_strbuf_length(buf) > 0) {
			rz_strbuf_appendf(buf, "%c%s", ch, item);
		} else {
			rz_strbuf_append(buf, item);
		}
	}
	if (append_last) {
		rz_strbuf_appendf(buf, "%c", ch);
	}
	return rz_strbuf_drain(buf);
}
