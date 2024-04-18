// SPDX-FileCopyrightText: 2007-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2007-2019 alvarofe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <rz_util.h>

/**
 * \brief returns the prev RzList iterator in the list
 *
 **/
RZ_API RZ_BORROW RzListIter *rz_list_iter_get_prev(RZ_NONNULL RzListIter *iter) {
	rz_return_val_if_fail(iter, NULL);
	return iter->prev;
}
/**
 * \brief returns the next RzList iterator in the list
 *
 **/
RZ_API RZ_BORROW RzListIter *rz_list_iter_get_next(RZ_NONNULL RzListIter *iter) {
	rz_return_val_if_fail(iter, NULL);
	return iter->next;
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
	return p->elem;
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
	return n->elem;
}

/**
 * \brief returns the value stored in the list iterator
 *
 **/
RZ_API void *rz_list_iter_get_data(RZ_NONNULL RzListIter *iter) {
	rz_return_val_if_fail(iter, NULL);
	return iter->elem;
}

/**
 * \brief Sets the value stored in the list iterator and returns true if succeeds
 *
 **/
RZ_API bool rz_list_iter_set_data(RZ_NONNULL RzListIter *iter, RZ_NULLABLE void *data) {
	rz_return_val_if_fail(iter, false);
	iter->elem = data;
	return true;
}

/**
 * \brief swaps the data held by two iterators and returns true if succeeds
 *
 **/
RZ_API bool rz_list_iter_swap_data(RZ_NONNULL RzListIter *iter0, RZ_NONNULL RzListIter *iter1) {
	rz_return_val_if_fail(iter0 && iter1, false);
	void *tmp = iter0->elem;
	iter0->elem = iter1->elem;
	iter1->elem = tmp;
	return true;
}

/**
 * \brief returns the first RzList iterator int the list
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
 * \brief Returns the first element of the list
 *
 **/
RZ_API RZ_BORROW void *rz_list_first(RZ_NONNULL const RzList *list) {
	rz_return_val_if_fail(list, NULL);
	return list->head ? list->head->elem : NULL;
}

/**
 * \brief Returns the last element of the list.
 *
 **/
RZ_API RZ_BORROW void *rz_list_last(RZ_NONNULL const RzList *list) {
	rz_return_val_if_fail(list, NULL);
	return list->tail ? list->tail->elem : NULL;
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

	RzListIter *it = list->head;
	while (it) {
		RzListIter *next = it->next;
		rz_list_delete(list, it);
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
 * \brief Deletes an entry in the list by searching for a pointer
 *
 **/
RZ_API bool rz_list_delete_data(RZ_NONNULL RzList *list, void *ptr) {
	rz_return_val_if_fail(list, false);
	RzListIter *iter = rz_list_find_ptr(list, ptr);
	if (!iter) {
		return false;
	}
	rz_list_delete(list, iter);
	return true;
}

/**
 * \brief Removes an entry in the list by using the RzListIter pointer
 *
 **/
RZ_API void rz_list_delete(RZ_NONNULL RzList *list, RZ_NONNULL RzListIter *iter) {
	rz_return_if_fail(list && iter);
	rz_list_split_iter(list, iter);
	if (list->free && iter->elem) {
		list->free(iter->elem);
	}
	iter->elem = NULL;
	free(iter);
}

RZ_API void rz_list_split(RZ_NONNULL RzList *list, void *ptr) {
	rz_return_if_fail(list);

	RzListIter *iter = rz_list_iterator(list);
	while (iter) {
		void *item = iter->elem;
		if (ptr == item) {
			rz_list_split_iter(list, iter);
			free(iter);
			break;
		}
		iter = iter->next;
	}
}

RZ_API void rz_list_split_iter(RZ_NONNULL RzList *list, RZ_NONNULL RzListIter *iter) {
	rz_return_if_fail(list);

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
RZ_API RZ_OWN RzList *rz_list_new_from_array(RZ_NONNULL const void **arr, size_t arr_size) {
	RzList *l = rz_list_new();
	if (!l) {
		return NULL;
	}
	size_t i;
	for (i = 0; i < arr_size; i++) {
		rz_list_append(l, (void *)arr[i]);
	}
	return l;
}

/**
 * \brief Creates a RzListIter element that can be inserted into a RzList
 *
 **/
RZ_API RZ_OWN RzListIter *rz_list_item_new(RZ_NULLABLE void *data) {
	RzListIter *item = RZ_NEW0(RzListIter);
	if (item) {
		item->elem = data;
	}
	return item;
}

/**
 * \brief Appends at the end of the list a new element
 *
 **/
RZ_API RZ_BORROW RzListIter *rz_list_append(RZ_NONNULL RzList *list, RZ_NONNULL void *data) {
	RzListIter *item = NULL;

	rz_return_val_if_fail(list, NULL);

	item = RZ_NEW(RzListIter);
	if (!item) {
		return item;
	}
	if (list->tail) {
		list->tail->next = item;
	}
	item->elem = data;
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

	RzListIter *item = RZ_NEW0(RzListIter);
	if (!item) {
		return NULL;
	}
	if (list->head) {
		list->head->prev = item;
	}
	item->elem = data;
	item->next = list->head;
	item->prev = NULL;
	list->head = item;
	if (!list->tail) {
		list->tail = item;
	}
	list->length++;
	list->sorted = true;
	return item;
}

/**
 * \brief Inserts a new element at the N-th position
 *
 **/
RZ_API RZ_BORROW RzListIter *rz_list_insert(RZ_NONNULL RzList *list, ut32 n, RZ_NONNULL void *data) {
	RzListIter *it, *item;
	ut32 i;

	rz_return_val_if_fail(list, NULL);

	if (!list->head || !n) {
		return rz_list_prepend(list, data);
	}
	for (it = list->head, i = 0; it && it->elem; it = it->next, i++) {
		if (i == n) {
			item = RZ_NEW(RzListIter);
			if (!item) {
				return NULL;
			}
			item->elem = data;
			item->next = it;
			item->prev = it->prev;
			if (it->prev) {
				it->prev->next = item;
			}
			it->prev = item;
			list->length++;
			list->sorted = true;
			return item;
		}
	}
	return rz_list_append(list, data);
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
		data = iter->elem;
		free(iter);
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
		data = iter->elem;
		free(iter);
		list->length--;
	}
	return data;
}

/**
 * \brief Removes the N-th element of the list
 *
 **/
RZ_API ut32 rz_list_del_n(RZ_NONNULL RzList *list, ut32 n) {
	RzListIter *it;
	ut32 i;

	rz_return_val_if_fail(list, false);

	for (it = list->head, i = 0; it && it->elem; it = it->next, i++) {
		if (i == n) {
			if (!it->prev && !it->next) {
				list->head = list->tail = NULL;
			} else if (!it->prev) {
				it->next->prev = NULL;
				list->head = it->next;
			} else if (!it->next) {
				it->prev->next = NULL;
				list->tail = it->prev;
			} else {
				it->prev->next = it->next;
				it->next->prev = it->prev;
			}
			rz_list_delete(list, it);
			return true;
		}
	}
	return false;
}

/**
 * \brief Reverses the list
 *
 **/
RZ_API void rz_list_reverse(RZ_NONNULL RzList *list) {
	RzListIter *it, *tmp;

	rz_return_if_fail(list);

	for (it = list->head; it && it->elem; it = it->prev) {
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
RZ_API RZ_BORROW RzListIter *rz_list_add_sorted(RZ_NONNULL RzList *list, RZ_NONNULL void *data, RZ_NONNULL RzListComparator cmp, void *user) {
	rz_return_val_if_fail(list && data && cmp, NULL);

	RzListIter *it, *item = NULL;
	for (it = list->head; it && it->elem && cmp(data, it->elem, user) > 0; it = it->next) {
	}
	if (it) {
		item = RZ_NEW0(RzListIter);
		if (!item) {
			return NULL;
		}
		item->next = it;
		item->prev = it->prev;
		item->elem = data;
		item->next->prev = item;
		if (!item->prev) {
			list->head = item;
		} else {
			item->prev->next = item;
		}
		list->length++;
	} else {
		rz_list_append(list, data);
	}
	list->sorted = true;
	return item;
}

/**
 * \brief Sets the N-th element of the list
 *
 **/
RZ_API ut32 rz_list_set_n(RZ_NONNULL RzList *list, ut32 n, RZ_NONNULL void *data) {
	RzListIter *it;
	ut32 i;

	rz_return_val_if_fail(list, false);
	for (it = list->head, i = 0; it; it = it->next, i++) {
		if (i == n) {
			if (list->free) {
				list->free(it->elem);
			}
			it->elem = data;
			list->sorted = false;
			return true;
		}
	}
	return false;
}

/**
 * \brief Returns the N-th element of the list
 *
 **/
RZ_API RZ_BORROW void *rz_list_get_n(RZ_NONNULL const RzList *list, ut32 n) {
	RzListIter *it;
	ut32 i;

	rz_return_val_if_fail(list, NULL);
	if (n >= list->length) {
		return NULL;
	}

	for (it = list->head, i = 0; it && it->elem; it = it->next, i++) {
		if (i == n) {
			return it->elem;
		}
	}
	return NULL;
}

/**
 * \brief Returns the RzListIter of the given pointer, if found
 *
 **/
RZ_API RZ_BORROW RzListIter *rz_list_contains(RZ_NONNULL const RzList *list, RZ_NONNULL const void *ptr) {
	return rz_list_find_ptr(list, ptr);
}

/**
 * \brief Returns the RzListIter of the given pointer, if found
 *
 **/
RZ_API RZ_BORROW RzListIter *rz_list_find_ptr(RZ_NONNULL const RzList *list, RZ_NONNULL const void *ptr) {
	rz_return_val_if_fail(list, NULL);
	void *p;
	RzListIter *iter;
	rz_list_foreach (list, iter, p) {
		if (ptr == p) {
			return iter;
		}
	}
	return NULL;
}

/**
 * \brief Returns RzListIter element which matches via the RzListComparator
 *
 * Find the first RzListIter that is equal to the given data
 * For searching by pointer comparison, rz_list_find_ptr() provides a simpler interface.
 *
 * \return the first RzListIter that is equall to p w.r.t. cmp.
 */
RZ_API RZ_BORROW RzListIter *rz_list_find(RZ_NONNULL const RzList *list, const void *p, RZ_NONNULL RzListComparator cmp, void *user) {
	rz_return_val_if_fail(list && cmp, NULL);

	void *q;
	RzListIter *iter;
	rz_list_foreach (list, iter, q) {
		if (!cmp(p, q, user)) {
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
		} else if (cmp(first->elem, second->elem, user) <= 0) {
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
	RzListIter *it;
	RzListIter *it2;
	for (it = list->head; it && it->elem; it = it->next) {
		for (it2 = it->next; it2 && it2->elem; it2 = it2->next) {
			if (cmp(it->elem, it2->elem, user) > 0) {
				void *t = it->elem;
				it->elem = it2->elem;
				it2->elem = t;
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
 * \brief Casts a RzList containg strings into a concatenated string
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
