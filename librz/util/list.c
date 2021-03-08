// SPDX-FileCopyrightText: 2007-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2007-2019 alvarofe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
// TODO: RRef - reference counting

#include <stdio.h>

#define _R_LIST_C_
#include "rz_util.h"

inline RzListIter *rz_list_iter_new(void) {
	return calloc(1, sizeof(RzListIter));
}

RZ_API void rz_list_iter_free(RzListIter *list) {
	/* do nothing? */
}

RZ_API RzListIter *rz_list_iter_get_next(RzListIter *list) {
	rz_return_val_if_fail(list, NULL);
	return list->n;
}

RZ_API void *rz_list_iter_get_data(RzListIter *list) {
	rz_return_val_if_fail(list, NULL);
	return list->data;
}

RZ_API RzListIter *rz_list_iterator(const RzList *list) {
	rz_return_val_if_fail(list, NULL);
	return list->head;
}

RZ_API RzListIter *rz_list_push(RzList *list, void *item) {
	return rz_list_append(list, item);
}

RZ_API RzListIter *rz_list_get_next(RzListIter *list) {
	rz_return_val_if_fail(list, NULL);
	return list->n;
}

//  rename to head/last
RZ_API void *rz_list_first(const RzList *list) {
	rz_return_val_if_fail(list, NULL);
	return list->head ? list->head->data : NULL;
}

RZ_API void *rz_list_last(const RzList *list) {
	rz_return_val_if_fail(list, NULL);
	return list->tail ? list->tail->data : NULL;
}

RZ_API void rz_list_init(RzList *list) {
	list->head = NULL;
	list->tail = NULL;
	list->free = NULL;
	list->length = 0;
	list->sorted = false;
}

RZ_API int rz_list_length(const RzList *list) {
	rz_return_val_if_fail(list, 0);
	return list->length;
}

/* remove all elements of a list */
RZ_API void rz_list_purge(RzList *list) {
	rz_return_if_fail(list);

	RzListIter *it = list->head;
	while (it) {
		RzListIter *next = it->n;
		rz_list_delete(list, it);
		it = next;
	}
	list->length = 0;
	list->head = list->tail = NULL;
}

/* free the list */
RZ_API void rz_list_free(RzList *list) {
	if (list) {
		rz_list_purge(list);
		free(list);
	}
}

RZ_API bool rz_list_delete_data(RzList *list, void *ptr) {
	void *p;
	RzListIter *iter;

	rz_return_val_if_fail(list, false);

	rz_list_foreach (list, iter, p) {
		if (ptr == p) {
			rz_list_delete(list, iter);
			return true;
		}
	}
	return false;
}

RZ_API void rz_list_delete(RzList *list, RzListIter *iter) {
	rz_return_if_fail(list && iter);
	rz_list_split_iter(list, iter);
	if (list->free && iter->data) {
		list->free(iter->data);
	}
	iter->data = NULL;
	free(iter);
}

RZ_API void rz_list_split(RzList *list, void *ptr) {
	rz_return_if_fail(list);

	RzListIter *iter = rz_list_iterator(list);
	while (iter) {
		void *item = iter->data;
		if (ptr == item) {
			rz_list_split_iter(list, iter);
			free(iter);
			break;
		}
		iter = iter->n;
	}
}

RZ_API void rz_list_split_iter(RzList *list, RzListIter *iter) {
	rz_return_if_fail(list);

	if (list->head == iter) {
		list->head = iter->n;
	}
	if (list->tail == iter) {
		list->tail = iter->p;
	}
	if (iter->p) {
		iter->p->n = iter->n;
	}
	if (iter->n) {
		iter->n->p = iter->p;
	}
	list->length--;
}

//Warning: free functions must be compatible
RZ_API int rz_list_join(RzList *list1, RzList *list2) {
	rz_return_val_if_fail(list1 && list2, 0);

	if (!(list2->length)) {
		return 0;
	}
	if (!(list1->length)) {
		list1->head = list2->head;
		list1->tail = list2->tail;
	} else {
		list1->tail->n = list2->head;
		list2->head->p = list1->tail;
		list1->tail = list2->tail;
		list1->tail->n = NULL;
		list1->sorted = false;
	}
	list1->length += list2->length;
	list2->length = 0;
	list2->head = list2->tail = NULL;
	return 1;
}

RZ_API RzList *rz_list_new(void) {
	RzList *list = RZ_NEW0(RzList);
	if (!list) {
		return NULL;
	}
	rz_list_init(list);
	return list;
}

RZ_API RzList *rz_list_newf(RzListFree f) {
	RzList *l = rz_list_new();
	if (l) {
		l->free = f;
	}
	return l;
}

RZ_API RzList *rz_list_new_from_array(const void **arr, size_t arr_size) {
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

RZ_API RzListIter *rz_list_item_new(void *data) {
	RzListIter *item = RZ_NEW0(RzListIter);
	if (item) {
		item->data = data;
	}
	return item;
}

RZ_API RzListIter *rz_list_append(RzList *list, void *data) {
	RzListIter *item = NULL;

	rz_return_val_if_fail(list, NULL);

	item = RZ_NEW(RzListIter);
	if (!item) {
		return item;
	}
	if (list->tail) {
		list->tail->n = item;
	}
	item->data = data;
	item->p = list->tail;
	item->n = NULL;
	list->tail = item;
	if (!list->head) {
		list->head = item;
	}
	list->length++;
	list->sorted = false;
	return item;
}

RZ_API RzListIter *rz_list_prepend(RzList *list, void *data) {
	rz_return_val_if_fail(list, NULL);

	RzListIter *item = RZ_NEW0(RzListIter);
	if (!item) {
		return NULL;
	}
	if (list->head) {
		list->head->p = item;
	}
	item->data = data;
	item->n = list->head;
	item->p = NULL;
	list->head = item;
	if (!list->tail) {
		list->tail = item;
	}
	list->length++;
	list->sorted = true;
	return item;
}

RZ_API RzListIter *rz_list_insert(RzList *list, int n, void *data) {
	RzListIter *it, *item;
	int i;

	rz_return_val_if_fail(list, NULL);

	if (!list->head || !n) {
		return rz_list_prepend(list, data);
	}
	for (it = list->head, i = 0; it && it->data; it = it->n, i++) {
		if (i == n) {
			item = RZ_NEW(RzListIter);
			if (!item) {
				return NULL;
			}
			item->data = data;
			item->n = it;
			item->p = it->p;
			if (it->p) {
				it->p->n = item;
			}
			it->p = item;
			list->length++;
			list->sorted = true;
			return item;
		}
	}
	return rz_list_append(list, data);
}

RZ_API void *rz_list_pop(RzList *list) {
	void *data = NULL;
	RzListIter *iter;

	rz_return_val_if_fail(list, NULL);

	if (list->tail) {
		iter = list->tail;
		if (list->head == list->tail) {
			list->head = list->tail = NULL;
		} else {
			list->tail = iter->p;
			list->tail->n = NULL;
		}
		data = iter->data;
		free(iter);
		list->length--;
	}
	return data;
}

RZ_API void *rz_list_pop_head(RzList *list) {
	void *data = NULL;

	rz_return_val_if_fail(list, NULL);

	if (list->head) {
		RzListIter *iter = list->head;
		if (list->head == list->tail) {
			list->head = list->tail = NULL;
		} else {
			list->head = iter->n;
			list->head->p = NULL;
		}
		data = iter->data;
		free(iter);
		list->length--;
	}
	return data;
}

RZ_API int rz_list_del_n(RzList *list, int n) {
	RzListIter *it;
	int i;

	rz_return_val_if_fail(list, false);

	for (it = list->head, i = 0; it && it->data; it = it->n, i++) {
		if (i == n) {
			if (!it->p && !it->n) {
				list->head = list->tail = NULL;
			} else if (!it->p) {
				it->n->p = NULL;
				list->head = it->n;
			} else if (!it->n) {
				it->p->n = NULL;
				list->tail = it->p;
			} else {
				it->p->n = it->n;
				it->n->p = it->p;
			}
			free(it);
			list->length--;
			return true;
		}
	}
	return false;
}

RZ_API void *rz_list_get_top(const RzList *list) {
	rz_return_val_if_fail(list, NULL);

	return list->tail ? list->tail->data : NULL;
}

RZ_API void *rz_list_get_bottom(const RzList *list) {
	rz_return_val_if_fail(list, NULL);

	return list->head ? list->head->data : NULL;
}

RZ_API void rz_list_reverse(RzList *list) {
	RzListIter *it, *tmp;

	rz_return_if_fail(list);

	for (it = list->head; it && it->data; it = it->p) {
		tmp = it->p;
		it->p = it->n;
		it->n = tmp;
	}
	tmp = list->head;
	list->head = list->tail;
	list->tail = tmp;
}

RZ_API RzList *rz_list_clone(const RzList *list) {
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

RZ_API RzListIter *rz_list_add_sorted(RzList *list, void *data, RzListComparator cmp) {
	RzListIter *it, *item = NULL;

	rz_return_val_if_fail(list && data && cmp, NULL);

	for (it = list->head; it && it->data && cmp(data, it->data) > 0; it = it->n) {
		;
	}
	if (it) {
		item = RZ_NEW0(RzListIter);
		if (!item) {
			return NULL;
		}
		item->n = it;
		item->p = it->p;
		item->data = data;
		item->n->p = item;
		if (!item->p) {
			list->head = item;
		} else {
			item->p->n = item;
		}
		list->length++;
	} else {
		rz_list_append(list, data);
	}
	list->sorted = true;
	return item;
}

RZ_API int rz_list_set_n(RzList *list, int n, void *p) {
	RzListIter *it;
	int i;

	rz_return_val_if_fail(list, false);
	for (it = list->head, i = 0; it; it = it->n, i++) {
		if (i == n) {
			if (list->free) {
				list->free(it->data);
			}
			it->data = p;
			list->sorted = false;
			return true;
		}
	}
	return false;
}

RZ_API void *rz_list_get_n(const RzList *list, int n) {
	RzListIter *it;
	int i;

	rz_return_val_if_fail(list, NULL);

	for (it = list->head, i = 0; it && it->data; it = it->n, i++) {
		if (i == n) {
			return it->data;
		}
	}
	return NULL;
}

RZ_API RzListIter *rz_list_contains(const RzList *list, const void *p) {
	void *q;
	RzListIter *iter;

	rz_return_val_if_fail(list, NULL);

	rz_list_foreach (list, iter, q) {
		if (p == q) {
			return iter;
		}
	}
	return NULL;
}

RZ_API RzListIter *rz_list_find(const RzList *list, const void *p, RzListComparator cmp) {
	void *q;
	RzListIter *iter;

	rz_return_val_if_fail(list, NULL);

	rz_list_foreach (list, iter, q) {
		if (!cmp(p, q)) {
			return iter;
		}
	}
	return NULL;
}

static RzListIter *_merge(RzListIter *first, RzListIter *second, RzListComparator cmp) {
	RzListIter *next = NULL, *result = NULL, *head = NULL;
	while (first || second) {
		if (!second) {
			next = first;
			first = first->n;
		} else if (!first) {
			next = second;
			second = second->n;
		} else if (cmp(first->data, second->data) <= 0) {
			next = first;
			first = first->n;
		} else {
			next = second;
			second = second->n;
		}
		if (!head) {
			result = next;
			head = result;
			head->p = NULL;
		} else {
			result->n = next;
			next->p = result;
			result = result->n;
		}
	}
	head->p = NULL;
	next->n = NULL;
	return head;
}

static RzListIter *_r_list_half_split(RzListIter *head) {
	RzListIter *tmp;
	RzListIter *fast;
	RzListIter *slow;
	if (!head || !head->n) {
		return head;
	}
	slow = head;
	fast = head;
	while (fast && fast->n && fast->n->n) {
		fast = fast->n->n;
		slow = slow->n;
	}
	tmp = slow->n;
	slow->n = NULL;
	return tmp;
}

static RzListIter *_merge_sort(RzListIter *head, RzListComparator cmp) {
	RzListIter *second;
	if (!head || !head->n) {
		return head;
	}
	second = _r_list_half_split(head);
	head = _merge_sort(head, cmp);
	second = _merge_sort(second, cmp);
	return _merge(head, second, cmp);
}

RZ_API void rz_list_merge_sort(RzList *list, RzListComparator cmp) {
	rz_return_if_fail(list);

	if (!list->sorted && list->head && cmp) {
		RzListIter *iter;
		list->head = _merge_sort(list->head, cmp);
		//update tail reference
		iter = list->head;
		while (iter && iter->n) {
			iter = iter->n;
		}
		list->tail = iter;
	}
	list->sorted = true;
}

RZ_API void rz_list_insertion_sort(RzList *list, RzListComparator cmp) {
	rz_return_if_fail(list);

	if (!list->sorted) {
		RzListIter *it;
		RzListIter *it2;
		if (cmp) {
			for (it = list->head; it && it->data; it = it->n) {
				for (it2 = it->n; it2 && it2->data; it2 = it2->n) {
					if (cmp(it->data, it2->data) > 0) {
						void *t = it->data;
						it->data = it2->data;
						it2->data = t;
					}
				}
			}
		}
		list->sorted = true;
	}
}

//chose wisely based on length
RZ_API void rz_list_sort(RzList *list, RzListComparator cmp) {
	rz_return_if_fail(list);
	if (list->length > 43) {
		rz_list_merge_sort(list, cmp);
	} else {
		rz_list_insertion_sort(list, cmp);
	}
}

RZ_API RzList *rz_list_uniq(const RzList *list, RzListComparator cmp) {
	RzListIter *iter, *iter2;
	void *item, *item2;

	rz_return_val_if_fail(list && cmp, NULL);

	RzList *nl = rz_list_newf(NULL);
	if (!nl) {
		return NULL;
	}
	rz_list_foreach (list, iter, item) {
		bool found = false;
		rz_list_foreach (nl, iter2, item2) {
			if (cmp(item, item2) == 0) {
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
RZ_API char *rz_list_to_str(RzList *list, char ch) {
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

RZ_API RzList *rz_list_of_sdblist(SdbList *sl) {
	RzList *l = rz_list_newf(free);
	SdbKv *kv;
	SdbListIter *iter;
	ls_foreach (sl, iter, kv) {
		rz_list_append(l, strdup(sdbkv_key(kv)));
	}
	return l;
}
