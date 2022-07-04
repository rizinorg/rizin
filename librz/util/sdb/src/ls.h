// SPDX-FileCopyrightText: pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#ifndef LS_H
#define LS_H

#include <stdio.h>
#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*SdbListFree)(void *ptr);
typedef int (*SdbListComparator)(const void *a, const void *b);

typedef struct ls_iter_t {
	void *data;
	struct ls_iter_t *n, *p;
} SdbListIter;

typedef struct ls_t {
	size_t length;
	SdbListIter *head;
	SdbListIter *tail;
	SdbListFree free;
	SdbListComparator cmp;
	bool sorted;
} SdbList;

#define ls_foreach(list, it, pos) \
	if ((list)) \
		for (it = (list)->head; it && (pos = it->data); it = it->n)
#define ls_foreach_safe(list, it, tmp, pos) \
	if ((list)) \
		for (it = list->head; \
			it && (pos = it->data) && ((tmp = it->n) || 1); it = tmp)
#define ls_foreach_prev(list, it, pos) \
	if ((list)) \
		for (it = list->tail; it && (pos = it->data); it = it->p)

#define ls_iterator(x) (x) ? (x)->head : NULL
// #define ls_empty(x) (!x || (!x->head && !x->tail))
#define ls_empty(x) (!x || !x->length)
#define ls_head(x)  x->head
#define ls_tail(x)  x->tail
#define ls_unref(x) x
#define ls_iter_get(x) \
	x->data; \
	x = x->n
#define ls_iter_next(x)  (x ? 1 : 0)
#define ls_iter_cur(x)   x->p
#define ls_iter_unref(x) x
#define ls_length(x)     x->length
RZ_API SdbList *ls_new(void);
RZ_API SdbList *ls_newf(SdbListFree freefn);
RZ_API SdbListIter *ls_append(SdbList *list, void *data);
RZ_API SdbListIter *ls_prepend(SdbList *list, void *data);
// RZ_API void ls_add_sorted(SdbList *list, void *data, SdbListComparator cmp);
RZ_API bool ls_sort(SdbList *list, SdbListComparator cmp);
RZ_API bool ls_merge_sort(SdbList *list, SdbListComparator cmp);

RZ_API void ls_delete(SdbList *list, SdbListIter *iter);
RZ_API bool ls_delete_data(SdbList *list, void *ptr);
RZ_API void ls_iter_init(SdbListIter *iter, SdbList *list);
RZ_API void ls_destroy(SdbList *list);
RZ_API void ls_free(SdbList *list);
RZ_API SdbListIter *ls_item_new(void *data);
RZ_API void ls_unlink(SdbList *list, void *ptr);
RZ_API void ls_split(SdbList *list, void *ptr);
// Removes element `iter` from `list`.
RZ_API void ls_split_iter(SdbList *list, SdbListIter *iter);
RZ_API void *ls_get_n(SdbList *list, int n);
RZ_API void *ls_get_top(SdbList *list);
#define ls_push(x, y) ls_append(x, y)
RZ_API void *ls_pop(SdbList *list);
RZ_API void ls_reverse(SdbList *list);
RZ_API SdbList *ls_clone(SdbList *list);
RZ_API int ls_join(SdbList *first, SdbList *second);
RZ_API int ls_del_n(SdbList *list, int n);
RZ_API SdbListIter *ls_insert(SdbList *list, int n, void *data);
RZ_API void *ls_pop_head(SdbList *list);

#ifdef __cplusplus
}
#endif

#endif
