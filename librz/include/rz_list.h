#ifndef RZ_LIST_H
#define RZ_LIST_H

#include <rz_types.h>
#include <ht_pp.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*RzListFree)(void *ptr);

typedef struct rz_list_iter_t {
	void *data;
	struct rz_list_iter_t *n, *p;
} RzListIter;

typedef struct rz_list_t {
	RzListIter *head;
	RzListIter *tail;
	RzListFree free;
	ut32 length;
	bool sorted;
} RzList;

typedef struct rz_list_range_t {
	HtPP *h;
	RzList *l;
	// RzListComparator c;
} RzListRange;

// RzListComparator should return -1, 0, 1 to indicate "value < list_data", "value == list_data", "value > list_data".
typedef int (*RzListComparator)(const void *value, const void *list_data);

#ifdef RZ_API

#define rz_list_foreach(list, it, pos) \
	if (list) \
		for (it = list->head; it && (pos = it->data, 1); it = it->n)
#define rz_list_foreach_iter(list, it) \
	if (list) \
		for (it = list->head; it; it = it->n)
/* Safe when calling rz_list_delete() while iterating over the list. */
#define rz_list_foreach_safe(list, it, tmp, pos) \
	if (list) \
		for (it = list->head; it && (pos = it->data, tmp = it->n, 1); it = tmp)
#define rz_list_foreach_prev(list, it, pos) \
	if (list) \
		for (it = list->tail; it && (pos = it->data, 1); it = it->p)
#define rz_list_foreach_prev_safe(list, it, tmp, pos) \
	for (it = list->tail; it && (pos = it->data, tmp = it->p, 1); it = tmp)

#define rz_list_empty(x) (!(x) || !(x)->length)
#define rz_list_head(x)  ((x) ? (x)->head : NULL)
#define rz_list_tail(x)  ((x) ? (x)->tail : NULL)

#define rz_list_iter_get(x) \
	x->data; \
	x = x->n
#define rz_list_iter_next(x) (x ? 1 : 0)
#define rz_list_iter_cur(x)  x->p

RZ_API RZ_OWN RzList *rz_list_new(void);
RZ_API RZ_OWN RzList *rz_list_newf(RzListFree f);
RZ_API RZ_OWN RzList *rz_list_new_from_array(RZ_NONNULL const void **arr, size_t arr_size);
RZ_API RZ_BORROW RzListIter *rz_list_iter_get_next(RzListIter *iter);
RZ_API RZ_BORROW void *rz_list_iter_get_next_data(RzListIter *iter);
RZ_API ut32 rz_list_set_n(RZ_NONNULL RzList *list, ut32 n, void *p);
RZ_API void *rz_list_iter_get_data(RzListIter *iter);
RZ_API RZ_BORROW RzListIter *rz_list_append(RZ_NONNULL RzList *list, void *data);
RZ_API RZ_BORROW RzListIter *rz_list_prepend(RZ_NONNULL RzList *list, void *data);
RZ_API RZ_BORROW RzListIter *rz_list_insert(RZ_NONNULL RzList *list, ut32 n, void *data);
RZ_API ut32 rz_list_length(RZ_NONNULL const RzList *list);
RZ_API RZ_BORROW void *rz_list_first(RZ_NONNULL const RzList *list);
RZ_API RZ_BORROW void *rz_list_last(RZ_NONNULL const RzList *list);
RZ_API RZ_BORROW RzListIter *rz_list_add_sorted(RZ_NONNULL RzList *list, void *data, RZ_NONNULL RzListComparator cmp);
RZ_API void rz_list_sort(RZ_NONNULL RzList *list, RZ_NONNULL RzListComparator cmp);
RZ_API void rz_list_merge_sort(RZ_NONNULL RzList *list, RZ_NONNULL RzListComparator cmp);
RZ_API void rz_list_insertion_sort(RZ_NONNULL RzList *list, RZ_NONNULL RzListComparator cmp);
RZ_API RZ_OWN RzList *rz_list_uniq(RZ_NONNULL const RzList *list, RZ_NONNULL RzListComparator cmp);
RZ_API void rz_list_init(RZ_NONNULL RzList *list);
RZ_API void rz_list_delete(RZ_NONNULL RzList *list, RZ_NONNULL RzListIter *iter);
RZ_API bool rz_list_delete_data(RZ_NONNULL RzList *list, void *ptr);
RZ_API void rz_list_purge(RZ_NONNULL RzList *list);
RZ_API void rz_list_free(RzList *list);
RZ_API RZ_OWN RzListIter *rz_list_item_new(void *data);
RZ_API void rz_list_split(RZ_NONNULL RzList *list, void *ptr);
RZ_API void rz_list_split_iter(RZ_NONNULL RzList *list, RZ_NONNULL RzListIter *iter);
RZ_API bool rz_list_join(RZ_NONNULL RzList *list1, RZ_NONNULL RzList *list2);
RZ_API RZ_BORROW void *rz_list_get_n(RZ_NONNULL const RzList *list, ut32 n);
RZ_API ut32 rz_list_del_n(RZ_NONNULL RzList *list, ut32 n);
RZ_API RZ_BORROW void *rz_list_get_top(RZ_NONNULL const RzList *list);
RZ_API RZ_BORROW void *rz_list_get_bottom(RZ_NONNULL const RzList *list);
RZ_API RZ_BORROW RzListIter *rz_list_iterator(const RzList *list);
RZ_API RZ_BORROW RzListIter *rz_list_push(RZ_NONNULL RzList *list, void *item);
RZ_API RZ_OWN void *rz_list_pop(RZ_NONNULL RzList *list);
RZ_API RZ_OWN void *rz_list_pop_head(RZ_NONNULL RzList *list);
RZ_API void rz_list_reverse(RZ_NONNULL RzList *list);
RZ_API RZ_OWN RzList *rz_list_clone(RZ_NONNULL const RzList *list);
RZ_API RZ_OWN char *rz_list_to_str(RZ_NONNULL RzList *list, char ch);
RZ_API RZ_OWN RzList *rz_list_of_sdblist(SdbList *sl);

/* hashlike api */
RZ_API RZ_BORROW RzListIter *rz_list_contains(RZ_NONNULL const RzList *list, RZ_NONNULL const void *ptr);
RZ_API RZ_BORROW RzListIter *rz_list_find_ptr(RZ_NONNULL const RzList *list, RZ_NONNULL const void *ptr);
RZ_API RZ_BORROW RzListIter *rz_list_find(RZ_NONNULL const RzList *list, const void *p, RZ_NONNULL RzListComparator cmp);

#ifdef __cplusplus
}
#endif

#endif
#endif
