#ifndef RZ_LIST_H
#define RZ_LIST_H

#include <rz_types.h>
#include <rz_flist.h>
#include <sdb.h>
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
	//RzListComparator c;
} RzListRange;

// RzListComparator should return -1, 0, 1 to indicate "value < list_data", "value == list_data", "value > list_data".
typedef int (*RzListComparator)(const void *value, const void *list_data);

#define ROFList_Parent RzList
typedef struct rz_oflist_t {
	ROFList_Parent super; // super class
	RFList *array; // statical readonly cache of linked list as a pointer array
} ROFList;
#endif

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

RZ_API RzList *rz_list_new(void);
RZ_API RzList *rz_list_newf(RzListFree f);
RZ_API RzList *rz_list_new_from_array(const void **arr, size_t arr_size);
RZ_API RzListIter *rz_list_iter_get_next(RzListIter *list);
RZ_API ut32 rz_list_set_n(RzList *list, ut32 n, void *p);
RZ_API void *rz_list_iter_get_data(RzListIter *list);
RZ_API RzListIter *rz_list_append(RzList *list, void *data);
RZ_API RzListIter *rz_list_prepend(RzList *list, void *data);
RZ_API RzListIter *rz_list_insert(RzList *list, ut32 n, void *data);
RZ_API ut32 rz_list_length(const RzList *list);
RZ_API void *rz_list_first(const RzList *list);
RZ_API void *rz_list_last(const RzList *list);
RZ_API RzListIter *rz_list_add_sorted(RzList *list, void *data, RzListComparator cmp);
RZ_API void rz_list_sort(RzList *list, RzListComparator cmp);
RZ_API void rz_list_merge_sort(RzList *list, RzListComparator cmp);
RZ_API void rz_list_insertion_sort(RzList *list, RzListComparator cmp);
RZ_API RzList *rz_list_uniq(const RzList *list, RzListComparator cmp);
RZ_API void rz_list_init(RzList *list);
RZ_API void rz_list_delete(RzList *list, RzListIter *iter);
RZ_API bool rz_list_delete_data(RzList *list, void *ptr);
RZ_API void rz_list_iter_init(RzListIter *iter, RzList *list);
RZ_API void rz_list_purge(RzList *list);
RZ_API void rz_list_free(RzList *list);
RZ_API RzListIter *rz_list_item_new(void *data);
RZ_API void rz_list_split(RzList *list, void *ptr);
RZ_API void rz_list_split_iter(RzList *list, RzListIter *iter);
RZ_API bool rz_list_join(RzList *list1, RzList *list2);
RZ_API void *rz_list_get_n(const RzList *list, ut32 n);
RZ_API ut32 rz_list_del_n(RzList *list, ut32 n);
RZ_API void *rz_list_get_top(const RzList *list);
RZ_API void *rz_list_get_bottom(const RzList *list);
RZ_API RzListIter *rz_list_iterator(const RzList *list);
RZ_API RzListIter *rz_list_push(RzList *list, void *item);
RZ_API void *rz_list_pop(RzList *list);
RZ_API void *rz_list_pop_head(RzList *list);
RZ_API void rz_list_reverse(RzList *list);
RZ_API RzList *rz_list_clone(const RzList *list);
RZ_API char *rz_list_to_str(RzList *list, char ch);
RZ_API RzList *rz_list_of_sdblist(SdbList *sl);

/* hashlike api */
RZ_API RzListIter *rz_list_contains(const RzList *list, const void *p);
RZ_API RzListIter *rz_list_find_ptr(RzList *list, void *ptr);
RZ_API RzListIter *rz_list_find(const RzList *list, const void *p, RzListComparator cmp);

#ifdef __cplusplus
}
#endif

#endif
