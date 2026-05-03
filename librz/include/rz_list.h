#ifndef RZ_LIST_H
#define RZ_LIST_H

#include <rz_util/rz_iterator.h>
#include <rz_vector.h>
#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*RzListFree)(void *ptr);

typedef struct rz_list_iter_t RzListIter;

struct rz_list_iter_t {
	void *val;
	RzListIter *next;
	RzListIter *prev;
};

typedef struct rz_list_slab_t RzListSlab;

typedef struct rz_list_t {
	RzListIter *head; ///< List head/first element.
	RzListIter *tail; ///< List tail/last element.
	RzListSlab *slab; ///< Owner of all the elements.
	RzListIter *unused; ///< List of nodes recently freed.
	RzListFree free; ///< Free function to call when an element is removed from the list.
	bool sorted; ///< When true, the list is sorted.
	size_t length; ///< Number of elements in list.
} RzList;

// RzListComparator should return -1, 0, 1 to indicate "value < list_data", "value == list_data", "value > list_data".
typedef int (*RzListComparator)(const void *value, const void *list_data, void *user);

#ifdef RZ_API

#define rz_list_foreach(list, it, var) \
	if (list) \
		for (it = list->head; it && (var = it->val, 1); it = it->next)
#define rz_list_foreach_enum(list, it, var, i) \
	if (list) \
		for (it = list->head, i = 0; it && (var = it->val, 1); it = it->next, ++i)
#define rz_list_foreach_iter(iter, it, var) \
	for (it = iter; it && (var = it->val, 1); it = it->next)
/* Safe when calling rz_list_delete() while iterating over the list. */
#define rz_list_foreach_safe(list, it, tmp, var) \
	if (list) \
		for (it = list->head; it && (var = it->val, tmp = it->next, 1); it = tmp)
#define rz_list_foreach_iter_safe(iter, it, tmp, var) \
	for (it = iter; it && (var = it->val, tmp = it->next, 1); it = tmp)
#define rz_list_foreach_prev(list, it, var) \
	if (list) \
		for (it = list->tail; it && (var = it->val, 1); it = it->prev)
#define rz_list_foreach_prev_safe(list, it, tmp, var) \
	for (it = list->tail; it && (var = it->val, tmp = it->prev, 1); it = tmp)

#define rz_list_empty(list) (rz_list_length(list) < 1)

static inline RZ_BORROW RzListIter *rz_list_head(RZ_NULLABLE const RzList *list) {
	return list ? list->head : NULL;
}

static inline RZ_BORROW RzListIter *rz_list_tail(RZ_NULLABLE const RzList *list) {
	return list ? list->tail : NULL;
}

static inline RZ_BORROW RzListIter *rz_list_prev(RZ_NONNULL const RzListIter *iter) {
	return iter->prev;
}

static inline RZ_BORROW RzListIter *rz_list_next(RZ_NONNULL const RzListIter *iter) {
	return iter->next;
}

static inline RZ_BORROW void *rz_list_val(RZ_NONNULL const RzListIter *iter) {
	return iter->val;
}

static inline void rz_list_set_val(RZ_NONNULL RzListIter *iter, RZ_NULLABLE void *val) {
	iter->val = val;
}

static inline bool rz_list_has_prev(RZ_NONNULL const RzListIter *iter) {
	return iter->prev != NULL;
}

static inline bool rz_list_has_next(RZ_NONNULL const RzListIter *iter) {
	return iter->next != NULL;
}

RZ_API RZ_OWN RzList *rz_list_new(void);
RZ_API RZ_OWN RzList *rz_list_newf(RZ_NULLABLE RzListFree f);
RZ_API RZ_OWN RzList *rz_list_new_from_array(const void **arr, size_t arr_size);
RZ_API RZ_OWN RzList *rz_list_new_from_iterator(RZ_BORROW RZ_NONNULL RzIterator *iter);
RZ_API void rz_list_set_free(RZ_NONNULL RzList *list, RZ_NULLABLE RzListFree f);
RZ_API RzListFree rz_list_get_free(RZ_NONNULL RzList *list);
RZ_API RZ_BORROW void *rz_list_iter_get_prev_data(RZ_NONNULL RzListIter *iter);
RZ_API RZ_BORROW void *rz_list_iter_get_next_data(RZ_NONNULL RzListIter *iter);
RZ_API ut32 rz_list_set_n(RZ_NONNULL RzList *list, ut32 n, RZ_NONNULL void *data);
RZ_API bool rz_list_iter_swap_data(RZ_NONNULL RzListIter *iter0, RZ_NONNULL RzListIter *iter1);
RZ_API RZ_BORROW RzListIter *rz_list_append(RZ_NONNULL RzList *list, RZ_NONNULL void *data);
RZ_API RZ_BORROW RzListIter *rz_list_prepend(RZ_NONNULL RzList *list, RZ_NONNULL void *data);
RZ_API RZ_BORROW RzListIter *rz_list_insert(RZ_NONNULL RzList *list, ut32 n, RZ_NONNULL void *data);
RZ_API ut32 rz_list_length(RZ_NONNULL const RzList *list);
RZ_API RZ_BORROW void *rz_list_first_val(RZ_NONNULL const RzList *list);
RZ_API RZ_BORROW void *rz_list_last_val(RZ_NONNULL const RzList *list);
RZ_API RZ_BORROW RzListIter *rz_list_add_sorted(RZ_NONNULL RzList *list, RZ_NONNULL void *data, RZ_NONNULL RzListComparator cmp, void *user);
RZ_API void rz_list_sort(RZ_NONNULL RzList *list, RZ_NONNULL RzListComparator cmp, void *user);
RZ_API void rz_list_merge_sort(RZ_NONNULL RzList *list, RZ_NONNULL RzListComparator cmp, void *user);
RZ_API void rz_list_insertion_sort(RZ_NONNULL RzList *list, RZ_NONNULL RzListComparator cmp, void *user);
RZ_API RZ_OWN RzList *rz_list_uniq(RZ_NONNULL const RzList *list, RZ_NONNULL RzListComparator cmp, void *user);
RZ_API void rz_list_sorted_uniq(RZ_NONNULL RzList *list, RZ_NONNULL RzListComparator cmp, void *user);
RZ_API void rz_list_delete(RZ_NONNULL RzList *list, RZ_OWN RZ_NONNULL RzListIter *iter);
RZ_API bool rz_list_delete_val(RZ_NONNULL RzList *list, void *val);
RZ_API void rz_list_purge(RZ_NONNULL RzList *list);
RZ_API void rz_list_free(RZ_NULLABLE RzList *list);
RZ_API bool rz_list_join(RZ_NONNULL RzList *dst_list, RZ_NONNULL RzList *src_list);
RZ_API RZ_BORROW void *rz_list_get_n(RZ_NONNULL const RzList *list, ut32 n);
RZ_API ut32 rz_list_del_n(RZ_NONNULL RzList *list, ut32 n);
RZ_API RZ_BORROW RzListIter *rz_list_iterator(RZ_NONNULL const RzList *list);
RZ_API RZ_OWN void *rz_list_pop(RZ_NONNULL RzList *list);
RZ_API RZ_OWN void *rz_list_pop_head(RZ_NONNULL RzList *list);
RZ_API void rz_list_reverse(RZ_NONNULL RzList *list);
RZ_API RZ_OWN RzList *rz_list_clone(RZ_NONNULL const RzList *list);
RZ_API RZ_OWN char *rz_list_to_str(RZ_NONNULL RzList /*<const char *>*/ *list, char ch, bool append_last);

#define rz_list_push rz_list_append

/* hashlike api */
RZ_API RZ_BORROW bool rz_list_contains(RZ_NONNULL const RzList *list, RZ_NONNULL const void *val);
RZ_API RZ_BORROW RzListIter *rz_list_find_val(RZ_NONNULL const RzList *list, RZ_NONNULL const void *val);
RZ_API RZ_BORROW RzListIter *rz_list_find(RZ_NONNULL const RzList *list, const void *val, RZ_NONNULL RzListComparator cmp, void *user);

#ifdef __cplusplus
}
#endif

#endif
#endif
