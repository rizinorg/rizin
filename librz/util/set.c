// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2024 pelijah
// SPDX-License-Identifier: MIT

#include <rz_util/rz_set.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_str.h>
#include <rz_list.h>

/**
 * \brief Create a new hash set with C-string as elements.
 * \param opt Defines how elements are stored
 */
RZ_API RZ_OWN RzSetS *rz_set_s_new(HtStrOption opt) {
	return ht_sp_new(opt, NULL, NULL);
}

/**
 * \brief Split the string \p str according to the substring \p c and returns a \p RzSetS with the result.
 *
 * Split a string \p str according to the delimiter specified in \p c. It can
 * optionally trim (aka remove spaces) the tokens. The result is a \p RzSetS with newly allocated strings for each
 * token.
 *
 * \param _str Input string to split
 * \param c Delimiter string used to split \p str
 * \param trim If true each token is considered without trailing/leading whitespaces.
 */
RZ_API RZ_OWN RzSetS *rz_str_split_dupset(RZ_NONNULL const char *_str, RZ_NONNULL const char *c, bool trim) {
	rz_return_val_if_fail(_str && c, NULL);
	RzList *list = rz_str_split_duplist(_str, c, trim);
	if (!list) {
		return NULL;
	}
	RzSetS *set = rz_set_s_new(HT_STR_DUP);
	if (!set) {
		rz_list_free(list);
		return NULL;
	}
	RzListIter *it;
	const char *val;
	rz_list_foreach (list, it, val) {
		rz_set_s_add(set, val);
	}
	rz_list_free(list);
	return set;
}

/**
 * \brief Add element \p str to hash set \p set.
 */
RZ_API void rz_set_s_add(RZ_NONNULL RzSetS *set, const char *str) {
	rz_return_if_fail(set);
	ht_sp_insert(set, str, (void *)1);
}

/**
 * \brief Check if hash set \p set contains element \p str.
 */
RZ_API bool rz_set_s_contains(const RZ_NONNULL RzSetS *set, const char *str) {
	rz_return_val_if_fail(set, false);
	return ht_sp_find((RzSetS *)set, str, NULL) != NULL;
}

/**
 * \brief Add element \p str from hash set \p set.
 */
RZ_API void rz_set_s_delete(RZ_NONNULL RzSetS *set, const char *str) {
	rz_return_if_fail(set);
	ht_sp_delete(set, str);
}

/**
 * \brief Fills \p iter with an iterator over \p set, yielding immutable elements.
 *
 * \param set The set to create the iterator for.
 * \param iter Output parameter, filled with the constructed iterator on success.
 *
 * \return True on success, false on failure.
 */
RZ_API bool rz_set_s_as_iter(const RZ_NONNULL RzSetS *set, RZ_OUT RZ_NONNULL RzIterator *iter) {
	rz_return_val_if_fail(set, false);
	return ht_sp_as_iter_keys((const HtSP *)set, iter);
}

static bool push_to_pvector(void *user, const char *k, RZ_UNUSED const void *v) {
	RzPVector *vec = (RzPVector *)user;
	return !!rz_pvector_push(vec, (void *)k);
}

/**
 * \brief Create a vector from elements of hash set \p set
 *
 * If a hash set owns stored strings the ownership will be transferred.
 */
RZ_API RZ_OWN RzPVector /*<char *>*/ *rz_set_s_to_vector(RZ_NONNULL RzSetS *set) {
	rz_return_val_if_fail(set, NULL);

	RzPVector *vec = rz_pvector_new(set->opt.finiKV ? free : NULL);
	if (!vec || !rz_pvector_reserve(vec, ht_sp_size((HtSP *)set))) {
		rz_pvector_free(vec);
		return NULL;
	}
	ht_sp_foreach(set, push_to_pvector, vec);
	set->opt.finiKV = NULL;
	set->opt.finiKV_user = NULL;
	return vec;
}

RZ_API void rz_set_s_free(RZ_NULLABLE RzSetS *set) {
	ht_sp_free((HtSP *)set);
}

/**
 * \brief Cleans the set.
 */
RZ_API void rz_set_s_clear(RZ_NONNULL RzSetS *set) {
	rz_return_if_fail(set);
	ht_sp_clear(set);
}

/**
 * \brief Return number of elements saved in the set.
 */
RZ_API ut32 rz_set_s_size(const RZ_NULLABLE RzSetS *set) {
	if (!set) {
		return 0;
	}
	return ht_sp_size((HtSP *)set);
}

/**
 * \brief Create a new hash set with ut64 as elements.
 */
RZ_API RZ_OWN RzSetU *rz_set_u_new(void) {
	return (RzSetU *)ht_up_new(NULL, NULL);
}

/**
 * \brief Add element \p u to hash set \p set.
 */
RZ_API void rz_set_u_add(RZ_NONNULL RzSetU *set, ut64 u) {
	rz_return_if_fail(set);
	ht_up_insert(set, u, (void *)1);
}

static bool take_first(void *user, const ut64 k, const void *v) {
	ut64 *out = user;
	*out = k;
	return false;
}

/**
 * \brief Take an element from \p set.
 * The element is removed from it.
 * There is no indicator what element is taken, because a set is unordered.
 *
 * The set must have a size of 1+ elements.
 * Otherwise a warning is printed and it returns UT64_MAX.
 */
RZ_API ut64 rz_set_u_take(RZ_NONNULL RzSetU *set) {
	rz_return_val_if_fail(set, UT64_MAX);
	if (rz_set_u_size(set) == 0) {
		rz_warn_if_reached();
		return UT64_MAX;
	}
	ut64 out = UT64_MAX;
	ht_up_foreach(set, take_first, &out);
	rz_set_u_delete(set, out);
	return out;
}

/**
 * \brief Check if hash set \p set contains element \p u.
 */
RZ_API bool rz_set_u_contains(const RZ_NONNULL RzSetU *set, ut64 u) {
	rz_return_val_if_fail(set, false);
	return ht_up_find((RzSetU *)set, u, NULL) != NULL;
}

/**
 * \brief Delete element \p u from hash set \p set.
 */
RZ_API void rz_set_u_delete(RZ_NONNULL RzSetU *set, ut64 u) {
	rz_return_if_fail(set);
	ht_up_delete(set, u);
}

/**
 * \brief Cleans the set.
 */
RZ_API void rz_set_u_clear(RZ_NONNULL RzSetU *set) {
	rz_return_if_fail(set);
	ht_up_clear(set);
}

RZ_API void rz_set_u_free(RZ_NULLABLE RzSetU *set) {
	ht_up_free((HtUP *)set);
}

/**
 * \brief Return number of elements saved in the set.
 */
RZ_API ut32 rz_set_u_size(const RZ_NONNULL RzSetU *set) {
	rz_return_val_if_fail(set, 0);
	return ht_up_size((HtUP *)set);
}

/**
 * \brief Fills \p iterator with an iterator over the \p set, yielding immutable elements.
 *
 * \param set The set to create the iterator for.
 * \param iterator Output parameter, filled with the constructed iterator on success.
 *
 * \return True on success, false on failure.
 */
RZ_API bool rz_set_u_as_iter(const RZ_NONNULL RzSetU *set, RZ_OUT RZ_NONNULL RzIterator *iterator) {
	rz_return_val_if_fail(set, false);
	return ht_up_as_iter_keys((const HtUP *)set, iterator);
}

/**
 * \brief Determines the union set of all given sets.
 *
 * \param union_set Optional pointer to the set where the union is written to.
 *                  Already existing elements in the set are kept.
 * \param ... The sets to build the union from. They are of type (const RzSetU *).
 *            The list must be terminated by NULL.
 *
 * \return The size of the union set or SZT_MAX in case of error.
 */
RZ_API size_t rz_set_u_union(RZ_OUT RZ_NULLABLE RzSetU *union_set, ...) {
	va_list ap;
	va_start(ap, union_set);

	RzSetU *s = union_set;
	bool created = !s;
	if (!s) {
		s = rz_set_u_new();
		if (!s) {
			va_end(ap);
			rz_warn_if_reached();
			return SZT_MAX;
		}
	}

	bool failed = false;
	for (;;) {
		const RzSetU *cur = va_arg(ap, const RzSetU *);
		if (!cur) {
			break;
		}
		if (cur == s) {
			// Its elements are already part of the union and inserting
			// them would modify the set we are iterating over.
			continue;
		}
		RzIterator it = (RzIterator){ 0 };
		if (!rz_set_u_as_iter(cur, &it)) {
			failed = true;
			rz_warn_if_reached();
			break;
		}
		const ut64 *u;
		rz_iterator_foreach(&it, u) {
			rz_set_u_add(s, *u);
		}
		rz_iterator_fini(&it);
		if (failed) {
			break;
		}
	}
	va_end(ap);

	size_t size = rz_set_u_size(s);
	if (created) {
		rz_set_u_free(s);
	}
	return failed ? SZT_MAX : size;
}

static size_t add_to_difference(const RzSetU *first, RzSetU *diff_set, va_list ap) {
	if (!first) {
		// The list is empty, thus the difference is empty.
		return diff_set ? rz_set_u_size(diff_set) : 0;
	}

	size_t count = 0;
	RzIterator it = (RzIterator){ 0 };
	if (!rz_set_u_as_iter(first, &it)) {
		rz_warn_if_reached();
		return SZT_MAX;
	}
	const ut64 *u;
	rz_iterator_foreach(&it, u) {
		bool in_any = false;
		va_list ap3;
		va_copy(ap3, ap);
		for (const RzSetU *cur = va_arg(ap3, const RzSetU *); cur; cur = va_arg(ap3, const RzSetU *)) {
			if (rz_set_u_contains(cur, *u)) {
				in_any = true;
				break;
			}
		}
		va_end(ap3);
		if (!in_any) {
			count++;
			if (diff_set) {
				rz_set_u_add(diff_set, *u);
			}
		}
	}
	rz_iterator_fini(&it);

	return diff_set ? rz_set_u_size(diff_set) : count;
}

/**
 * \brief Determines the difference set of all given sets.
 *
 * The difference set consists of all elements of the first given set that
 * are not contained in any of the other given sets.
 *
 * \param diff_set Optional pointer to the set where the difference is written to.
 *                 If it is the first of the given sets, it is reduced to the
 *                 difference instead, otherwise the elements of the difference
 *                 are added to it. If it is one of the other given sets, its
 *                 content is replaced by the difference.
 * \param ... The sets to build the difference from. The first set is the one
 *            the other sets are subtracted from. They are of type (const RzSetU *).
 *            The list must be terminated by NULL.
 *
 * \return The size of the difference set or SZT_MAX in case of error.
 *
 * Examples:
 * ```
 * A = {1, 2, 3} B = {2, 3, 4} X = {} Y = {5} Z = {1, 6}
 * rz_set_u_difference(X, A, B);
 * // X = {1}
 * rz_set_u_difference(Y, A, B);
 * // Y = {5, 1}
 * rz_set_u_difference(A, A, B);
 * // A = {1}
 * rz_set_u_difference(Z, A, Z);
 * // Z = {}
 * ```
 */
RZ_API size_t rz_set_u_difference(RZ_OUT RZ_NULLABLE RzSetU *diff_set, ...) {
	va_list ap;
	va_start(ap, diff_set);

	const RzSetU *first = va_arg(ap, const RzSetU *);

	if (diff_set && first == diff_set) {
		// diff_set is the set to subtract from, thus all elements of the
		// difference are already contained in it. Reduce it by deleting
		// every element that is contained in any of the other sets.
		RzIterator it = (RzIterator){ 0 };
		if (!rz_set_u_as_iter(diff_set, &it)) {
			va_end(ap);
			rz_warn_if_reached();
			return SZT_MAX;
		}
		const ut64 *u;
		rz_iterator_foreach(&it, u) {
			va_list ap3;
			va_copy(ap3, ap);
			for (const RzSetU *cur = va_arg(ap3, const RzSetU *); cur; cur = va_arg(ap3, const RzSetU *)) {
				if (rz_set_u_contains(cur, *u)) {
					rz_set_u_delete(diff_set, *u);
					break;
				}
			}
			va_end(ap3);
		}
		rz_iterator_fini(&it);
		va_end(ap);
		return rz_set_u_size(diff_set);
	}

	// Check whether diff_set is one of the sets to subtract.
	bool diff_in_rest = false;
	va_list ap2;
	va_copy(ap2, ap);
	for (const RzSetU *cur = va_arg(ap2, const RzSetU *); cur; cur = va_arg(ap2, const RzSetU *)) {
		if (cur == diff_set) {
			diff_in_rest = true;
			break;
		}
	}
	va_end(ap2);

	if (diff_set && diff_in_rest) {
		// diff_set is one of the sets to subtract, thus its previous content
		// is not part of the difference. Determine the difference in a
		// temporary set and replace the content of diff_set with it.
		RzSetU *tmp = rz_set_u_new();
		if (!tmp) {
			va_end(ap);
			rz_warn_if_reached();
			return SZT_MAX;
		}
		bool failed = add_to_difference(first, tmp, ap) == SZT_MAX;
		if (!failed) {
			rz_set_u_clear(diff_set);
			RzIterator it = (RzIterator){ 0 };
			if (rz_set_u_as_iter(tmp, &it)) {
				const ut64 *u;
				rz_iterator_foreach(&it, u) {
					rz_set_u_add(diff_set, *u);
				}
				rz_iterator_fini(&it);
			} else {
				failed = true;
				rz_warn_if_reached();
			}
		}
		rz_set_u_free(tmp);
		va_end(ap);
		return failed ? SZT_MAX : rz_set_u_size(diff_set);
	}

	size_t size = add_to_difference(first, diff_set, ap);
	va_end(ap);
	return size;
}

static size_t add_to_intersection(const RzSetU *smallest, RzSetU *inter_set, va_list ap) {
	bool failed = false;
	size_t count = 0;
	if (!smallest) {
		// The list is empty, thus the intersection is empty.
		return inter_set ? rz_set_u_size(inter_set) : 0;
	}

	RzIterator it = (RzIterator){ 0 };
	if (!rz_set_u_as_iter(smallest, &it)) {
		rz_warn_if_reached();
		return SZT_MAX;
	}
	const ut64 *u;
	rz_iterator_foreach(&it, u) {
		bool in_all = true;
		va_list ap3;
		va_copy(ap3, ap);
		for (const RzSetU *cur = va_arg(ap3, const RzSetU *); cur; cur = va_arg(ap3, const RzSetU *)) {
			if (cur == smallest) {
				continue;
			}
			if (!rz_set_u_contains(cur, *u)) {
				in_all = false;
				break;
			}
		}
		va_end(ap3);
		if (!in_all) {
			continue;
		}
		count++;
		if (inter_set) {
			rz_set_u_add(inter_set, *u);
		}
	}
	rz_iterator_fini(&it);

	size_t size = inter_set ? rz_set_u_size(inter_set) : count;
	return failed ? SZT_MAX : size;
}

/**
 * \brief Determines the intersection set of all given sets.
 *
 * \param inter_set Optional pointer to the set where the intersection is added to.
 *                  If it is one of the given sets, it is reduced to the
 *                  intersection instead, otherwise the elements of the
 *                  intersection are added to it.
 * \param ... The sets to build the intersection from. They are of type (const RzSetU *).
 *            The list must be terminated by NULL.
 *
 * \return The size of the intersection set or SZT_MAX in case of error.
 */
RZ_API size_t rz_set_u_intersection(RZ_OUT RZ_NULLABLE RzSetU *inter_set, ...) {
	va_list ap;
	va_start(ap, inter_set);

	// Find the smallest set as candidate source and check whether inter_set
	// is one of the given sets.
	bool inter_in_list = false;
	const RzSetU *smallest = NULL;
	va_list ap2;
	va_copy(ap2, ap);
	for (const RzSetU *cur = va_arg(ap2, const RzSetU *); cur; cur = va_arg(ap2, const RzSetU *)) {
		if (cur == inter_set) {
			inter_in_list = true;
		}
		if (!smallest || rz_set_u_size(cur) < rz_set_u_size(smallest)) {
			smallest = cur;
		}
	}
	va_end(ap2);

	if (!inter_in_list) {
		// inter_set is not one of the given sets, thus the elements of the
		// intersection are added to it.
		size_t s = add_to_intersection(smallest, inter_set, ap);
		va_end(ap);
		return s;
	}

	// inter_set is one of the given sets, thus all elements of the
	// intersection are already contained in it. Reduce it by deleting
	// every element that is not part of the intersection.
	RzIterator it = (RzIterator){ 0 };
	if (!rz_set_u_as_iter(inter_set, &it)) {
		va_end(ap);
		rz_warn_if_reached();
		return SZT_MAX;
	}
	const ut64 *u;
	rz_iterator_foreach(&it, u) {
		bool in_all = true;
		va_list ap3;
		va_copy(ap3, ap);
		for (const RzSetU *cur = va_arg(ap3, const RzSetU *); cur; cur = va_arg(ap3, const RzSetU *)) {
			if (cur == inter_set) {
				continue;
			}
			if (!rz_set_u_contains(cur, *u)) {
				in_all = false;
				break;
			}
		}
		va_end(ap3);
		if (!in_all) {
			rz_set_u_delete(inter_set, *u);
		}
	}
	rz_iterator_fini(&it);
	va_end(ap);
	return rz_set_u_size(inter_set);
}
