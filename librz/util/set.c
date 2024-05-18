// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2024 pelijah
// SPDX-License-Identifier: MIT

#include <rz_util/rz_set.h>
#include <rz_util/rz_assert.h>

/**
 * \brief Create a new hash set with C-string as elements.
 * \param opt Defines how elements are stored
 */
RZ_API RZ_OWN RzSetS *rz_set_s_new(HtStrOption opt) {
	return ht_sp_new(opt, NULL, NULL);
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
RZ_API bool rz_set_s_contains(RZ_NONNULL RzSetS *set, const char *str) {
	rz_return_val_if_fail(set, false);
	return ht_sp_find(set, str, NULL) != NULL;
}

/**
 * \brief Add element \p str from hash set \p set.
 */
RZ_API void rz_set_s_delete(RZ_NONNULL RzSetS *set, const char *str) {
	rz_return_if_fail(set);
	ht_sp_delete(set, str);
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
	if (!vec || !rz_pvector_reserve(vec, set->count)) {
		rz_pvector_free(vec);
		return NULL;
	}
	ht_sp_foreach_cb(set, push_to_pvector, vec);
	set->opt.finiKV = NULL;
	set->opt.finiKV_user = NULL;
	return vec;
}

RZ_API void set_s_free(RZ_NULLABLE RzSetS *set) {
	ht_sp_free((HtSP *)set);
}

/**
 * \brief Return number of elements saved in the set.
 */
RZ_API ut32 rz_set_s_size(RZ_NULLABLE RzSetS *set) {
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

/**
 * \brief Check if hash set \p set contains element \p u.
 */
RZ_API bool rz_set_u_contains(RZ_NONNULL RzSetU *set, ut64 u) {
	rz_return_val_if_fail(set, false);
	return ht_up_find(set, u, NULL) != NULL;
}

/**
 * \brief Delete element \p u from hash set \p set.
 */
RZ_API void rz_set_u_delete(RZ_NONNULL RzSetU *set, ut64 u) {
	rz_return_if_fail(set);
	ht_up_delete(set, u);
}

RZ_API void rz_set_u_free(RZ_NULLABLE RzSetU *set) {
	ht_up_free((HtUP *)set);
}

/**
 * \brief Return number of elements saved in the set.
 */
RZ_API ut32 rz_set_u_size(RZ_NULLABLE RzSetU *set) {
	return ht_up_size((HtUP *)set);
}
