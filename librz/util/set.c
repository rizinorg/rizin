// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2024 pelijah
// SPDX-License-Identifier: MIT

#include <rz_util/set.h>
#include <rz_util/rz_assert.h>

/**
 * \brief Create a new hash set with C-string as elements.
 * \param opt Defines how elements are stored
 */
RZ_API RZ_OWN SetS *set_s_new(HtStrOption opt) {
	return ht_sp_new(opt, NULL, NULL);
}

/**
 * \brief Add element \p str to hash set \p set.
 */
RZ_API void set_s_add(RZ_NONNULL SetS *set, const char *str) {
	rz_return_if_fail(set);
	ht_sp_insert(set, str, (void *)1);
}

/**
 * \brief Check if hash set \p set contains element \p str.
 */
RZ_API bool set_s_contains(RZ_NONNULL SetS *set, const char *str) {
	rz_return_val_if_fail(set, false);
	return ht_sp_find(set, str, NULL) != NULL;
}

/**
 * \brief Add element \p str from hash set \p set.
 */
RZ_API void set_s_delete(RZ_NONNULL SetS *set, const char *str) {
	rz_return_if_fail(set);
	ht_sp_delete(set, str);
}

RZ_API void set_s_free(RZ_NULLABLE SetS *set) {
	ht_sp_free((HtSP *)set);
}

/**
 * \brief Create a new hash set with ut64 as elements.
 */
RZ_API RZ_OWN SetU *set_u_new(void) {
	return (SetU *)ht_up_new(NULL, NULL);
}

/**
 * \brief Add element \p u to hash set \p set.
 */
RZ_API void set_u_add(RZ_NONNULL SetU *set, ut64 u) {
	rz_return_if_fail(set);
	ht_up_insert(set, u, (void *)1);
}

/**
 * \brief Get the size of set \s.
 */
RZ_API ut64 set_u_size(SetU *s) {
	rz_return_val_if_fail(s, 0);
	return s->count;
}

/**
 * \brief Check if hash set \p set contains element \p u.
 */
RZ_API bool set_u_contains(RZ_NONNULL SetU *set, ut64 u) {
	rz_return_val_if_fail(set, false);
	return ht_up_find(set, u, NULL) != NULL;
}

/**
 * \brief Delete element \p u from hash set \p set.
 */
RZ_API void set_u_delete(RZ_NONNULL SetU *set, ut64 u) {
	rz_return_if_fail(set);
	ht_up_delete(set, u);
}

RZ_API void set_u_free(RZ_NULLABLE SetU *set) {
	ht_up_free((HtUP *)set);
}

RZ_API void advance_set_u_iter(SetU *s, SetUIter *it) {
	if (it->ti >= s->size) {
		it->ti++;
		return;
	}
	for (; it->ti < s->size; it->ti++) {
		if (s->table[it->ti].count == 0) {
			continue;
		}
		for (; it->bi < s->table[it->ti].count;) {
			it->v = s->table[it->ti].arr[it->bi].key;
			it->bi++;
			return;
		}
		it->bi = 0;
	}
	it->ti++;
}
