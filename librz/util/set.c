// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#include <rz_util/rz_assert.h>
#include <rz_util/set.h>

// p

RZ_API SetP *set_p_new(void) {
	return ht_pp_new0();
}

RZ_API void set_p_add(SetP *s, const void *u) {
	ht_pp_insert(s, u, (void *)1);
}

RZ_API bool set_p_contains(SetP *s, const void *u) {
	return ht_pp_find(s, u, NULL) != NULL;
}

RZ_API void set_p_delete(SetP *s, const void *u) {
	ht_pp_delete(s, u);
}

RZ_API void set_p_free(SetP *p) {
	ht_pp_free((HtPP *)p);
}

// u

RZ_API SetU *set_u_new(void) {
	return (SetU *)ht_uu_new0();
}

RZ_API void set_u_add(SetU *s, ut64 u) {
	ht_uu_insert(s, u, 1);
}

RZ_API ut64 set_u_size(SetU *s) {
	rz_return_val_if_fail(s, 0);
	return s->count;
}

RZ_API bool set_u_contains(SetU *s, ut64 u) {
	bool found = false;
	ht_uu_find(s, u, &found);
	return found;
}

RZ_API void set_u_delete(SetU *s, ut64 u) {
	ht_uu_delete(s, u);
}

RZ_API void set_u_free(SetU *s) {
	ht_uu_free(s);
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
