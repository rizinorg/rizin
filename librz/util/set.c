// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#include <rz_util/set.h>

// s

RZ_API SetS *set_s_new(HtStrOption opt) {
	return ht_sp_new(opt, NULL, NULL);
}

RZ_API void set_s_add(SetS *s, const char *str) {
	ht_sp_insert(s, str, (void *)1);
}

RZ_API bool set_s_contains(SetS *s, const char *str) {
	return ht_sp_find(s, str, NULL) != NULL;
}

RZ_API void set_s_delete(SetS *s, const char *str) {
	ht_sp_delete(s, str);
}

RZ_API void set_s_free(SetS *s) {
	ht_sp_free((HtSP *)s);
}

// u

RZ_API SetU *set_u_new(void) {
	return (SetU *)ht_up_new(NULL, NULL);
}

RZ_API void set_u_add(SetU *s, ut64 u) {
	ht_up_insert(s, u, (void *)1);
}

RZ_API bool set_u_contains(SetU *s, ut64 u) {
	return ht_up_find(s, u, NULL) != NULL;
}

RZ_API void set_u_delete(SetU *s, ut64 u) {
	ht_up_delete(s, u);
}

RZ_API void set_u_free(SetU *s) {
	ht_up_free(s);
}
