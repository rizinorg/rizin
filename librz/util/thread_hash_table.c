// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_th.h>
#include <rz_util.h>

#define th_ht_type(name) struct rz_th_##name##_t
#define th_ht_struct(name, type) \
	th_ht_type(name) { \
		type *table; \
		RzThreadLock *lock; \
	};

#define th_ht_free(name, v) rz_th_##name##_free(v)
#define th_ht_free_decl(name) \
	RZ_API void rz_th_##name##_free(th_ht_type(name) * ht) { \
		if (!ht) { \
			return; \
		} \
		name##_free(ht->table); \
		rz_th_lock_free(ht->lock); \
		free(ht); \
	}

#define th_ht_new_decl(name, type) \
	RZ_API th_ht_type(name) * rz_th_##name##_new(type *table) { \
		rz_return_val_if_fail(table, NULL); \
		th_ht_type(name) *ht = RZ_NEW0(th_ht_type(name)); \
		if (!ht) { \
			return NULL; \
		} \
		ht->lock = rz_th_lock_new(true); \
		if (!ht->lock) { \
			free(ht); \
			return NULL; \
		} \
		ht->table = table; \
		return ht; \
	}

#define th_ht_kv_op_decl(name, op, ktype, vtype) \
	RZ_API bool rz_th_##name##_##op(th_ht_type(name) * ht, ktype key, vtype value) { \
		rz_return_val_if_fail(ht && ht->table, false); \
		rz_th_lock_enter(ht->lock); \
		bool ret = name##_##op(ht->table, key, value, NULL); \
		rz_th_lock_leave(ht->lock); \
		return ret; \
	}

#define th_ht_delete_decl(name, ktype) \
	RZ_API bool rz_th_##name##_delete(th_ht_type(name) * ht, const ktype key) { \
		rz_return_val_if_fail(ht && ht->table, false); \
		rz_th_lock_enter(ht->lock); \
		bool ret = name##_delete(ht->table, key); \
		rz_th_lock_leave(ht->lock); \
		return ret; \
	}

#define th_ht_find_decl(name, ktype, vtype) \
	RZ_API vtype rz_th_##name##_find(th_ht_type(name) * ht, const ktype key, bool *found) { \
		rz_return_val_if_fail(ht && ht->table, 0); \
		rz_th_lock_enter(ht->lock); \
		vtype ret = name##_find(ht->table, key, found); \
		rz_th_lock_leave(ht->lock); \
		return ret; \
	}

#define th_ht_move_decl(name, type) \
	RZ_API type *rz_th_##name##_move(th_ht_type(name) * ht) { \
		rz_return_val_if_fail(ht && ht->table, false); \
		rz_th_lock_enter(ht->lock); \
		type *ret = ht->table; \
		ht->table = NULL; \
		rz_th_lock_leave(ht->lock); \
		return ret; \
	}

#define th_ht_foreach_decl(name, type) \
	RZ_API void rz_th_##name##_foreach(th_ht_type(name) * ht, type##ForeachCallback cb, void *user) { \
		rz_return_if_fail(ht && ht->table && cb); \
		rz_th_lock_enter(ht->lock); \
		name##_foreach(ht->table, cb, user); \
		rz_th_lock_leave(ht->lock); \
	}

#define th_ht_define(name, type, ktype, vtype) \
	th_ht_struct(name, type); \
	th_ht_free_decl(name); \
	th_ht_new_decl(name, type); \
	th_ht_kv_op_decl(name, insert, const ktype, vtype); \
	th_ht_kv_op_decl(name, update, const ktype, vtype); \
	th_ht_delete_decl(name, ktype); \
	th_ht_find_decl(name, ktype, vtype); \
	th_ht_move_decl(name, type); \
	th_ht_foreach_decl(name, type)

th_ht_define(ht_pp, HtPP, void *, void *);
th_ht_define(ht_up, HtUP, ut64, void *);
th_ht_define(ht_uu, HtUU, ut64, ut64);
th_ht_define(ht_pu, HtPU, void *, ut64);
th_ht_define(ht_sp, HtSP, char *, void *);
th_ht_define(ht_ss, HtSS, char *, char *);
th_ht_define(ht_su, HtSU, char *, ut64);
