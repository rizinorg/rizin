// SPDX-FileCopyrightText: 2017-2020 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_types.h>
#include <string.h>
#include <stdlib.h>
#if __WINDOWS__
#include <search.h>
#endif

static ut32 get_msb(ut32 v) {
	int i;
	for (i = 31; i > (-1); i--) {
		if (v & (0x1U << i)) {
			return (v & (0x1U << i));
		}
	}
	return 0;
}

RZ_API RzIDPool *rz_id_pool_new(ut32 start_id, ut32 last_id) {
	RzIDPool *pool = NULL;
	if (start_id < last_id) {
		pool = RZ_NEW0(RzIDPool);
		if (pool) {
			pool->next_id = pool->start_id = start_id;
			pool->last_id = last_id;
		}
	}
	return pool;
}

RZ_API bool rz_id_pool_grab_id(RzIDPool *pool, ut32 *grabber) {
	rz_return_val_if_fail(pool && grabber, false);

	*grabber = UT32_MAX;
	if (pool->freed_ids) {
		ut32 grab = (ut32)(size_t)rz_queue_dequeue(pool->freed_ids);
		*grabber = (ut32)grab;
		if (rz_queue_is_empty(pool->freed_ids)) {
			rz_queue_free(pool->freed_ids);
			pool->freed_ids = NULL;
		}
		return true;
	}
	if (pool->next_id < pool->last_id) {
		*grabber = pool->next_id;
		pool->next_id++;
		return true;
	}
	return false;
}

RZ_API bool rz_id_pool_kick_id(RzIDPool *pool, ut32 kick) {
	if (!pool || (kick < pool->start_id) || (pool->start_id == pool->next_id)) {
		return false;
	}
	if (kick == (pool->next_id - 1)) {
		pool->next_id--;
		return true;
	}
	if (!pool->freed_ids) {
		pool->freed_ids = rz_queue_new(2);
	}
	rz_queue_enqueue(pool->freed_ids, (void *)(size_t)kick);
	return true;
}

RZ_API void rz_id_pool_free(RzIDPool *pool) {
	if (pool && pool->freed_ids) {
		rz_queue_free(pool->freed_ids);
	}
	free(pool);
}

RZ_API RzIDStorage *rz_id_storage_new(ut32 start_id, ut32 last_id) {
	RzIDStorage *storage = NULL;
	RzIDPool *pool = rz_id_pool_new(start_id, last_id);
	if (pool) {
		storage = RZ_NEW0(RzIDStorage);
		if (!storage) {
			rz_id_pool_free(pool);
			return NULL;
		}
		storage->pool = pool;
	}
	return storage;
}

static bool id_storage_reallocate(RzIDStorage *storage, ut32 size) {
	if (!storage) {
		return false;
	}
	void **data = realloc(storage->data, size * sizeof(void *));
	if (!data) {
		return false;
	}
	if (size > storage->size) {
		memset(data + storage->size, 0, (size - storage->size) * sizeof(void *));
	}
	storage->data = data;
	storage->size = size;
	return true;
}

static bool oid_storage_preallocate(ROIDStorage *st, ut32 size) {
	ut32 *permutation;
	if (!st) {
		return false;
	}
	if (!size) {
		RZ_FREE(st->permutation);
		st->psize = 0;
	}
	permutation = realloc(st->permutation, size * sizeof(ut32));
	if (!permutation) {
		return false;
	}
	if (size > st->psize) {
		memset(permutation + st->psize, 0, (size - st->psize) * sizeof(ut32));
	}
	st->permutation = permutation;
	st->psize = size;
	return true;
}

RZ_API bool rz_id_storage_set(RzIDStorage *storage, void *data, ut32 id) {
	ut32 n;
	if (!storage || !storage->pool || (id >= storage->pool->next_id)) {
		return false;
	}
	n = get_msb(id + 1);
	if (n > ((storage->size / 2) + (storage->size / 4))) {
		if ((n * 2) < storage->pool->last_id) {
			if (!id_storage_reallocate(storage, n * 2)) {
				return false;
			}
		} else if (n != (storage->pool->last_id)) {
			if (!id_storage_reallocate(storage, storage->pool->last_id)) {
				return false;
			}
		}
	}
	storage->data[id] = data;
	if (id > storage->top_id) {
		storage->top_id = id;
	}
	return true;
}

RZ_API bool rz_id_storage_add(RzIDStorage *storage, void *data, ut32 *id) {
	if (!storage || !rz_id_pool_grab_id(storage->pool, id)) {
		return false;
	}
	return rz_id_storage_set(storage, data, *id);
}

RZ_API void *rz_id_storage_get(RzIDStorage *storage, ut32 id) {
	if (!storage || !storage->data || (storage->size <= id)) {
		return NULL;
	}
	return storage->data[id];
}

RZ_API bool rz_id_storage_get_lowest(RzIDStorage *storage, ut32 *id) {
	rz_return_val_if_fail(storage, false);
	ut32 i;
	for (i = 0; i < storage->size && !storage->data[i]; i++)
		;
	*id = i;
	return i < storage->size;
}

RZ_API bool rz_id_storage_get_highest(RzIDStorage *storage, ut32 *id) {
	rz_return_val_if_fail(storage, false);
	size_t i = 0;
	if (storage->size > 0) {
		for (i = storage->size - 1; !storage->data[i] && i > 0; i--)
			;
		*id = i;
		return storage->data[i] != NULL;
	}
	// *id = i;
	return false;
}

RZ_API bool rz_id_storage_get_next(RzIDStorage *storage, ut32 *idref) {
	rz_return_val_if_fail(idref && storage, false);
	ut32 id = *idref;
	if (storage->size < 1 || id >= storage->size || !storage->data) {
		return false;
	}
	for (id = *idref + 1; id < storage->size && !storage->data[id]; id++)
		;
	if (id < storage->size) {
		*idref = id;
		return true;
	}
	return false;
}

RZ_API bool rz_id_storage_get_prev(RzIDStorage *storage, ut32 *idref) {
	rz_return_val_if_fail(idref && storage, false);
	ut32 id = *idref;
	if (id == 0 || id >= storage->size || storage->size < 1 || !storage->data) {
		return false;
	}
	for (id = *idref - 1; id > 0 && !storage->data[id]; id--)
		;
	if (storage->data[id]) {
		*idref = id;
		return true;
	}
	return false;
}

RZ_API void rz_id_storage_delete(RzIDStorage *storage, ut32 id) {
	if (!storage || !storage->data || (storage->size <= id)) {
		return;
	}
	storage->data[id] = NULL;
	if (id == storage->top_id) {
		while (storage->top_id && !storage->data[storage->top_id]) {
			storage->top_id--;
		}
		if (!storage->top_id) {
			if (storage->data[storage->top_id]) {
				id_storage_reallocate(storage, 2);
			} else {
				RzIDPool *pool = rz_id_pool_new(storage->pool->start_id, storage->pool->last_id);
				RZ_FREE(storage->data);
				storage->size = 0;
				rz_id_pool_free(storage->pool);
				storage->pool = pool;
				return;
			}
		} else if ((storage->top_id + 1) < (storage->size / 4)) {
			id_storage_reallocate(storage, storage->size / 2);
		}
	}
	rz_id_pool_kick_id(storage->pool, id);
}

RZ_API void *rz_id_storage_take(RzIDStorage *storage, ut32 id) {
	void *ret = rz_id_storage_get(storage, id);
	rz_id_storage_delete(storage, id);
	return ret;
}

RZ_API bool rz_id_storage_foreach(RzIDStorage *storage, RzIDStorageForeachCb cb, void *user) {
	ut32 i;
	if (!cb || !storage || !storage->data) {
		return false;
	}
	for (i = 0; i < storage->top_id; i++) {
		if (storage->data[i] && !cb(user, storage->data[i], i)) {
			return false;
		}
	}
	if (storage->data[i]) {
		return cb(user, storage->data[i], i);
	}
	return true;
}

RZ_API void rz_id_storage_free(RzIDStorage *storage) {
	if (storage) {
		rz_id_pool_free(storage->pool);
		free(storage->data);
	}
	free(storage);
}

static bool _list(void *user, void *data, ut32 id) {
	rz_list_append(user, data);
	return true;
}

RZ_API RzList *rz_id_storage_list(RzIDStorage *s) { //remove this pls
	RzList *list = rz_list_newf(NULL);
	rz_id_storage_foreach(s, _list, list);
	return list;
}

RZ_API ROIDStorage *rz_oids_new(ut32 start_id, ut32 last_id) {
	ROIDStorage *storage = RZ_NEW0(ROIDStorage);
	if (!storage) {
		return NULL;
	}
	if (!(storage->data = rz_id_storage_new(start_id, last_id))) {
		free(storage);
		return NULL;
	}
	return storage;
}

RZ_API void *rz_oids_get(ROIDStorage *storage, ut32 id) {
	if (storage) {
		return rz_id_storage_get(storage->data, id);
	}
	return NULL;
}

RZ_API void *rz_oids_oget(ROIDStorage *storage, ut32 od) {
	ut32 id;
	if (rz_oids_get_id(storage, od, &id)) {
		return rz_id_storage_get(storage->data, id);
	}
	return NULL;
}

RZ_API bool rz_oids_get_id(ROIDStorage *storage, ut32 od, ut32 *id) {
	if (storage && storage->permutation && (storage->ptop > od)) {
		*id = storage->permutation[od];
		return true;
	}
	return false;
}

RZ_API bool rz_oids_get_od(ROIDStorage *storage, ut32 id, ut32 *od) {
	if (storage && storage->permutation &&
		storage->data && (id < storage->data->pool->next_id)) {
		for (od[0] = 0; od[0] < storage->ptop; od[0]++) {
			if (id == storage->permutation[od[0]]) {
				return true;
			}
		}
	}
	return false;
}

RZ_API bool rz_oids_add(ROIDStorage *storage, void *data, ut32 *id, ut32 *od) {
	if (!storage || !id || !od) {
		return false;
	}
	if (!rz_id_storage_add(storage->data, data, id)) {
		return false;
	}
	if (!storage->permutation) {
		oid_storage_preallocate(storage, 4);
	} else if (storage->ptop > (storage->psize * 3 / 4)) {
		oid_storage_preallocate(storage, storage->psize * 2);
	}
	if (storage->psize <= storage->ptop) {
		rz_id_storage_delete(storage->data, *id);
		return false;
	}
	if (!storage->permutation) {
		return false;
	}
	*od = storage->ptop;
	storage->permutation[*od] = *id;
	storage->ptop++;
	return true;
}

RZ_API bool rz_oids_to_front(ROIDStorage *storage, const ut32 id) {
	ut32 od;
	if (!storage || !storage->permutation) {
		return false;
	}
	for (od = 0; od < storage->ptop; od++) {
		if (id == storage->permutation[od]) {
			break;
		}
	}
	if (od == storage->ptop) {
		return false;
	} else if (od == (storage->ptop - 1)) {
		return true;
	}
	memmove(&storage->permutation[od], &storage->permutation[od + 1],
		(storage->ptop - od - 1) * sizeof(ut32));
	storage->permutation[storage->ptop - 1] = id;
	return true;
}

RZ_API bool rz_oids_to_rear(ROIDStorage *storage, ut32 id) {
	ut32 od;
	if (!storage || !storage->permutation ||
		!storage->data || (id >= storage->data->pool->next_id)) {
		return false;
	}
	bool found = false;
	for (od = 0; od < storage->ptop; od++) {
		if (id == storage->permutation[od]) {
			found = true;
			break;
		}
	}
	if (od == storage->ptop) {
		return false;
	}
	if (!found) {
		return true;
	}
	memmove(&storage->permutation[1], &storage->permutation[0], od * sizeof(ut32));
	storage->permutation[0] = id;
	return true;
}

RZ_API void rz_oids_delete(ROIDStorage *storage, ut32 id) {
	if (!rz_oids_to_front(storage, id)) {
		return;
	}
	rz_id_storage_delete(storage->data, id);
	storage->ptop--;
	if (!storage->ptop) {
		RZ_FREE(storage->permutation);
		storage->psize = 0;
	} else if ((storage->ptop + 1) < (storage->psize / 4)) {
		oid_storage_preallocate(storage, storage->psize / 2);
	}
}

RZ_API void rz_oids_odelete(ROIDStorage *st, ut32 od) {
	ut32 n;
	if (!st || !st->permutation || od >= st->ptop) {
		return;
	}
	n = st->ptop - od - 1;
	rz_id_storage_delete(st->data, st->permutation[od]);
	memmove(&st->permutation[od], &st->permutation[od + 1], n * sizeof(ut32));
	st->ptop--;
	if (!st->ptop) {
		RZ_FREE(st->permutation);
		st->psize = 0;
	} else if ((st->ptop + 1) < (st->psize / 4)) {
		oid_storage_preallocate(st, st->psize / 2);
	}
}

RZ_API void *rz_oids_take(ROIDStorage *storage, ut32 id) {
	rz_return_val_if_fail(storage, NULL);
	void *ret = rz_id_storage_get(storage->data, id);
	rz_oids_delete(storage, id);
	return ret;
}

RZ_API void *rz_oids_otake(ROIDStorage *st, ut32 od) {
	void *ret = rz_oids_oget(st, od);
	rz_oids_odelete(st, od);
	return ret;
}

RZ_API void rz_oids_free(ROIDStorage *storage) {
	if (storage) {
		free(storage->permutation);
		rz_id_storage_free(storage->data);
	}
	free(storage);
}

//returns the element with lowest order
RZ_API void *rz_oids_last(ROIDStorage *storage) {
	if (storage && storage->data && storage->data->data && storage->permutation) {
		return storage->data->data[storage->permutation[0]];
	}
	return NULL;
}

//return the element with highest order
RZ_API void *rz_oids_first(ROIDStorage *storage) {
	if (storage && storage->data && storage->data->data && storage->permutation) {
		return storage->data->data[storage->permutation[storage->ptop - 1]];
	}
	return NULL;
}

RZ_API bool rz_oids_foreach(ROIDStorage *storage, RzIDStorageForeachCb cb, void *user) {
	ut32 i;
	ut32 id;
	if (!cb || !storage || !storage->data || !storage->data->data || !storage->permutation) {
		return false;
	}
	for (i = storage->ptop - 1; i != 0; i--) {
		id = storage->permutation[i];
		if (!cb(user, storage->data->data[id], id)) {
			return false;
		}
	}
	id = storage->permutation[0];
	return cb(user, storage->data->data[id], id);
}

RZ_API bool rz_oids_foreach_prev(ROIDStorage *storage, RzIDStorageForeachCb cb, void *user) {
	ut32 i;
	ut32 id;
	if (!cb || !storage || !storage->data || !storage->data->data || !storage->permutation) {
		return false;
	}
	for (i = 0; i < storage->ptop; i++) {
		id = storage->permutation[i];
		if (!cb(user, storage->data->data[id], id)) {
			return false;
		}
	}
	return true;
}

bool oids_od_bfind(ROIDStorage *st, ut32 *od, void *incoming, void *user) {
	st64 high, low;
	int cmp_res;
	void *in;

	if (!st->ptop) {
		return false;
	}

	high = st->ptop - 1;
	low = 0;

	while (1) {
		if (high <= low) {
			od[0] = (ut32)low;
			in = rz_oids_oget(st, od[0]);
			//in - incoming
			if (!st->cmp(in, incoming, user, &cmp_res)) {
				return false;
			}
			if (cmp_res < 0) {
				od[0]++;
			}
			return true;
		}

		od[0] = (ut32)((low + high) / 2);
		in = rz_oids_oget(st, od[0]);
		if (!st->cmp(in, incoming, user, &cmp_res)) {
			return false;
		}

		if (cmp_res == 0) {
			return true;
		}

		if (cmp_res < 0) {
			low = od[0] + 1;
		} else {
			high = od[0];
			high--;
		}
	}
	return false;
}

bool oids_od_binsert(ROIDStorage *storage, ut32 id, ut32 *od, void *incoming, void *user) {
	if (!oids_od_bfind(storage, od, incoming, user)) {
		return false;
	}
	if (od[0] != storage->ptop) {
		memmove(&storage->permutation[od[0] + 1], &storage->permutation[od[0]], (storage->ptop - od[0]) * sizeof(ut32));
	}
	storage->ptop++;
	storage->permutation[od[0]] = id;
	return true;
}

RZ_API bool rz_oids_insert(ROIDStorage *storage, void *data, ut32 *id, ut32 *od, void *user) {
	if (!storage || !storage->cmp || !id || !od) {
		return false;
	}
	if (!storage->ptop) { //empty storage
		return rz_oids_add(storage, data, id, od);
	}
	if (!rz_id_storage_add(storage->data, data, id)) {
		return false;
	}
	if (storage->ptop > (storage->psize * 3 / 4)) {
		oid_storage_preallocate(storage, storage->psize * 2);
	}
	return oids_od_binsert(storage, id[0], od, data, user);
}

RZ_API bool rz_oids_sort(ROIDStorage *storage, void *user) {
	ut32 od, id, ptop, *permutation;

	if (!storage || !storage->ptop || !storage->cmp) {
		return false;
	}
	if (storage->ptop == 1) {
		return true;
	}
	permutation = storage->permutation;
	storage->permutation = RZ_NEWS0(ut32, storage->psize);
	if (!storage->permutation) {
		storage->permutation = permutation;
		return false;
	}
	storage->permutation[0] = permutation[0];
	ptop = storage->ptop;
	storage->ptop = 1;
	while (storage->ptop != ptop) {
		id = permutation[storage->ptop];
		void *incoming = rz_id_storage_get(storage->data, id);
		if (!oids_od_binsert(storage, id, &od, incoming, user)) {
			goto beach;
		}
	}
	free(permutation);
	return true;

beach:
	free(storage->permutation);
	storage->permutation = permutation;
	storage->ptop = ptop;
	return false;
}

RZ_API ut32 rz_oids_find(ROIDStorage *storage, void *incoming, void *user) {
	ut32 ret;
	return oids_od_bfind(storage, &ret, incoming, user) ? ret : storage->ptop;
}
