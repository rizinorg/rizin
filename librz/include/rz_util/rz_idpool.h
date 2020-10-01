/* rizin - LGPL - Copyright 2017-2018 - condret */

#ifndef R_ID_STORAGE_H
#define R_ID_STORAGE_H

#include <rz_util/rz_pool.h>
#include <rz_util/rz_queue.h>
#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_id_pool_t {
	ut32 start_id;
	ut32 last_id;
	ut32 next_id;
	RQueue *freed_ids;
} RIDPool;

RZ_API RIDPool *rz_id_pool_new(ut32 start_id, ut32 last_id);
RZ_API bool rz_id_pool_grab_id(RIDPool *pool, ut32 *grabber);
RZ_API bool rz_id_pool_kick_id(RIDPool *pool, ut32 kick);
RZ_API void rz_id_pool_free(RIDPool *pool);

typedef struct rz_id_storage_t {
	RIDPool *pool;
	void **data;
	ut32 top_id;
	ut32 size;
} RIDStorage;

typedef bool (*RIDStorageForeachCb)(void *user, void *data, ut32 id);
typedef bool (*ROIDStorageCompareCb)(void *in, void *incoming, void *user, int *cmp_res);

RZ_API RIDStorage *rz_id_storage_new(ut32 start_id, ut32 last_id);
RZ_API bool rz_id_storage_set(RIDStorage *storage, void *data, ut32 id);
RZ_API bool rz_id_storage_add(RIDStorage *storage, void *data, ut32 *id);
RZ_API void *rz_id_storage_get(RIDStorage *storage, ut32 id);
RZ_API void rz_id_storage_delete(RIDStorage *storage, ut32 id);
RZ_API void *rz_id_storage_take(RIDStorage *storage, ut32 id);
RZ_API bool rz_id_storage_foreach(RIDStorage *storage, RIDStorageForeachCb cb, void *user);
RZ_API void rz_id_storage_free(RIDStorage *storage);
RZ_API RzList *rz_id_storage_list(RIDStorage *s);

typedef struct rz_ordered_id_storage_t {
	ut32 *permutation;
	ut32 psize;
	ut32 ptop;
	RIDStorage *data;
	ROIDStorageCompareCb cmp;
} ROIDStorage;

RZ_API ROIDStorage *rz_oids_new(ut32 start_id, ut32 last_id);
RZ_API void *rz_oids_get(ROIDStorage *storage, ut32 id);
RZ_API void *rz_oids_oget(ROIDStorage *storage, ut32 od);
RZ_API bool rz_oids_get_id(ROIDStorage *storage, ut32 od, ut32 *id);
RZ_API bool rz_oids_get_od(ROIDStorage *storage, ut32 id, ut32 *od);
RZ_API bool rz_oids_to_front(ROIDStorage *storage, const ut32 id);
RZ_API bool rz_oids_to_rear(ROIDStorage *storage, const ut32 id);
RZ_API void rz_oids_delete(ROIDStorage *storage, ut32 id);
RZ_API void rz_oids_odelete(ROIDStorage *st, ut32 od);
RZ_API void rz_oids_free(ROIDStorage *storage);
RZ_API bool rz_oids_add(ROIDStorage *storage, void *data, ut32 *id, ut32 *od);
RZ_API void *rz_oids_take(ROIDStorage *storage, ut32 id);
RZ_API void *rz_oids_otake(ROIDStorage *st, ut32 od);
RZ_API bool rz_oids_foreach(ROIDStorage* storage, RIDStorageForeachCb cb, void* user);
RZ_API bool rz_oids_foreach_prev(ROIDStorage* storage, RIDStorageForeachCb cb, void* user);
RZ_API bool rz_oids_insert(ROIDStorage *storage, void *data, ut32 *id, ut32 *od, void *user); 
RZ_API bool rz_oids_sort(ROIDStorage *storage, void *user);
RZ_API ut32 rz_oids_find (ROIDStorage *storage, void *incoming, void *user);
RZ_API void *rz_oids_last(ROIDStorage *storage);
RZ_API void *rz_oids_first(ROIDStorage *storage);

#ifdef __cplusplus
}
#endif

#endif
