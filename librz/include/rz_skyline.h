#ifndef RZ_SKYLINE_H
#define RZ_SKYLINE_H

#include "rz_vector.h"
#include "rz_util/rz_itv.h"

typedef struct rz_skyline_item_t {
	RzInterval itv;
	void *user;
} RzSkylineItem;

typedef struct rz_skyline_t {
	RzVector v;
} RzSkyline;

RZ_API bool rz_skyline_add(RzSkyline *skyline, RzInterval itv, void *user);
RZ_API const RzSkylineItem *rz_skyline_get_item_intersect(RzSkyline *skyline, ut64 addr, ut64 len);

static inline void rz_skyline_init(RzSkyline *skyline) {
	rz_return_if_fail(skyline);
	rz_vector_init(&skyline->v, sizeof(RzSkylineItem), NULL, NULL);
}

static inline void rz_skyline_fini(RzSkyline *skyline) {
	rz_return_if_fail(skyline);
	rz_vector_fini(&skyline->v);
}

static inline void rz_skyline_clear(RzSkyline *skyline) {
	rz_return_if_fail(skyline);
	rz_vector_clear(&skyline->v);
}

static inline const RzSkylineItem *rz_skyline_get_item(RzSkyline *skyline, ut64 addr) {
	rz_return_val_if_fail(skyline, NULL);
	return rz_skyline_get_item_intersect(skyline, addr, 0);
}

static inline void *rz_skyline_get(RzSkyline *skyline, ut64 addr) {
	rz_return_val_if_fail(skyline, NULL);
	const RzSkylineItem *item = rz_skyline_get_item(skyline, addr);
	return item ? item->user : NULL;
}

static inline void *rz_skyline_get_intersect(RzSkyline *skyline, ut64 addr, ut64 len) {
	rz_return_val_if_fail(skyline, NULL);
	const RzSkylineItem *item = rz_skyline_get_item_intersect(skyline, addr, len);
	return item ? item->user : NULL;
}

static inline bool rz_skyline_contains(RzSkyline *skyline, ut64 addr) {
	rz_return_val_if_fail(skyline, false);
	return (bool)rz_skyline_get_item(skyline, addr);
}

#endif
