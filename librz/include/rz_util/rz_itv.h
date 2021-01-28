#ifndef RZ_INTERVAL_H
#define RZ_INTERVAL_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

// An interval in 64-bit address space which is aware of address space wraparound
// Precondition: 0 <= size < 2**64 and addr + size <= 2**64
// range is [], [10, 5) => 10 <= x < (10 + 5)
typedef struct rz_interval_t {
	// public:
	ut64 addr;
	ut64 size;
} RzInterval;

typedef RzInterval rz_itv_t;

static inline RzInterval *rz_itv_new(ut64 addr, ut64 size) {
	RzInterval *itv = RZ_NEW(RzInterval);
	if (itv) {
		itv->addr = addr;
		itv->size = size;
	}
	return itv;
}

static inline void rz_itv_free(RzInterval *itv) {
	free(itv);
}

static inline ut64 rz_itv_begin(RzInterval itv) {
	return itv.addr;
}

static inline ut64 rz_itv_size(RzInterval itv) {
	return itv.size;
}

static inline ut64 rz_itv_end(RzInterval itv) {
	return itv.addr + itv.size;
}

// Returns true if itv equals itv2
static inline bool rz_itv_eq(RzInterval itv, RzInterval itv2) {
	return itv.addr == itv2.addr && itv.size == itv2.size;
}

// Returns true if itv contained addr
static inline bool rz_itv_contain(RzInterval itv, ut64 addr) {
	const ut64 end = itv.addr + itv.size;
	return itv.addr <= addr && (!end || addr < end);
}

// Returns true if x is a subset of itv
static inline bool rz_itv_include(RzInterval itv, RzInterval x) {
	const ut64 end = itv.addr + itv.size;
	return itv.addr <= x.addr && (!end || (x.addr + x.size && x.addr + x.size <= end));
}

// Returns true if itv and x overlap (implying they are non-empty)
static inline bool rz_itv_overlap(RzInterval itv, RzInterval x) {
	const ut64 end = itv.addr + itv.size, end1 = x.addr + x.size;
	return (!end1 || itv.addr < end1) && (!end || x.addr < end);
}

static inline bool rz_itv_overlap2(RzInterval itv, ut64 addr, ut64 size) {
	RzInterval rai = { addr, size };
	return rz_itv_overlap(itv, rai);
}

// Precondition: itv and x overlap
// Returns the intersection of itv and x
static inline RzInterval rz_itv_intersect(RzInterval itv, RzInterval x) {
	const ut64 addr = RZ_MAX(itv.addr, x.addr);
	const ut64 end = RZ_MIN(itv.addr + itv.size - 1, x.addr + x.size - 1) + 1;
	RzInterval rai = { addr, end - addr };
	return rai;
}

#ifdef __cplusplus
}
#endif

#endif // RZ_INTERVAL_H
