#ifndef RZ_INTERVAL_H
#define RZ_INTERVAL_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief An interval in 64-bit address space which is aware of address space wraparound.
 *
 * Precondition: 0 <= size < 2**64 and addr + size <= 2**64
 * Interval range is [addr, addr + size)
 * e.g. with addr = 10 and size = 5, interval range is [10, 15) where 10 <= x < (10 + 5).
 *
 * This interval is usually (though not always!) treated as right open interval.
 */
typedef struct rz_interval_t {
	ut64 addr; ///< Start address of the interval.
	ut64 size; ///< Size of the interval in bytes.
} RzInterval;

typedef enum {
	RZ_INTERVAL_IN = 0, ///< A value is in the interval.
	RZ_INTERVAL_OUT, ///< A value is outside of the interval.
	RZ_INTERVAL_UNDEF, ///< A value affiliation is not defined for the interval.
} RzIntervalAffiliation;

typedef enum rz_interval_bound_t {
	RZ_INTERVAL_BOUND_CLOSED = 0, ///< A closed interval: `[a, b]`. True if right and left open are NOT set.
	RZ_INTERVAL_BOUND_RIGHT_OPEN = 1, ///< A right-open interval: `[a, b)`. This is the assumed default interpretation in Rizin.
	RZ_INTERVAL_BOUND_LEFT_OPEN = 2, ///< A left-open interval: `(a, b]`.
	RZ_INTERVAL_BOUND_OPEN = 3, ///< An open interval: `(a, b)`. True if right and left open are set.
	RZ_INTERVAL_BOUND_UNDEF = 4, ///< Undefined.
} RzIntervalBound;

/**
 * \brief An interval with explicitly defined bounds.
 */
typedef struct {
	ut64 a; ///< The left-hand value.
	ut64 b; ///< The right-hand value.
	RzIntervalBound bound; ///< Interval bound attribute.
} RzIntervalBoundedUt64;

typedef RzInterval rz_itv_t;

static inline RzIntervalAffiliation rz_itv_bound_contains_ut64(RzIntervalBoundedUt64 *itv, ut64 value) {
	switch (itv->bound) {
	default:
		return RZ_INTERVAL_UNDEF;
	case RZ_INTERVAL_BOUND_RIGHT_OPEN:
		return (itv->a <= value && value < itv->b) ? RZ_INTERVAL_IN : RZ_INTERVAL_OUT;
	case RZ_INTERVAL_BOUND_LEFT_OPEN:
		return (itv->a < value && value <= itv->b) ? RZ_INTERVAL_IN : RZ_INTERVAL_OUT;
	case RZ_INTERVAL_BOUND_OPEN:
		return (itv->a < value && value < itv->b) ? RZ_INTERVAL_IN : RZ_INTERVAL_OUT;
	case RZ_INTERVAL_BOUND_CLOSED:
		return (itv->a <= value && value <= itv->b) ? RZ_INTERVAL_IN : RZ_INTERVAL_OUT;
	}
}

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

RZ_API bool rz_itv_str_to_bounded_itv_ut64(RZ_NONNULL const char *itv_str, RZ_OUT RzIntervalBoundedUt64 *out_itv);

#ifdef __cplusplus
}
#endif

#endif // RZ_INTERVAL_H
