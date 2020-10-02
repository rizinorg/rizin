#ifndef RZ_RANGE_H
#define RZ_RANGE_H

#ifdef __cplusplus
extern "C" {
#endif

/* range.c */

typedef struct rz_range_item_t {
	ut64 fr;
	ut64 to;
	ut8 *data;
	int datalen;
} RRangeItem;

typedef struct rz_range_t {
	int count;
	int changed;
	RzList *ranges;
} RRange;

RZ_API RRange *rz_range_new(void);
RZ_API RRange *rz_range_new_from_string(const char *string);
RZ_API RRange *rz_range_free(RRange *r);
RZ_API RRangeItem *rz_range_item_get(RRange *r, ut64 addr);
RZ_API ut64 rz_range_size(RRange *r);
RZ_API int rz_range_add_from_string(RRange *rgs, const char *string);
RZ_API RRangeItem *rz_range_add(RRange *rgs, ut64 from, ut64 to, int rw);
RZ_API int rz_range_sub(RRange *rgs, ut64 from, ut64 to);
RZ_API void rz_range_merge(RRange *rgs, RRange *r);
RZ_API int rz_range_contains(RRange *rgs, ut64 addr);
RZ_API int rz_range_sort(RRange *rgs);
RZ_API void rz_range_percent(RRange *rgs);
RZ_API int rz_range_list(RRange *rgs, int rad);
RZ_API int rz_range_get_n(RRange *rgs, int n, ut64 *from, ut64 *to);
RZ_API RRange *rz_range_inverse(RRange *rgs, ut64 from, ut64 to, int flags);
RZ_API int rz_range_overlap(ut64 a0, ut64 a1, ut64 b0, ut64 b1, int *d);

#ifdef __cplusplus
}
#endif

#endif //  RZ_RANGE_H
