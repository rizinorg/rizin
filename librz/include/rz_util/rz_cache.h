#ifndef RZ_CACHE_H
#define RZ_CACHE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_cache_t {
	ut64 base;
	ut8 *buf;
	ut64 len;
} RzCache;

typedef struct rz_prof_t {
	struct timeval begin;
	double result;
} RProfile;

RZ_API RzCache *rz_cache_new(void);
RZ_API void rz_cache_free(RzCache *c);
RZ_API const ut8 *rz_cache_get(RzCache *c, ut64 addr, int *len);
RZ_API int rz_cache_set(RzCache *c, ut64 addr, const ut8 *buf, int len);
RZ_API void rz_cache_flush(RzCache *c);
RZ_API void rz_prof_start(RProfile *p);
RZ_API double rz_prof_end(RProfile *p);

#ifdef __cplusplus
}
#endif
#endif //  RZ_CACHE_H
