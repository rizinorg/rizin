#ifndef RZ_STR_CONSTPOOL_H
#define RZ_STR_CONSTPOOL_H

#include <rz_types.h>
#include <rz_util/ht_sp.h>

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * RzStrConstPool is a pool of constant strings.
 * References to strings will be valid as long as the RzStrConstPool is alive.
 */

typedef struct rz_str_constpool_t {
	HtSP *ht;
} RzStrConstPool;

RZ_API bool rz_str_constpool_init(RzStrConstPool *pool);
RZ_API void rz_str_constpool_fini(RzStrConstPool *pool);
RZ_API const char *rz_str_constpool_get(RzStrConstPool *pool, const char *str);

#ifdef __cplusplus
}
#endif

#endif // RZ_STR_CONSTPOOL_H
