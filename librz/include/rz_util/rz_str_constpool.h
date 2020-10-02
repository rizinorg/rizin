#ifndef RZ_STR_CONSTPOOL_H
#define RZ_STR_CONSTPOOL_H

#include <rz_types.h>
#include <sdbht.h>

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * RStrConstPool is a pool of constant strings.
 * References to strings will be valid as long as the RStrConstPool is alive.
 */

typedef struct rz_str_constpool_t {
	HtPP *ht;
} RStrConstPool;

RZ_API bool rz_str_constpool_init(RStrConstPool *pool);
RZ_API void rz_str_constpool_fini(RStrConstPool *pool);
RZ_API const char *rz_str_constpool_get(RStrConstPool *pool, const char *str);

#ifdef __cplusplus
}
#endif

#endif //RZ_STR_CONSTPOOL_H
