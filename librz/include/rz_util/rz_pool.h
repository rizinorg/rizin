#ifndef RZ_POOL_H
#define RZ_POOL_H
#include <rz_util/rz_mem.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_mem_pool_factory_t {
	int limit;
	RMemoryPool **pools;
} RPoolFactory;

RZ_API RPoolFactory *rz_poolfactory_instance(void);
RZ_API void rz_poolfactory_init(int limit);
RZ_API RPoolFactory *rz_poolfactory_new(int limit);
RZ_API void *rz_poolfactory_alloc(RPoolFactory *pf, int nodesize);
RZ_API void rz_poolfactory_stats(RPoolFactory *pf);
RZ_API void rz_poolfactory_free(RPoolFactory *pf);

#ifdef __cplusplus
}
#endif

#endif //  RZ_POOL_H
