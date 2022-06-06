#ifndef RZ_TH_H
#define RZ_TH_H

#ifdef _GNU_SOURCE
#undef _GNU_SOURCE
#endif
#define _GNU_SOURCE
#include "rz_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	RZ_TH_FREED = -1,
	RZ_TH_STOP = 0,
	RZ_TH_REPEAT = 1
} RzThreadFunctionRet;
#define RZ_TH_FUNCTION(x) RzThreadFunctionRet (*x)(struct rz_th_t *)

typedef struct rz_th_sem_t RzThreadSemaphore;
typedef struct rz_th_lock_t RzThreadLock;
typedef struct rz_th_cond_t RzThreadCond;
typedef struct rz_th_t RzThread;

#define RZ_THREAD_POOL_ALL_CORES (0)

typedef struct rz_th_pool_t {
	size_t size;
	RzThread **threads;
} RzThreadPool;

#ifdef RZ_API
RZ_API RzThread *rz_th_new(RZ_TH_FUNCTION(fun), void *user, int delay);
RZ_API void *rz_th_get_user(RzThread *th);
RZ_API bool rz_th_start(RzThread *th, int enable);
RZ_API bool rz_th_wait(RzThread *th);
RZ_API bool rz_th_wait_async(RzThread *th);
RZ_API void rz_th_break(RzThread *th);
RZ_API void rz_th_free(RzThread *th);
RZ_API void rz_th_kill_free(RzThread *th);
RZ_API bool rz_th_kill(RzThread *th, bool force);
RZ_API bool rz_th_setname(RzThread *th, const char *name);
RZ_API bool rz_th_getname(RzThread *th, char *name, size_t len);
RZ_API bool rz_th_setaffinity(RzThread *th, int cpuid);

RZ_API RzThreadSemaphore *rz_th_sem_new(unsigned int initial);
RZ_API void rz_th_sem_free(RzThreadSemaphore *sem);
RZ_API void rz_th_sem_post(RzThreadSemaphore *sem);
RZ_API void rz_th_sem_wait(RzThreadSemaphore *sem);

RZ_API RzThreadLock *rz_th_lock_new(bool recursive);
RZ_API int rz_th_lock_wait(RzThreadLock *th);
RZ_API int rz_th_lock_tryenter(RzThreadLock *thl);
RZ_API int rz_th_lock_enter(RzThreadLock *thl);
RZ_API int rz_th_lock_leave(RzThreadLock *thl);
RZ_API void *rz_th_lock_free(RzThreadLock *thl);

RZ_API RzThreadCond *rz_th_cond_new(void);
RZ_API void rz_th_cond_signal(RzThreadCond *cond);
RZ_API void rz_th_cond_signal_all(RzThreadCond *cond);
RZ_API void rz_th_cond_wait(RzThreadCond *cond, RzThreadLock *lock);
RZ_API void rz_th_cond_free(RzThreadCond *cond);

RZ_API size_t rz_th_physical_core_number();
RZ_API RZ_OWN RzThreadPool *rz_th_pool_new(size_t max_threads);
RZ_API void rz_th_pool_free(RZ_NULLABLE RzThreadPool *pool);
RZ_API bool rz_th_pool_add_thread(RZ_NONNULL RzThreadPool *pool, RZ_NONNULL RzThread *thread);
RZ_API bool rz_th_pool_start(RZ_NONNULL RzThreadPool *pool, bool enable);
RZ_API bool rz_th_pool_wait(RZ_NONNULL RzThreadPool *pool);
RZ_API bool rz_th_pool_wait_async(RZ_NONNULL RzThreadPool *pool);
RZ_API bool rz_th_pool_kill(RZ_NONNULL RzThreadPool *pool, bool force);
RZ_API bool rz_th_pool_kill_free(RZ_NONNULL RzThreadPool *pool);

#endif

#ifdef __cplusplus
}
#endif

#endif
