// SPDX-FileCopyrightText: 2020-2023 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2009-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_TH_H
#define RZ_TH_H

#ifdef _GNU_SOURCE
#undef _GNU_SOURCE
#endif
#define _GNU_SOURCE
#include <rz_types.h>
#include <rz_list.h>
#include <rz_vector.h>

#include <rz_util/rz_th_ht.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	RZ_THREAD_N_CORES_ALL_AVAILABLE = 0,
} RzThreadNCores;

typedef enum {
	RZ_THREAD_QUEUE_UNLIMITED = 0,
} RzThreadQueueSize;

typedef struct rz_th_sem_t RzThreadSemaphore;
typedef struct rz_th_lock_t RzThreadLock;
typedef struct rz_th_cond_t RzThreadCond;
typedef struct rz_th_t RzThread;
typedef struct rz_th_pool_t RzThreadPool;
typedef struct rz_th_queue_t RzThreadQueue;
typedef void *(*RzThreadFunction)(void *user);
typedef void (*RzThreadIterator)(void *element, void *user);

typedef struct rz_atomic_bool_t RzAtomicBool;

#ifdef RZ_API
RZ_API RZ_OWN RzThread *rz_th_new(RZ_NONNULL RzThreadFunction function, RZ_NULLABLE void *user);
RZ_API RZ_OWN void *rz_th_get_user(RZ_NONNULL RzThread *th);
RZ_API RZ_OWN void *rz_th_get_retv(RZ_NONNULL RzThread *th);
RZ_API bool rz_th_wait(RZ_NONNULL RzThread *th);
RZ_API void rz_th_free(RZ_NULLABLE RzThread *th);
RZ_API bool rz_th_set_name(RZ_NONNULL RzThread *th, RZ_NONNULL const char *name);
RZ_API bool rz_th_get_name(RZ_NONNULL RzThread *th, RZ_NONNULL RZ_OUT char *name, size_t len);
RZ_API bool rz_th_set_affinity(RZ_NONNULL RzThread *th, int cpuid);
RZ_API bool rz_th_yield(void);

RZ_API RZ_OWN RzThreadSemaphore *rz_th_sem_new(unsigned int initial);
RZ_API void rz_th_sem_free(RZ_NULLABLE RzThreadSemaphore *sem);
RZ_API void rz_th_sem_post(RZ_NONNULL RzThreadSemaphore *sem);
RZ_API void rz_th_sem_wait(RZ_NONNULL RzThreadSemaphore *sem);

RZ_API RZ_OWN RzThreadLock *rz_th_lock_new(bool recursive);
RZ_API bool rz_th_lock_tryenter(RZ_NONNULL RzThreadLock *thl);
RZ_API void rz_th_lock_enter(RZ_NONNULL RzThreadLock *thl);
RZ_API void rz_th_lock_leave(RZ_NONNULL RzThreadLock *thl);
RZ_API void rz_th_lock_free(RZ_NULLABLE RzThreadLock *thl);

RZ_API RZ_OWN RzThreadCond *rz_th_cond_new(void);
RZ_API void rz_th_cond_signal(RZ_NONNULL RzThreadCond *cond);
RZ_API void rz_th_cond_signal_all(RZ_NONNULL RzThreadCond *cond);
RZ_API void rz_th_cond_wait(RZ_NONNULL RzThreadCond *cond, RZ_NONNULL RzThreadLock *lock);
RZ_API void rz_th_cond_free(RZ_NULLABLE RzThreadCond *cond);

RZ_API RzThreadNCores rz_th_physical_core_number();
RZ_API RzThreadNCores rz_th_max_threads(RzThreadNCores requested);

RZ_API RZ_OWN RzThreadPool *rz_th_pool_new(RzThreadNCores max_threads);
RZ_API void rz_th_pool_free(RZ_NULLABLE RzThreadPool *pool);
RZ_API bool rz_th_pool_add_thread(RZ_NONNULL RzThreadPool *pool, RZ_NONNULL RzThread *thread);
RZ_API RZ_BORROW RzThread *rz_th_pool_get_thread(RZ_NONNULL RzThreadPool *pool, size_t index);
RZ_API bool rz_th_pool_wait(RZ_NONNULL RzThreadPool *pool);
RZ_API size_t rz_th_pool_size(RZ_NONNULL RzThreadPool *pool);

RZ_API RZ_OWN RzThreadQueue *rz_th_queue_new(RzThreadQueueSize max_size, RZ_NULLABLE RzListFree qfree);
RZ_API RZ_OWN RzThreadQueue *rz_th_queue_from_list(RZ_NONNULL RZ_BORROW RzList /*<void *>*/ *list, RZ_NULLABLE RzListFree qfree);
RZ_API RZ_OWN RzThreadQueue *rz_th_queue_from_pvector(RZ_NONNULL RZ_BORROW RzPVector /*<void *>*/ *vector, RZ_NULLABLE RzListFree qfree);
RZ_API void rz_th_queue_free(RZ_NULLABLE RzThreadQueue *queue);
RZ_API bool rz_th_queue_push(RZ_NONNULL RzThreadQueue *queue, RZ_NONNULL void *user, bool tail);
RZ_API RZ_OWN void *rz_th_queue_pop(RZ_NONNULL RzThreadQueue *queue, bool tail);
RZ_API RZ_OWN void *rz_th_queue_wait_pop(RZ_NONNULL RzThreadQueue *queue, bool tail);
RZ_API RZ_OWN RzList /*<void *>*/ *rz_th_queue_pop_all(RZ_NONNULL RzThreadQueue *queue);
RZ_API bool rz_th_queue_is_empty(RZ_NONNULL RzThreadQueue *queue);
RZ_API bool rz_th_queue_is_full(RZ_NONNULL RzThreadQueue *queue);
RZ_API size_t rz_th_queue_size(RZ_NONNULL RzThreadQueue *queue);

RZ_API RZ_OWN RzAtomicBool *rz_atomic_bool_new(bool value);
RZ_API void rz_atomic_bool_free(RZ_NULLABLE RzAtomicBool *tbool);
RZ_API bool rz_atomic_bool_get(RZ_NONNULL RzAtomicBool *tbool);
RZ_API void rz_atomic_bool_set(RZ_NONNULL RzAtomicBool *tbool, bool value);

RZ_API bool rz_th_iterate_list(RZ_NONNULL const RzList /*<void *>*/ *list, RZ_NONNULL RzThreadIterator iterator, RzThreadNCores max_threads, RZ_NULLABLE void *user);
RZ_API bool rz_th_iterate_pvector(RZ_NONNULL const RzPVector /*<void *>*/ *pvec, RZ_NONNULL RzThreadIterator iterator, RzThreadNCores max_threads, RZ_NULLABLE void *user);

#endif /* RZ_API */

#ifdef __cplusplus
}
#endif

#endif /* RZ_TH_H */
