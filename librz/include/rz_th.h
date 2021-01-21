#ifndef RZ_TH_H
#define RZ_TH_H

#ifdef _GNU_SOURCE
#undef _GNU_SOURCE
#endif
#define _GNU_SOURCE
#include "rz_types.h"

#define HAVE_PTHREAD 1

#if __WINDOWS__
#undef HAVE_PTHREAD
#define HAVE_PTHREAD 0
#define RZ_TH_TID    HANDLE
#define RZ_TH_LOCK_T CRITICAL_SECTION
#define RZ_TH_COND_T CONDITION_VARIABLE
#define RZ_TH_SEM_T  HANDLE
//HANDLE

#elif HAVE_PTHREAD
#define __GNU
#include <semaphore.h>
#include <pthread.h>
#if __linux__
#include <sched.h>
#endif
#if __linux__ && __GLIBC_MINOR < 12
#define HAVE_PTHREAD_NP 0
#else
#define HAVE_PTHREAD_NP 1
#endif
#if __APPLE__
#include <pthread.h>
#endif
#if __FreeBSD__ || __OpenBSD__ || __DragonFly__
#if __FreeBSD__
#include <sys/cpuset.h>
#endif
#include <pthread_np.h>
#endif
#define RZ_TH_TID    pthread_t
#define RZ_TH_LOCK_T pthread_mutex_t
#define RZ_TH_COND_T pthread_cond_t
#define RZ_TH_SEM_T  sem_t *

#else
#error Threading library only supported for pthread and w32
#endif

typedef enum { RZ_TH_FREED = -1,
	RZ_TH_STOP = 0,
	RZ_TH_REPEAT = 1 } RzThreadFunctionRet;
#define RZ_TH_FUNCTION(x) RzThreadFunctionRet (*x)(struct rz_th_t *)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_th_sem_t {
	RZ_TH_SEM_T sem;
} RzThreadSemaphore;

typedef struct rz_th_lock_t {
	RZ_TH_LOCK_T lock;
} RzThreadLock;

typedef struct rz_th_cond_t {
	RZ_TH_COND_T cond;
} RzThreadCond;

typedef struct rz_th_t {
	RZ_TH_TID tid;
	RzThreadLock *lock;
	RZ_TH_FUNCTION(fun);
	void *user; // user pointer
	int running;
	int breaked; // thread aims to be interrupted
	int delay; // delay the startup of the thread N seconds
	int ready; // thread is properly setup
} RzThread;

typedef struct rz_th_pool_t {
	int size;
	RzThread **threads;
} RzThreadPool;

#ifdef RZ_API
RZ_API RzThread *rz_th_new(RZ_TH_FUNCTION(fun), void *user, int delay);
RZ_API bool rz_th_start(RzThread *th, int enable);
RZ_API int rz_th_wait(RzThread *th);
RZ_API int rz_th_wait_async(RzThread *th);
RZ_API void rz_th_break(RzThread *th);
RZ_API void *rz_th_free(RzThread *th);
RZ_API void *rz_th_kill_free(RzThread *th);
RZ_API bool rz_th_kill(RzThread *th, bool force);
RZ_API RZ_TH_TID rz_th_self(void);
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

#endif

#ifdef __cplusplus
}
#endif

#endif
