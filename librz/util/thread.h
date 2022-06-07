// SPDX-FileCopyrightText: 2022 GustavoLCR <gugulcr@gmail.com>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_THREAD_INTERNAL_H
#define RZ_THREAD_INTERNAL_H
#ifdef _GNU_SOURCE
#undef _GNU_SOURCE
#endif
#define _GNU_SOURCE
#include <rz_th.h>
#include "rz_types.h"

#if __WINDOWS__
#include <rz_windows.h>
#define RZ_TH_TID    HANDLE
#define RZ_TH_LOCK_T CRITICAL_SECTION
#define RZ_TH_COND_T CONDITION_VARIABLE
#define RZ_TH_SEM_T  HANDLE
#define RZ_TH_RET_T  DWORD WINAPI
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
#define RZ_TH_RET_T  void *
#else
#error Threading library only supported for pthread and w32
#endif

struct rz_th_sem_t {
	RZ_TH_SEM_T sem;
};

struct rz_th_lock_t {
	RZ_TH_LOCK_T lock;
};

struct rz_th_cond_t {
	RZ_TH_COND_T cond;
};

struct rz_th_t {
	RZ_TH_TID tid; ///< Thread identifier.
	RzThreadFunction function; ///< User defined thread function.
	void *user; ///< User defined thread data to pass (can be NULL).
};

RZ_IPI RZ_TH_TID rz_th_self(void);

#endif /* RZ_THREAD_INTERNAL_H */
