// SPDX-FileCopyrightText: 2009-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_th.h>

/* locks/mutex/sems */

RZ_API RzThreadLock *rz_th_lock_new(bool recursive) {
	RzThreadLock *thl = RZ_NEW0(RzThreadLock);
	if (thl) {
#if HAVE_PTHREAD
		if (recursive) {
			pthread_mutexattr_t attr;
			pthread_mutexattr_init(&attr);
#if !defined(__GLIBC__) || __USE_UNIX98__
			pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
#else
			pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP);
#endif
			pthread_mutex_init(&thl->lock, &attr);
		} else {
			pthread_mutex_init(&thl->lock, NULL);
		}
#elif __WINDOWS__
		// TODO: obey `recursive` (currently it is always recursive)
		InitializeCriticalSection(&thl->lock);
#endif
	}
	return thl;
}

RZ_API int rz_th_lock_wait(RzThreadLock *thl) {
	rz_th_lock_enter(thl); // locks here
	rz_th_lock_leave(thl); // releases previous mutex
	return 0;
}

RZ_API int rz_th_lock_enter(RzThreadLock *thl) {
#if HAVE_PTHREAD
	return pthread_mutex_lock(&thl->lock);
#elif __WINDOWS__
	EnterCriticalSection(&thl->lock);
	return 0;
#endif
}

RZ_API int rz_th_lock_tryenter(RzThreadLock *thl) {
#if HAVE_PTHREAD
	return !pthread_mutex_trylock(&thl->lock);
#elif __WINDOWS__
	return TryEnterCriticalSection(&thl->lock);
#endif
}

RZ_API int rz_th_lock_leave(RzThreadLock *thl) {
#if HAVE_PTHREAD
	return pthread_mutex_unlock(&thl->lock);
#elif __WINDOWS__
	LeaveCriticalSection(&thl->lock);
	return 0;
#endif
}

RZ_API void *rz_th_lock_free(RzThreadLock *thl) {
	if (thl) {
#if HAVE_PTHREAD
		pthread_mutex_destroy(&thl->lock);
#elif __WINDOWS__
		DeleteCriticalSection(&thl->lock);
#endif
		free(thl);
	}
	return NULL;
}
