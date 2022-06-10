// SPDX-FileCopyrightText: 2009-2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "thread.h"

RZ_API RZ_OWN RzThreadLock *rz_th_lock_new(bool recursive) {
	RzThreadLock *thl = RZ_NEW0(RzThreadLock);
	if (!thl) {
		return NULL;
	}
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
	// Windows critical sections always accept recursive
	// access and it cannot be configured in any other way.
	InitializeCriticalSection(&thl->lock);
#endif
	return thl;
}

RZ_API void rz_th_lock_enter(RZ_NONNULL RzThreadLock *thl) {
	rz_return_if_fail(thl);
#if HAVE_PTHREAD
	pthread_mutex_lock(&thl->lock);
#elif __WINDOWS__
	EnterCriticalSection(&thl->lock);
#endif
}

RZ_API bool rz_th_lock_tryenter(RZ_NONNULL RzThreadLock *thl) {
	rz_return_val_if_fail(thl, false);
#if HAVE_PTHREAD
	return !pthread_mutex_trylock(&thl->lock);
#elif __WINDOWS__
	return TryEnterCriticalSection(&thl->lock);
#endif
}

RZ_API void rz_th_lock_leave(RZ_NONNULL RzThreadLock *thl) {
	rz_return_if_fail(thl);
#if HAVE_PTHREAD
	pthread_mutex_unlock(&thl->lock);
#elif __WINDOWS__
	LeaveCriticalSection(&thl->lock);
#endif
}

RZ_API void rz_th_lock_free(RZ_NULLABLE RzThreadLock *thl) {
	if (!thl) {
		return;
	}
#if HAVE_PTHREAD
	pthread_mutex_destroy(&thl->lock);
#elif __WINDOWS__
	DeleteCriticalSection(&thl->lock);
#endif
	free(thl);
}
