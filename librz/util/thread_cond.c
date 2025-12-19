// SPDX-FileCopyrightText: 2009-2020 thestr4ng3r <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2022-2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include "thread.h"

/**
 * \brief Condition variables are intended to be used to communicate changes in the state of data shared between threads.
 * Condition variables are always associated with a mutex to provide synchronized access to the shared data.
 *
 * \return On success returns a valid pointer to a RzThreadCond structure.
 */
RZ_API RZ_OWN RzThreadCond *rz_th_cond_new(void) {
	RzThreadCond *cond = RZ_NEW0(RzThreadCond);
	if (!cond) {
		return NULL;
	}
#if HAVE_PTHREAD
	if (pthread_cond_init(&cond->cond, NULL) != 0) {
		free(cond);
		return NULL;
	}
#elif __WINDOWS__
	InitializeConditionVariable(&cond->cond);
#endif
	return cond;
}

/**
 * \brief  This function shall unblock at least one of the threads that are blocked on the specified condition
 *
 * \param  cond The RzThreadCond to use for signalling a waiting thread
 */
RZ_API void rz_th_cond_signal(RZ_NONNULL RzThreadCond *cond) {
	rz_return_if_fail(cond);
#if HAVE_PTHREAD
	pthread_cond_signal(&cond->cond);
#elif __WINDOWS__
	WakeConditionVariable(&cond->cond);
#endif
}

/**
 * \brief  This function shall unblock all threads currently blocked on the specified condition
 *
 * \param  cond The RzThreadCond to use for signalling all waiting threads
 */
RZ_API void rz_th_cond_signal_all(RZ_NONNULL RzThreadCond *cond) {
	rz_return_if_fail(cond);
#if HAVE_PTHREAD
	pthread_cond_broadcast(&cond->cond);
#elif __WINDOWS__
	WakeAllConditionVariable(&cond->cond);
#endif
}

/**
 * \brief  The function shall block on a condition variable and shall be called with RzThreadLock locked by the calling thread.
 *
 * \param  cond  The RzThreadCond to use for waiting the signal
 * \param  lock  The RzThreadLock lock to use (the lock must be already taken by the thread)
 */
RZ_API void rz_th_cond_wait(RZ_NONNULL RzThreadCond *cond, RZ_NONNULL RzThreadLock *lock) {
	rz_return_if_fail(cond);
#if HAVE_PTHREAD
	pthread_cond_wait(&cond->cond, &lock->lock);
#elif __WINDOWS__
	SleepConditionVariableCS(&cond->cond, &lock->lock, INFINITE);
#endif
}

/**
 * \brief  The function shall block up to a given timeout on a condition variable and shall be called with RzThreadLock locked by the calling thread.
 *
 * \param  cond        The RzThreadCond to use for waiting the signal
 * \param  lock        The RzThreadLock lock to use (the lock must be already taken by the thread)
 * \param  timeout_ms  How many millisecs it needs to wait before it is ok to continue.
 */
RZ_API void rz_th_cond_timed_wait(RZ_NONNULL RzThreadCond *cond, RZ_NONNULL RzThreadLock *lock, size_t timeout_ms) {
	rz_return_if_fail(cond);
#if HAVE_PTHREAD
	struct timespec timeout;
	timeout.tv_sec = timeout_ms / 1000;
	timeout.tv_nsec = (timeout_ms % 1000) * 1000000ull;
	pthread_cond_timedwait(&cond->cond, &lock->lock, &timeout);
#elif __WINDOWS__
	SleepConditionVariableCS(&cond->cond, &lock->lock, timeout_ms);
#endif
}

/**
 * \brief  Frees a RzThreadCond struct
 *
 * \param  cond  The RzThreadCond to free
 */
RZ_API void rz_th_cond_free(RZ_NULLABLE RzThreadCond *cond) {
	if (!cond) {
		return;
	}
#if HAVE_PTHREAD
	pthread_cond_destroy(&cond->cond);
#endif
	free(cond);
}
