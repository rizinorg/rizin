// SPDX-FileCopyrightText: 2009-2020 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_th.h>

RZ_API RzThreadCond *rz_th_cond_new(void) {
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

RZ_API void rz_th_cond_signal(RzThreadCond *cond) {
#if HAVE_PTHREAD
	pthread_cond_signal(&cond->cond);
#elif __WINDOWS__
	WakeConditionVariable(&cond->cond);
#endif
}

RZ_API void rz_th_cond_signal_all(RzThreadCond *cond) {
#if HAVE_PTHREAD
	pthread_cond_broadcast(&cond->cond);
#elif __WINDOWS__
	WakeAllConditionVariable(&cond->cond);
#endif
}

RZ_API void rz_th_cond_wait(RzThreadCond *cond, RzThreadLock *lock) {
#if HAVE_PTHREAD
	pthread_cond_wait(&cond->cond, &lock->lock);
#elif __WINDOWS__
	SleepConditionVariableCS(&cond->cond, &lock->lock, INFINITE);
#endif
}

RZ_API void rz_th_cond_free(RzThreadCond *cond) {
	if (!cond) {
		return;
	}
#if HAVE_PTHREAD
	pthread_cond_destroy(&cond->cond);
#endif
	free(cond);
}
