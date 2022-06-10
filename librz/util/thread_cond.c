// SPDX-FileCopyrightText: 2009-2020 thestr4ng3r <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "thread.h"

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

RZ_API void rz_th_cond_signal(RZ_NONNULL RzThreadCond *cond) {
	rz_return_if_fail(cond);
#if HAVE_PTHREAD
	pthread_cond_signal(&cond->cond);
#elif __WINDOWS__
	WakeConditionVariable(&cond->cond);
#endif
}

RZ_API void rz_th_cond_signal_all(RZ_NONNULL RzThreadCond *cond) {
	rz_return_if_fail(cond);
#if HAVE_PTHREAD
	pthread_cond_broadcast(&cond->cond);
#elif __WINDOWS__
	WakeAllConditionVariable(&cond->cond);
#endif
}

RZ_API void rz_th_cond_wait(RZ_NONNULL RzThreadCond *cond, RZ_NONNULL RzThreadLock *lock) {
	rz_return_if_fail(cond);
#if HAVE_PTHREAD
	pthread_cond_wait(&cond->cond, &lock->lock);
#elif __WINDOWS__
	SleepConditionVariableCS(&cond->cond, &lock->lock, INFINITE);
#endif
}

RZ_API void rz_th_cond_free(RZ_NULLABLE RzThreadCond *cond) {
	if (!cond) {
		return;
	}
#if HAVE_PTHREAD
	pthread_cond_destroy(&cond->cond);
#endif
	free(cond);
}
