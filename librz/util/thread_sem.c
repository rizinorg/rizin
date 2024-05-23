// SPDX-FileCopyrightText: 2018 thestr4ng3r <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "thread.h"

#ifdef __APPLE__
#define RZ_SEM_NAMED_ONLY   1
#define RZ_SEM_NAME_LEN_MAX 31
#else
#define RZ_SEM_NAMED_ONLY 0
#endif

#if RZ_SEM_NAMED_ONLY
#include <uuid/uuid.h>
#include <limits.h>
#endif

RZ_API const char *rz_th_sem_get_errno_str(RzThreadSemaphore *sem) {
	return sem->errno_str;
}

/**
 * \brief  Allocates and initialize a RzThreadSemaphore structure
 *
 * \param  initial  The initial status of the semaphore
 *
 * \return On success returns a valid RzThreadSemaphore pointer, otherwise NULL
 */
RZ_API RZ_OWN RzThreadSemaphore *rz_th_sem_new(unsigned int initial) {
	RzThreadSemaphore *sem = RZ_NEW(RzThreadSemaphore);
	sem->errno_str = "";
	if (!sem) {
		return NULL;
	}
#if HAVE_PTHREAD
#if RZ_SEM_NAMED_ONLY
	uuid_t uuid;
	uuid_generate(uuid);
	char name[38];
	name[0] = '/';
	uuid_unparse(uuid, name + 1);
	if (strlen(name) > RZ_SEM_NAME_LEN_MAX - 1) {
		name[RZ_SEM_NAME_LEN_MAX - 1] = '\0';
	}
	sem->sem = sem_open(name, O_CREAT | O_EXCL, S_IRUSR | S_IWUSR, initial);
	if (sem->sem == SEM_FAILED) {
		sem->errno_str = strdup(strerror(errno));
		// free(sem);
		// return NULL;
		sem->sem = NULL;
		return sem;
	}
#else
	sem->sem = malloc(sizeof(sem_t));
	if (!sem->sem) {
		free(sem);
		return NULL;
	}
	if (sem_init(sem->sem, 0, initial) != 0) {
		free(sem->sem);
		free(sem);
		return NULL;
	}
#endif
#elif __WINDOWS__
	sem->sem = CreateSemaphore(NULL, (LONG)initial, ST32_MAX, NULL);
	if (!sem->sem) {
		free(sem);
		return NULL;
	}
#endif
	return sem;
}

/**
 * \brief  Frees a RzThreadSemaphore struct
 *
 * \param  sem  The RzThreadSemaphore to free
 */
RZ_API void rz_th_sem_free(RZ_NULLABLE RzThreadSemaphore *sem) {
	if (!sem) {
		return;
	}
#if HAVE_PTHREAD
	if (sem->sem) {
#if RZ_SEM_NAMED_ONLY
		sem_close(sem->sem);
#else
		sem_destroy(sem->sem);
		free(sem->sem);
#endif
	}
#elif __WINDOWS__
	CloseHandle(sem->sem);
#endif
	free(sem);
}

/**
 * \brief  increments (releases) a semaphore
 *
 * \param  sem   The RzThreadSemaphore to increment (release)
 */
RZ_API void rz_th_sem_post(RZ_NONNULL RzThreadSemaphore *sem) {
	rz_return_if_fail(sem);
#if HAVE_PTHREAD
	sem_post(sem->sem);
#elif __WINDOWS__
	ReleaseSemaphore(sem->sem, 1, NULL);
#endif
}

/**
 * \brief  Decrements (acquires) the semaphore (waits indefinetely)
 *
 * \param  sem   The RzThreadSemaphore to decrement (acquire)
 */
RZ_API void rz_th_sem_wait(RZ_NONNULL RzThreadSemaphore *sem) {
	rz_return_if_fail(sem);
#if HAVE_PTHREAD
	sem_wait(sem->sem);
#elif __WINDOWS__
	WaitForSingleObject(sem->sem, INFINITE);
#endif
}
