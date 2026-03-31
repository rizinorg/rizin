// SPDX-FileCopyrightText: 2020-2021 ret2libc <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2020-2022 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2022 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "thread.h"

/*
 * Main thread function, this function is meant to be
 * hidden from the user which is using the C APIs.
 */
static RZ_TH_RET_T thread_main_function(void *_th) {
#if HAVE_PTHREAD
#ifndef __ANDROID__
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
#endif
#endif
	RzThread *th = (RzThread *)_th;
	th->terminated = false;
	th->retv = th->function(th->user);
	th->terminated = true;
	return (RZ_TH_RET_T)0;
}

RZ_IPI RZ_TH_TID rz_th_self(void) {
#if HAVE_PTHREAD
	return pthread_self();
#elif __WINDOWS__
	return GetCurrentThread();
#else
#pragma message("Not implemented on this platform")
	return (RZ_TH_TID)-1;
#endif
}

/**
 * \brief Sets the name of the thread
 *
 * \param  th    The thread to rename
 * \param  name  The name to assign to the thread
 *
 * \return On success returns true, otherwise false
 */
RZ_API bool rz_th_set_name(RZ_NONNULL RzThread *th, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(th && name, false);

#if defined(HAVE_PTHREAD_NP) && HAVE_PTHREAD_NP
#if __linux__ || __sun
	if (pthread_setname_np(th->tid, name) != 0) {
		RZ_LOG_ERROR("thread: Failed to set thread name\n");
		return false;
	}
#elif __APPLE__ && defined(MAC_OS_X_VERSION_10_6)
	if (pthread_setname_np(name) != 0) {
		RZ_LOG_ERROR("thread: Failed to set thread name\n");
		return false;
	}
#elif __FreeBSD__ || __OpenBSD__ || __DragonFly__ || __sun
	pthread_set_name_np(th->tid, name);
#elif __NetBSD__
	if (pthread_setname_np(th->tid, "%s", (void *)name) != 0) {
		RZ_LOG_ERROR("thread: Failed to set thread name\n");
		return false;
	}
#elif __HAIKU__
	if (rename_thread((thread_id)th->tid, name) != B_OK) {
		RZ_LOG_ERROR("thread: Failed to set thread name\n");
		return false;
	}
#else
#pragma message("warning rz_th_setname not implemented")
#endif
#endif
	return true;
}

/**
 * \brief Gets the name of the thread and writes it into the output buffer
 *
 * \param  th    The thread from which the name is taken
 * \param  name  The output buffer name to use to copy the name
 * \param  len   The output buffer length
 *
 * \return On success returns true, otherwise false
 */
RZ_API bool rz_th_get_name(RZ_NONNULL RzThread *th, RZ_NONNULL RZ_OUT char *name, size_t len) {
	rz_return_val_if_fail(th && name && len > 0, false);

#if defined(HAVE_PTHREAD_NP) && HAVE_PTHREAD_NP
#if __linux__ || __NetBSD__ || (__APPLE__ && defined(MAC_OS_X_VERSION_10_6)) || __sun
	if (pthread_getname_np(th->tid, name, len) != 0) {
		RZ_LOG_ERROR("thread: Failed to get thread name\n");
		return false;
	}
#elif (__FreeBSD__ && __FreeBSD_version >= 1200000) || __DragonFly__ || (__OpenBSD__ && OpenBSD >= 201905)
	pthread_get_name_np(th->tid, name, len);
#elif defined(__HAIKU__)
	thread_info ti;
	size_t flen = len < B_OS_NAME_LENGTH ? len : B_OS_NAME_LENGTH;

	if (get_thread_info((thread_id)th->tid, &ti) != B_OK) {
		RZ_LOG_ERROR("thread: Failed to get thread name\n");
		return false;
	}

	rz_str_ncpy(name, ti.name, flen);
#else
#pragma message("warning rz_th_getname not implemented")
#endif
#endif
	return true;
}

/**
 * \brief Sets the thread cpu affinity
 *
 * \param  th     The thread to change the cpu affinity
 * \param  cpuid  The cpuid to set to the thread.
 *
 * \return On success returns true, otherwise false.
 */
RZ_API bool rz_th_set_affinity(RZ_NONNULL RzThread *th, int cpuid) {
	rz_return_val_if_fail(th, false);

#if __linux__
#if defined(__GLIBC__) && defined(__GLIBC_MINOR__) && (__GLIBC__ <= 2) && (__GLIBC_MINOR__ <= 2)
	// Old versions of GNU libc don't have this feature
#pragma message("warning rz_th_setaffinity not implemented")
#else
	cpu_set_t c;
	CPU_ZERO(&c);
	CPU_SET(cpuid, &c);

	if (sched_setaffinity((pid_t)th->tid, sizeof(c), &c) != 0) {
		RZ_LOG_ERROR("thread: Failed to set cpu affinity\n");
		return false;
	}
#endif
#elif __FreeBSD__ || __DragonFly__
	cpuset_t c;
	CPU_ZERO(&c);
	CPU_SET(cpuid, &c);

	if (pthread_setaffinity_np(th->tid, sizeof(c), &c) != 0) {
		RZ_LOG_ERROR("thread: Failed to set cpu affinity\n");
		return false;
	}
#elif __NetBSD__
	cpuset_t *c;
	c = cpuset_create();

	if (pthread_setaffinity_np(th->tid, cpuset_size(c), c) != 0) {
		cpuset_destroy(c);
		RZ_LOG_ERROR("thread: Failed to set cpu affinity\n");
		return false;
	}

	cpuset_destroy(c);
#elif __APPLE__
	thread_affinity_policy_data_t c = { cpuid };
	if (thread_policy_set(pthread_mach_thread_np(th->tid),
		    THREAD_AFFINITY_POLICY, (thread_policy_t)&c, 1) != KERN_SUCCESS) {
		RZ_LOG_ERROR("thread: Failed to set cpu affinity\n");
		return false;
	}
#elif __WINDOWS__
	if (SetThreadAffinityMask(th->tid, (DWORD_PTR)1 << cpuid) == 0) {
		RZ_LOG_ERROR("thread: Failed to set cpu affinity\n");
		return false;
	}
#elif __sun
	psetid_t c;

	pset_create(&c);
	pset_assign(c, cpuid, NULL);

	if (pset_bind(c, P_PID, getpid(), NULL)) {
		pset_destroy(c);
		RZ_LOG_ERROR("thread: Failed to set cpu affinity\n");
		return false;
	}

	pset_destroy(c);
#else
#pragma message("warning rz_th_setaffinity not implemented")
#endif
	return true;
}

/**
 * \brief      Creates and starts a new thread.
 *
 * \param      function  The callback to call when the thread starts.
 * \param      user      A pointer to a user structure to pass to the callback function
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_API RZ_OWN RzThread *rz_th_new(RZ_NONNULL RzThreadFunction function, RZ_NULLABLE void *user) {
	rz_return_val_if_fail(function, NULL);

	RzThread *th = RZ_NEW0(RzThread);
	if (!th) {
		RZ_LOG_ERROR("thread: Failed to allocate RzThread\n");
		return NULL;
	}

	th->function = function;
	th->user = user;

#if HAVE_PTHREAD
	if (!pthread_create(&th->tid, NULL, thread_main_function, th)) {
		return th;
	}
#elif __WINDOWS__
	if ((th->tid = CreateThread(NULL, 0, thread_main_function, th, 0, 0))) {
		return th;
	}
#endif
	RZ_LOG_ERROR("thread: Failed to start the RzThread\n");
	free(th);
	return NULL;
}

/**
 * \brief      Awaits indefinetely for a thread to join
 *
 * \param[in]  th  The thread to await for.
 *
 * \return     On graceful stop returns true, otherwise false
 */
RZ_API bool rz_th_wait(RZ_NONNULL RzThread *th) {
	rz_return_val_if_fail(th, false);
#if HAVE_PTHREAD
	void *thret = NULL;
	return pthread_join(th->tid, &thret) == 0;
#elif __WINDOWS__
	return WaitForSingleObject(th->tid, INFINITE) == 0; // WAIT_OBJECT_0
#endif
}

/**
 * \brief  Frees a RzThread structure
 *
 * \param  th  The RzThread to free
 */
RZ_API void rz_th_free(RZ_NULLABLE RzThread *th) {
	if (!th) {
		return;
	}
#if __WINDOWS__
	CloseHandle(th->tid);
#endif
	free(th);
}

/**
 * \brief Returns user pointer of thread
 *
 * \param  th The thread to get the user pointer from
 *
 * \return user pointer set by the rz_th_new user parameter
 */
RZ_API RZ_OWN void *rz_th_get_user(RZ_NONNULL RzThread *th) {
	rz_return_val_if_fail(th, NULL);
	return th->user;
}

/**
 * \brief Returns return value of the thread
 *
 * \param  th The thread to get the return value from
 *
 * \return returns a pointer set when the thread returns
 */
RZ_API RZ_OWN void *rz_th_get_retv(RZ_NONNULL RzThread *th) {
	rz_return_val_if_fail(th, NULL);
	return th->retv;
}

/**
 * \brief Checks if a thread returned. This function is non-blocking.
 *
 * \param th The thread to check.
 *
 * \return True if the thread terminated. False otherwise,
 */
RZ_API bool rz_th_terminated(const RZ_NONNULL RzThread *th) {
	rz_return_val_if_fail(th, false);
	return th->terminated;
}

/**
 * \brief Yield the processor
 *
 * \return On success returns true, otherwise false
 */
RZ_API bool rz_th_yield(void) {
#if __WINDOWS__
	return SwitchToThread() != 0;
#else
	// sched_yield is not available everywhere.
	// usleep is more portable.
	rz_sys_usleep(1);
	return true;
#endif
}
