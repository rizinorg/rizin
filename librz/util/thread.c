// SPDX-FileCopyrightText: 2020-2021 ret2libc <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2020-2022 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2022 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "thread.h"

#if __APPLE__
// Here to avoid polluting mach types macro redefinitions...
#include <mach/thread_act.h>
#include <mach/thread_policy.h>
#endif

#if __APPLE__ || __NetBSD__ || __FreeBSD__ || __OpenBSD__ || __DragonFly__ || __sun
#include <sys/param.h>
#include <sys/sysctl.h>
#endif

#if __sun
#include <sys/pset.h>
#endif

#if __HAIKU__
#include <kernel/scheduler.h>
#include <OS.h>
#endif

/**
 * \brief RzThreadPool is a structure which handles n-threads threads
 *
 * This structure provides methods to handle multiple threads, like they were one.
 */
struct rz_th_pool_t {
	size_t size;
	RzThread **threads;
};

/**
 * \brief RzThreadQueue is a thread-safe queue that can be listened on from multiple threads.
 *
 * This Queue is thread-safe and allows to perform LIFO/FIFO operations.
 * rz_th_queue_new      Allocates a RzThreadQueue structure and allows to limit the size of the queue.
 * rz_th_queue_push     Pushes an element to the queue unless the limit is reached.
 * rz_th_queue_pop      Pops an element from the queue, but returns NULL when is empty.
 * rz_th_queue_wait_pop Pops an element from the queue, but awaits for new elements when is empty.
 * rz_th_queue_free     Frees a RzThreadQueue structure, if the queue is not empty, it frees the elements with the provided qfree function.
 */
struct rz_th_queue_t {
	RzThreadLock *lock;
	RzThreadCond *cond;
	size_t max_size;
	RzList *list;
};

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
	RzThreadStatus status = RZ_TH_STATUS_LOOP;

	while (status == RZ_TH_STATUS_LOOP) {
		status = th->function(th->user);
	}

#if HAVE_PTHREAD
	pthread_exit(NULL);
#endif
	return 0;
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
RZ_API bool rz_th_setname(RZ_NONNULL RzThread *th, RZ_NONNULL const char *name) {
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
RZ_API bool rz_th_getname(RZ_NONNULL RzThread *th, RZ_NONNULL RZ_OUT char *name, size_t len) {
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
RZ_API bool rz_th_setaffinity(RZ_NONNULL RzThread *th, int cpuid) {
	rz_return_val_if_fail(th, false);

#if __linux__
#if defined(__GLIBC__) && defined(__GLIBC_MINOR__) && (__GLIBC__ <= 2) && (__GLIBC_MINOR__ <= 2)
	// Old versions of GNU libc don't have this feature
#pragma message("warning rz_th_setaffinity not implemented")
#else
	cpu_set_t c;
	CPU_ZERO(&c);
	CPU_SET(cpuid, &c);

	if (sched_setaffinity((pid_t)(ut64)th->tid, sizeof(c), &c) != 0) {
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
 * \brief  Force-stops a thread
 *
 * \param  RzThread  The thread to stop
 */
RZ_API void rz_th_kill(RZ_NONNULL RzThread *th) {
	rz_return_if_fail(th);

#if HAVE_PTHREAD
	if (!pthread_kill(th->tid, 0)) {
#ifdef __ANDROID__
		pthread_kill(th->tid, 9);
#else
		pthread_cancel(th->tid);
#endif
	}
#elif __WINDOWS__
	if (WaitForSingleObject(th->tid, 0)) {
		TerminateThread(th->tid, -1);
	}
#endif
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
 * \brief  Stops the thread and frees the RzThread structure
 *
 * \param  th  The thread to stop and free.
 */
RZ_API void rz_th_kill_free(RZ_NONNULL RzThread *th) {
	rz_return_if_fail(th);
	rz_th_kill(th);
	rz_th_free(th);
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

/**
 * \brief      Returns the number of available physical cores of the host machine
 *
 * \return     The number of available physical cores (always >= 1)
 */
RZ_API size_t rz_th_physical_core_number() {
#ifdef __WINDOWS__
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	return sysinfo.dwNumberOfProcessors;
#elif __APPLE__ || __FreeBSD__ || __OpenBSD__ || __DragonFly__ || __NetBSD__
	int os_status = 0;
	int mib[4];
	unsigned long n_cpus = 1;
	size_t n_cpus_length = sizeof(n_cpus);

	/* set the mib for hw.ncpu */
	mib[0] = CTL_HW;
#if __NetBSD__
	mib[1] = HW_NCPUONLINE;
#elif __OpenBSD__ || __FreeBSD__ || __DragonFly__
	mib[1] = HW_NCPU;
#else
	mib[1] = HW_AVAILCPU;
#endif

	os_status = sysctl(mib, 2, &n_cpus, &n_cpus_length, NULL, 0);

	if (os_status != 0) {
#if __OpenBSD__ || __FreeBSD__
		n_cpus = 1;
#else
		// HW_AVAILCPU does not exist.
		mib[1] = HW_NCPU;
		os_status = sysctl(mib, 2, &n_cpus, &n_cpus_length, NULL, 0);
		if (os_status != 0) {
			n_cpus = 1;
		}
#endif
	}
	// this is needed because the upper bits are set on bsd platforms
	n_cpus &= UT32_MAX;

	return n_cpus;
#elif __HAIKU__
	system_info info;
	get_system_info(&info);
	return info.cpu_count;
#else
	return sysconf(_SC_NPROCESSORS_ONLN);
#endif
}

/**
 * \brief returns a new RzThreadPool structure with a pool of thread
 *
 * Returns a new RzThreadPool structure with a pool of thread limited
 * by either the physical core number count or by the value specified
 * by the user (if set to 0, it will be the max physical cores number)
 *
 * \param  max_threads  The maximum number of threads needed in the pool
 * \return RzThreadPool The RzThreadPool structure
 */
RZ_API RZ_OWN RzThreadPool *rz_th_pool_new(size_t max_threads) {
	RzThreadPool *pool = RZ_NEW0(RzThreadPool);
	if (!pool) {
		return NULL;
	}

	size_t cores = rz_th_physical_core_number();
	if (max_threads) {
		cores = RZ_MIN(cores, max_threads);
	}

	pool->size = cores;
	pool->threads = RZ_NEWS0(RzThread *, cores);
	if (!pool->threads) {
		free(pool);
		return NULL;
	}

	return pool;
}

/**
 * \brief Kills (and frees) the threads and frees the RzThreadPool struct
 *
 * \param RzThreadPool *The thread pool to free
 */
RZ_API void rz_th_pool_free(RZ_NULLABLE RzThreadPool *pool) {
	if (!pool) {
		return;
	}
	rz_th_pool_kill_free(pool);
	free(pool->threads);
	free(pool);
}

/**
 * \brief Adds a thread to the thread pool
 *
 * \param  RzThreadPool  The thread pool where to add the thread
 * \param  RzThread      The thread to add to the pool
 * \return true if a slot is found, false otherwise
 */
RZ_API bool rz_th_pool_add_thread(RZ_NONNULL RzThreadPool *pool, RZ_NONNULL RzThread *thread) {
	rz_return_val_if_fail(pool && thread, false);
	for (ut32 i = 0; i < pool->size; ++i) {
		if (!pool->threads[i]) {
			RZ_LOG_DEBUG("thread: thread %u added\n", i);
			pool->threads[i] = thread;
			return true;
		}
	}
	return false;
}

/**
 * \brief  Returns the n-th thread in the thread pool.
 *
 * \param  pool   The thread pool to use
 * \param  index  The index of the thread to get
 *
 * \return Returns the pointer of the n-th thread in the thread pool.
 */
RZ_API RZ_OWN RzThread *rz_th_pool_get_thread(RZ_NONNULL RzThreadPool *pool, size_t index) {
	rz_return_val_if_fail(pool && index < pool->size, NULL);
	return pool->threads[index];
}

/**
 * \brief Waits the end of all the threads in the thread pool
 *
 * \param  RzThreadPool The thread pool to wait for
 *
 * \return true if managed to wait all threads, otherwise false
 */
RZ_API bool rz_th_pool_wait(RZ_NONNULL RzThreadPool *pool) {
	rz_return_val_if_fail(pool, false);
	bool has_exited = true;
	for (ut32 i = 0; i < pool->size; ++i) {
		if (pool->threads[i]) {
			RZ_LOG_DEBUG("thread: waiting for thread %u\n", i);
			has_exited = has_exited && rz_th_wait(pool->threads[i]);
		}
	}
	return has_exited;
}

/**
 * \brief Force-stops all threads in the thread pool
 *
 * \param  pool  The thread pool to kill
 *
 * \return true if managed to kill all threads, otherwise false
 */
RZ_API bool rz_th_pool_kill(RZ_NONNULL RzThreadPool *pool) {
	rz_return_val_if_fail(pool, false);
	bool has_exited = false;
	for (ut32 i = 0; i < pool->size; ++i) {
		if (pool->threads[i]) {
			RZ_LOG_DEBUG("thread: killing thread %u\n", i);
			rz_th_kill(pool->threads[i]);
			has_exited = true;
		}
	}
	return has_exited;
}

/**
 * \brief Force kills all threads in the thread pool and frees them
 *
 * \param  pool The thread pool to kill
 *
 * \return true if managed to kill all threads, otherwise false
 */
RZ_API bool rz_th_pool_kill_free(RZ_NONNULL RzThreadPool *pool) {
	rz_return_val_if_fail(pool, false);
	bool has_exited = false;
	for (ut32 i = 0; i < pool->size; ++i) {
		if (pool->threads[i]) {
			RZ_LOG_DEBUG("thread: killing thread %u\n", i);
			rz_th_kill_free(pool->threads[i]);
			has_exited = true;
			pool->threads[i] = NULL;
		}
	}
	return has_exited;
}

/**
 * \brief  Returns the thread pool size
 *
 * \param  pool  The RzThreadPool to use
 *
 * \return The size of the thread pool (always >= 1).
 */
RZ_API size_t rz_th_pool_size(RZ_NONNULL RzThreadPool *pool) {
	rz_return_val_if_fail(pool, 1);
	return pool->size;
}

/**
 * \brief  Allocates and initializes a new fifo queue
 *
 * \param  max_size  The maximum size of the queue, use RZ_THREAD_QUEUE_UNLIMITED for an unlimited size
 * \param  qfree     Pointer to a custom free function to free the queue if not empty.
 *
 * \return On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzThreadQueue *rz_th_queue_new(size_t max_size, RZ_NULLABLE RzListFree qfree) {
	RzThreadQueue *queue = RZ_NEW0(RzThreadQueue);
	if (!queue) {
		return NULL;
	}

	queue->max_size = max_size;
	queue->list = rz_list_newf(qfree);
	queue->lock = rz_th_lock_new(false);
	queue->cond = rz_th_cond_new();
	if (!queue->list || !queue->lock || !queue->cond) {
		rz_th_queue_free(queue);
		return NULL;
	}

	return queue;
}

/**
 * \brief  Frees a RzThreadQueue structure
 *
 * \param  queue The RzThreadQueue to free
 */
RZ_API void rz_th_queue_free(RZ_NULLABLE RzThreadQueue *queue) {
	if (!queue) {
		return;
	}

	rz_list_free(queue->list);
	rz_th_lock_free(queue->lock);
	rz_th_cond_free(queue->cond);
	free(queue);
}

/**
 * \brief  Pushes a new element into the queue
 *
 * \param  queue The RzThreadQueue to push to
 * \param  user  The non-null pointer to push to the queue
 * \param  tail  When true, appends the element to the tail, otherwise to the head
 *
 * \return On success returns true, otherwise false
 */
RZ_API bool rz_th_queue_push(RZ_NONNULL RzThreadQueue *queue, RZ_NONNULL void *user, bool tail) {
	rz_return_val_if_fail(queue && user, false);

	bool added = false;
	rz_th_lock_enter(queue->lock);
	if (!queue->max_size || rz_list_length(queue->list) < queue->max_size) {
		if (tail) {
			added = rz_list_append(queue->list, user) != NULL;
		} else {
			added = rz_list_prepend(queue->list, user) != NULL;
		}
	}
	if (added) {
		rz_th_cond_signal(queue->cond);
	}
	rz_th_lock_leave(queue->lock);
	return added;
}

/**
 * \brief  Removes an element from the queue, but does not awaits when empty.
 *
 * \param  queue The RzThreadQueue to push to
 * \param  tail  When true, pops the element from the tail, otherwise from the head
 *
 * \return On success returns a valid pointer, otherwise NULL
 */
RZ_API void *rz_th_queue_pop(RZ_NONNULL RzThreadQueue *queue, bool tail) {
	rz_return_val_if_fail(queue, NULL);

	void *user = NULL;
	rz_th_lock_enter(queue->lock);
	if (tail) {
		user = rz_list_pop(queue->list);
	} else {
		user = rz_list_pop_head(queue->list);
	}
	rz_th_lock_leave(queue->lock);
	return user;
}

/**
 * \brief  Removes an element from the queue, but yields the thread till not empty.
 *
 * \param  queue The RzThreadQueue to push to
 * \param  tail  When true, pops the element from the tail, otherwise from the head
 *
 * \return On success returns a valid pointer, otherwise NULL
 */
RZ_API void *rz_th_queue_wait_pop(RZ_NONNULL RzThreadQueue *queue, bool tail) {
	rz_return_val_if_fail(queue, NULL);

	void *user = NULL;
	rz_th_lock_enter(queue->lock);
	if (rz_list_empty(queue->list)) {
		rz_th_cond_wait(queue->cond, queue->lock);
	}
	if (tail) {
		user = rz_list_pop(queue->list);
	} else {
		user = rz_list_pop_head(queue->list);
	}
	rz_th_lock_leave(queue->lock);
	return user;
}
