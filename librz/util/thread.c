// SPDX-FileCopyrightText: 2009-2018 pancake <pancake@nopcode.org>
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

#if __WINDOWS__
static DWORD WINAPI _rz_th_launcher(void *_th) {
#else
static void *_rz_th_launcher(void *_th) {
#endif
	int ret;
	RzThread *th = _th;
	th->ready = true;
	if (th->delay > 0) {
		rz_sys_sleep(th->delay);
	} else if (th->delay < 0) {
		rz_th_lock_wait(th->lock);
	}
	rz_th_lock_enter(th->lock);
	do {
		rz_th_lock_leave(th->lock);
		th->running = true;
		ret = th->fun(th);
		if (ret < 0) {
			// th has been freed
			return 0;
		}
		th->running = false;
		rz_th_lock_enter(th->lock);
	} while (ret);
	rz_th_lock_leave(th->lock);
#if HAVE_PTHREAD
	pthread_exit(&ret);
#endif
	return 0;
}

RZ_API int rz_th_push_task(struct rz_th_t *th, void *user) {
	int ret = true;
	th->user = user;
	rz_th_lock_leave(th->lock);
	return ret;
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

RZ_API bool rz_th_setname(RzThread *th, const char *name) {
#if defined(HAVE_PTHREAD_NP) && HAVE_PTHREAD_NP
#if __linux__ || __sun
	if (pthread_setname_np(th->tid, name) != 0) {
		eprintf("Failed to set thread name\n");
		return false;
	}
#elif __APPLE__ && defined(MAC_OS_X_VERSION_10_6)
	if (pthread_setname_np(name) != 0) {
		eprintf("Failed to set thread name\n");
		return false;
	}
#elif __FreeBSD__ || __OpenBSD__ || __DragonFly__ || __sun
	pthread_set_name_np(th->tid, name);
#elif __NetBSD__
	if (pthread_setname_np(th->tid, "%s", (void *)name) != 0) {
		eprintf("Failed to set thread name\n");
		return false;
	}
#elif __HAIKU__
	if (rename_thread((thread_id)th->tid, name) != B_OK) {
		eprintf("Failed to set thread name\n");
		return false;
	}
#else
#pragma message("warning rz_th_setname not implemented")
#endif
#endif
	return true;
}

RZ_API bool rz_th_getname(RzThread *th, char *name, size_t len) {
#if defined(HAVE_PTHREAD_NP) && HAVE_PTHREAD_NP
#if __linux__ || __NetBSD__ || (__APPLE__ && defined(MAC_OS_X_VERSION_10_6)) || __sun
	if (pthread_getname_np(th->tid, name, len) != 0) {
		eprintf("Failed to get thread name\n");
		return false;
	}
#elif (__FreeBSD__ && __FreeBSD_version >= 1200000) || __DragonFly__ || (__OpenBSD__ && OpenBSD >= 201905)
	pthread_get_name_np(th->tid, name, len);
#elif defined(__HAIKU__)
	thread_info ti;
	size_t flen = len < B_OS_NAME_LENGTH ? len : B_OS_NAME_LENGTH;

	if (get_thread_info((thread_id)th->tid, &ti) != B_OK) {
		eprintf("Failed to get thread name\n");
		return false;
	}

	rz_str_ncpy(name, ti.name, flen);
#else
#pragma message("warning rz_th_getname not implemented")
#endif
#endif
	return true;
}

RZ_API bool rz_th_setaffinity(RzThread *th, int cpuid) {
#if __linux__
#if defined(__GLIBC__) && defined(__GLIBC_MINOR__) && (__GLIBC__ <= 2) && (__GLIBC_MINOR__ <= 2)
	// Old versions of GNU libc don't have this feature
#pragma message("warning rz_th_setaffinity not implemented")
#else
	cpu_set_t c;
	CPU_ZERO(&c);
	CPU_SET(cpuid, &c);

	if (sched_setaffinity((pid_t)(ut64)th->tid, sizeof(c), &c) != 0) {
		eprintf("Failed to set cpu affinity\n");
		return false;
	}
#endif
#elif __FreeBSD__ || __DragonFly__
	cpuset_t c;
	CPU_ZERO(&c);
	CPU_SET(cpuid, &c);

	if (pthread_setaffinity_np(th->tid, sizeof(c), &c) != 0) {
		eprintf("Failed to set cpu affinity\n");
		return false;
	}
#elif __NetBSD__
	cpuset_t *c;
	c = cpuset_create();

	if (pthread_setaffinity_np(th->tid, cpuset_size(c), c) != 0) {
		cpuset_destroy(c);
		eprintf("Failed to set cpu affinity\n");
		return false;
	}

	cpuset_destroy(c);
#elif __APPLE__
	thread_affinity_policy_data_t c = { cpuid };
	if (thread_policy_set(pthread_mach_thread_np(th->tid),
		    THREAD_AFFINITY_POLICY, (thread_policy_t)&c, 1) != KERN_SUCCESS) {
		eprintf("Failed to set cpu affinity\n");
		return false;
	}
#elif __WINDOWS__
	if (SetThreadAffinityMask(th->tid, (DWORD_PTR)1 << cpuid) == 0) {
		eprintf("Failed to set cpu affinity\n");
		return false;
	}
#elif __sun
	psetid_t c;

	pset_create(&c);
	pset_assign(c, cpuid, NULL);

	if (pset_bind(c, P_PID, getpid(), NULL)) {
		pset_destroy(c);
		eprintf("Failed to set cpu affinity\n");
		return false;
	}

	pset_destroy(c);
#else
#pragma message("warning rz_th_setaffinity not implemented")
#endif
	return true;
}

RZ_API RzThread *rz_th_new(RZ_TH_FUNCTION(fun), void *user, int delay) {
	RzThread *th = RZ_NEW0(RzThread);
	if (th) {
		th->lock = rz_th_lock_new(false);
		th->running = false;
		th->fun = fun;
		th->user = user;
		th->delay = delay;
		th->breaked = false;
		th->ready = false;
#if HAVE_PTHREAD
		pthread_create(&th->tid, NULL, _rz_th_launcher, th);
#elif __WINDOWS__
		th->tid = CreateThread(NULL, 0, _rz_th_launcher, th, 0, 0);
#endif
	}
	return th;
}

RZ_API void rz_th_break(RzThread *th) {
	th->breaked = true;
}

RZ_API bool rz_th_kill(RzThread *th, bool force) {
	if (!th || !th->tid || !th->running) {
		return false;
	}
	th->breaked = true;
	th->running = false;
	rz_th_break(th);
	rz_th_wait(th);
#if HAVE_PTHREAD
#ifdef __ANDROID__
	pthread_kill(th->tid, 9);
#else
	pthread_cancel(th->tid);
#endif
#elif __WINDOWS__
	TerminateThread(th->tid, -1);
#endif
	return 0;
}

RZ_API bool rz_th_start(RzThread *th, int enable) {
	bool ret = true;
	if (enable) {
		if (!th->running) {
			// start thread
			while (!th->ready) {
				/* spinlock */
			}
			rz_th_lock_leave(th->lock);
		}
	} else {
		if (th->running) {
			// stop thread
			// rz_th_kill (th, 0);
			rz_th_lock_enter(th->lock); // deadlock?
		}
	}
	th->running = enable;
	return ret;
}

RZ_API bool rz_th_wait(RzThread *th) {
	bool ret = false;
	if (th) {
#if HAVE_PTHREAD
		void *thret = NULL;
		ret = pthread_join(th->tid, &thret);
#elif __WINDOWS__
		ret = WaitForSingleObject(th->tid, INFINITE);
#endif
		th->running = false;
	}
	return ret;
}

RZ_API bool rz_th_wait_async(RzThread *th) {
	return th->running;
}

RZ_API void rz_th_free(RzThread *th) {
	if (!th) {
		return;
	}
#if __WINDOWS__
	CloseHandle(th->tid);
#endif
	rz_th_lock_free(th->lock);
	free(th);
}

RZ_API void rz_th_kill_free(RzThread *th) {
	if (!th) {
		return;
	}
	rz_th_kill(th, true);
	rz_th_free(th);
}

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
 * @brief Starts all the threads in the thread pool
 *
 * @param RzThreadPool  The thread pool to start
 * @param enable        Enable the thread or disables them (see rz_th_start)
 *
 * @return returns true if starts any thread from the pool, otherwise false
 */
RZ_API bool rz_th_pool_start(RZ_NONNULL RzThreadPool *pool, bool enable) {
	rz_return_val_if_fail(pool, false);
	bool started = false;
	for (ut32 i = 0; i < pool->size; ++i) {
		if (pool->threads[i]) {
			RZ_LOG_DEBUG("thread: started thread %u\n", i);
			rz_th_start(pool->threads[i], enable);
			started = true;
		}
	}
	if (!started) {
		RZ_LOG_ERROR("thread: cannot start thread pool when there are no threads in it\n");
	}
	return started;
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
			has_exited &= !rz_th_wait(pool->threads[i]);
		}
	}
	return has_exited;
}

/**
 * \brief Waits asynchronously the end of all the threads in the thread pool
 *
 * \param  RzThreadPool The thread pool to wait for
 *
 * \return true if managed to wait all threads, otherwise false
 */
RZ_API bool rz_th_pool_wait_async(RZ_NONNULL RzThreadPool *pool) {
	rz_return_val_if_fail(pool, false);
	bool has_exited = true;
	for (ut32 i = 0; i < pool->size; ++i) {
		if (pool->threads[i]) {
			RZ_LOG_DEBUG("thread: waiting for thread %u (async)\n", i);
			has_exited &= !rz_th_wait_async(pool->threads[i]);
		}
	}
	return has_exited;
}

/**
 * \brief Kills all threads in the thread pool
 *
 * \param  pool  The thread pool to kill
 * \param  force Set to true if force killing the threads
 *
 * \return true if managed to kill all threads, otherwise false
 */
RZ_API bool rz_th_pool_kill(RZ_NONNULL RzThreadPool *pool, bool force) {
	rz_return_val_if_fail(pool, false);
	bool has_exited = false;
	for (ut32 i = 0; i < pool->size; ++i) {
		if (pool->threads[i]) {
			RZ_LOG_DEBUG("thread: killing thread %u\n", i);
			rz_th_kill(pool->threads[i], force);
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
 * \brief Returns user pointer of thread
 *
 * \param  th The thread to get the user pointer from
 *
 * \return user pointer set by the rz_th_new user parameter
 */
RZ_API void *rz_th_get_user(RzThread *th) {
	return th->user;
}
