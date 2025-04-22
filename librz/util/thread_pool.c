// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_th.h>
#include "thread.h"
#include <rz_userconf.h>

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
 * \brief      Returns the number of available physical cores of the host machine
 *
 * \return     The number of available physical cores (always >= 1)
 */
RZ_API RzThreadNCores rz_th_physical_core_number() {
#ifdef __WINDOWS__
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	return (RzThreadNCores)sysinfo.dwNumberOfProcessors;
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

	return (RzThreadNCores)n_cpus;
#elif __HAIKU__
	system_info info;
	get_system_info(&info);
	return (RzThreadNCores)info.cpu_count;
#else
	return (RzThreadNCores)sysconf(_SC_NPROCESSORS_ONLN);
#endif
}

/**
 * \brief      Returns the maximum number of threads available unless it exeeds N_THREAD_LIMIT.
 *	           When set to 0, it will be the max number of cores.
 *
 * \param[in]  max_threads  The maximum number of threads to request
 *
 * \return     The max number of threads requested
 */
RZ_API RzThreadNCores rz_th_max_threads(RzThreadNCores requested) {
	const size_t n_thread_limit = N_THREAD_LIMIT;
	RzThreadNCores n_cores = rz_th_physical_core_number();
	if (requested <= RZ_THREAD_N_CORES_ALL_AVAILABLE) {
		return n_cores;
	} else if (n_thread_limit < (size_t)requested) {
		RZ_LOG_WARN("The number of requested threads is higher than the thread limit (%" PFMTSZu ").\n", n_thread_limit);
		return n_thread_limit;
	}
	return requested;
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
RZ_API RZ_OWN RzThreadPool *rz_th_pool_new(RzThreadNCores max_threads) {
	RzThreadPool *pool = RZ_NEW0(RzThreadPool);
	if (!pool) {
		return NULL;
	}

	pool->size = (size_t)rz_th_max_threads(max_threads);
	pool->threads = RZ_NEWS0(RzThread *, pool->size);
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
	for (ut32 i = 0; i < pool->size; ++i) {
		if (pool->threads[i]) {
			rz_th_free(pool->threads[i]);
			pool->threads[i] = NULL;
		}
	}
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
RZ_API RZ_BORROW RzThread *rz_th_pool_get_thread(RZ_NONNULL RzThreadPool *pool, size_t index) {
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