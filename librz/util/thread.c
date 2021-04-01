// SPDX-FileCopyrightText: 2009-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_th.h>
#include <rz_util.h>

#if __APPLE__
// Here to avoid polluting mach types macro redefinitions...
#include <mach/thread_act.h>
#include <mach/thread_policy.h>
#endif

#if __sun
#include <sys/pset.h>
#endif

#if __HAIKU__
#include <kernel/scheduler.h>
#endif

#if __WINDOWS__
static DWORD WINAPI _r_th_launcher(void *_th) {
#else
static void *_r_th_launcher(void *_th) {
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

RZ_API RZ_TH_TID rz_th_self(void) {
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
#elif __APPLE__
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
#if __linux__ || __NetBSD__ || __APPLE__ || __sun
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

	if (sched_setaffinity(th->tid, sizeof(c), &c) != 0) {
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
		pthread_create(&th->tid, NULL, _r_th_launcher, th);
#elif __WINDOWS__
		th->tid = CreateThread(NULL, 0, _r_th_launcher, th, 0, 0);
#endif
	}
	return th;
}

RZ_API void rz_th_break(RzThread *th) {
	th->breaked = true;
}

RZ_API bool rz_th_kill(RzThread *th, bool force) {
	if (!th || !th->tid) {
		return false;
	}
	th->breaked = true;
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
			//rz_th_kill (th, 0);
			rz_th_lock_enter(th->lock); // deadlock?
		}
	}
	th->running = enable;
	return ret;
}

RZ_API int rz_th_wait(struct rz_th_t *th) {
	int ret = false;
	if (th) {
#if HAVE_PTHREAD
		void *thret;
		ret = pthread_join(th->tid, &thret);
#elif __WINDOWS__
		ret = WaitForSingleObject(th->tid, INFINITE);
#endif
		th->running = false;
	}
	return ret;
}

RZ_API int rz_th_wait_async(struct rz_th_t *th) {
	return th->running;
}

RZ_API void *rz_th_free(struct rz_th_t *th) {
	if (!th) {
		return NULL;
	}
#if __WINDOWS__
	CloseHandle(th->tid);
#endif
	rz_th_lock_free(th->lock);
	free(th);
	return NULL;
}

RZ_API void *rz_th_kill_free(struct rz_th_t *th) {
	if (!th) {
		return NULL;
	}
	rz_th_kill(th, true);
	rz_th_free(th);
	return NULL;
}

#if 0

// Thread Pipes
typedef struct rz_th_pipe_t {
	RzList *msglist;
	RzThread *th;
	//RzThreadLock *lock;
} RzThreadPipe;

rz_th_pipe_new();

#endif
