// SPDX-FileCopyrightText: 2018-2021 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PTRACE_WRAP_H
#define PTRACE_WRAP_H

#include <pthread.h>
#include <semaphore.h>
#include <sys/ptrace.h>

#ifdef __GLIBC__
typedef enum __ptrace_request ptrace_wrap_ptrace_request;
#else
typedef int ptrace_wrap_ptrace_request;
#endif

typedef enum {
	PTRACE_WRAP_REQUEST_TYPE_STOP,
	PTRACE_WRAP_REQUEST_TYPE_PTRACE,
	PTRACE_WRAP_REQUEST_TYPE_FORK,
	PTRACE_WRAP_REQUEST_TYPE_FUNC
} ptrace_wrap_request_type;

typedef void *(*ptrace_wrap_func_func)(void *);

typedef struct ptrace_wrap_request_t {
	ptrace_wrap_request_type type;
	union {
		struct {
			ptrace_wrap_ptrace_request request;
			pid_t pid;
			void *addr;
			void *data;
			int *_errno;
		} ptrace;
		struct {
			void (*child_callback)(void *);
			void *child_callback_user;
			int *_errno;
		} fork;
		struct {
			ptrace_wrap_func_func func;
			void *user;
		} func;
	};
} ptrace_wrap_request;

typedef struct ptrace_wrap_instance_t {
	pthread_t th;
	sem_t request_sem;
	ptrace_wrap_request request;
	sem_t result_sem;
	union {
		long ptrace_result;
		pid_t fork_result;
		void *func_result;
	};
} ptrace_wrap_instance;

int ptrace_wrap_instance_start(ptrace_wrap_instance *inst);
void ptrace_wrap_instance_stop(ptrace_wrap_instance *inst);
long ptrace_wrap(ptrace_wrap_instance *inst, ptrace_wrap_ptrace_request request, pid_t pid, void *addr, void *data);
pid_t ptrace_wrap_fork(ptrace_wrap_instance *inst, void (*child_callback)(void *), void *child_callback_user);
void *ptrace_wrap_func(ptrace_wrap_instance *inst, ptrace_wrap_func_func func, void *user);

#endif // PTRACE_WRAP_H
