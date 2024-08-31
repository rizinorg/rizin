// SPDX-FileCopyrightText: 2023 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2017-2020 condret <condr3t@protonmail.com>
// SPDX-FileCopyrightText: 2017-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2017-2020 alvaro <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_PTRACE_H
#define RZ_PTRACE_H

#include <rz_types.h>

#if __sun
#include <sys/types.h>
#else
#if DEBUGGER && HAVE_PTRACE
#if TARGET_OS_IPHONE
// iOS has ptrace but no header for it
#define PT_TRACE_ME    0 /* child declares it's being traced */
#define PT_READ_I      1 /* read word in child's I space */
#define PT_READ_D      2 /* read word in child's D space */
#define PT_READ_U      3 /* read word in child's user structure */
#define PT_WRITE_I     4 /* write word in child's I space */
#define PT_WRITE_D     5 /* write word in child's D space */
#define PT_WRITE_U     6 /* write word in child's user structure */
#define PT_CONTINUE    7 /* continue the child */
#define PT_KILL        8 /* kill the child process */
#define PT_STEP        9 /* single step the child */
#define PT_ATTACH      10 /* trace some running process */
#define PT_DETACH      11 /* stop tracing a process */
#define PT_SIGEXC      12 /* signals as exceptions for current_proc */
#define PT_THUPDATE    13 /* signal for thread# */
#define PT_ATTACHEXC   14 /* attach to running process with signal exception */
#define PT_FORCEQUOTA  30 /* Enforce quota for root */
#define PT_DENY_ATTACH 31
#define PT_FIRSTMACH   32 /* for machine-specific requests */
int ptrace(int _request, pid_t _pid, caddr_t _addr, int _data);
#else
#include <sys/ptrace.h>
#endif
#endif
#endif

#if (defined(__GLIBC__) && defined(__linux__))
typedef enum __ptrace_request rz_ptrace_request_t;
typedef void *rz_ptrace_data_t;
#define RZ_PTRACE_NODATA NULL
#else
#if __ANDROID__
typedef int rz_ptrace_request_t;
typedef void *rz_ptrace_data_t;
#define RZ_PTRACE_NODATA NULL
#elif __APPLE__ || __OpenBSD__ || __NetBSD__ || __FreeBSD__ || __DragonFly__
typedef int rz_ptrace_request_t;
typedef int rz_ptrace_data_t;
#define RZ_PTRACE_NODATA 0
#else
typedef int rz_ptrace_request_t;
typedef void *rz_ptrace_data_t;
#define RZ_PTRACE_NODATA NULL
#endif
#endif

#endif
