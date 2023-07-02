// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_NATIVE_DEBUGGER_H
#define RZ_NATIVE_DEBUGGER_H
#include <rz_userconf.h>
#include <rz_debug.h>
#include <rz_util.h>
#include <rz_list.h>

/*
 * Linux debugger
 */

#if (__x86_64__ || __i386__)
#include "x86/config.h"
#else /* linux-arch */
#warning Unsupported debugger for this linux platform
#endif /* linux-arch */

#define NATIVE_CAN_STEP           true
#define NATIVE_INIT_CB            native_linux_init
#define NATIVE_FINI_CB            NULL
#define NATIVE_INFO_CB            native_linux_process_info
#define NATIVE_ATTACH_CB          native_linux_process_attach
#define NATIVE_DETACH_CB          native_linux_process_detach
#define NATIVE_SELECT_CB          native_linux_process_select
#define NATIVE_THREADS_CB         native_linux_process_threads
#define NATIVE_PIDS_CB            native_linux_process_list
#define NATIVE_STOP_CB            native_linux_process_stop
#define NATIVE_STEP_CB            native_linux_process_single_step
#define NATIVE_STEP_OVER_CB       NULL
#define NATIVE_CONT_CB            native_linux_process_continue
#define NATIVE_WAIT_CB            NULL
#define NATIVE_GCORE_CB           NULL
#define NATIVE_KILL_CB            NULL
#define NATIVE_CONTSC_CB          NULL
#define NATIVE_FRAMES_CB          NULL
#define NATIVE_BREAKPOINT_CB      NULL
#define NATIVE_REG_READ_CB        NULL
#define NATIVE_REG_WRITE_CB       NULL
#define NATIVE_SYNC_REGISTERS_CB  NULL
#define NATIVE_REG_PROFILE_CB     NULL
#define NATIVE_SET_REG_PROFILE_CB NULL
#define NATIVE_MAP_GET_CB         native_linux_process_list_maps
#define NATIVE_MODULES_GET_CB     NULL
#define NATIVE_MAP_ALLOC_CB       NULL
#define NATIVE_MAP_DEALLOC_CB     NULL
#define NATIVE_MAP_PROTECT_CB     NULL
#define NATIVE_DRX_CB             NULL
#define NATIVE_DESC_CB \
	{ 0 }

bool native_linux_init(RzDebug *dbg, void **user);
RzDebugInfo *native_linux_process_info(RzDebug *dbg, const char *arg);
int native_linux_process_attach(RzDebug *dbg, int pid);
int native_linux_process_detach(RzDebug *dbg, int pid);
int native_linux_process_select(RzDebug *dbg, int pid, int tid);
RzList /*<RzDebugPid *>*/ *native_linux_process_threads(RzDebug *dbg, int pid);
RzList /*<RzDebugPid *>*/ *native_linux_process_list(RzDebug *dbg, int ppid);
int native_linux_process_stop(RzDebug *dbg);
bool native_linux_process_single_step(RzDebug *dbg);
int native_linux_process_continue(RzDebug *dbg, int pid, int tid, int sig);

RzList /*<RzDebugMap *>*/ *native_linux_process_list_maps(RzDebug *dbg);

#endif /* RZ_NATIVE_DEBUGGER_H */
