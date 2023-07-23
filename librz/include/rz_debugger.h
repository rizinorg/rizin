// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_DEBUGGER_H
#define RZ_DEBUGGER_H

#include <rz_util.h>
#include <rz_reg.h>
#include <rz_bp.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RZ_PROCESS_ID_INVALID (-1)

typedef int RzPid;
typedef int RzSyscallId;

typedef enum {
	RZ_SIGNAL_UNKNOWN = 0,
	RZ_SIGNAL_HUP, ///< Signal hangup
	RZ_SIGNAL_INT, ///< Signal interrupt
	RZ_SIGNAL_QUIT, ///< Signal quit
	RZ_SIGNAL_ILL, ///< Signal illegal instruction
	RZ_SIGNAL_TRAP, ///< Signal trace/breakpoint trap
	RZ_SIGNAL_ABRT, ///< Signal abort
	RZ_SIGNAL_FPE, ///< Signal floating-point exception
	RZ_SIGNAL_KILL, ///< Signal kill
	RZ_SIGNAL_SEGV, ///< Signal segmentation fault
	RZ_SIGNAL_PIPE, ///< Signal broken pipe
	RZ_SIGNAL_ALRM, ///< Signal alarm clock
	RZ_SIGNAL_TERM, ///< Signal termination
	RZ_SIGNAL_USR1, ///< Signal user-defined signal 1
	RZ_SIGNAL_USR2, ///< Signal user-defined signal 2
	RZ_SIGNAL_CHLD, ///< Signal child process status change
	RZ_SIGNAL_CONT, ///< Signal continue
	RZ_SIGNAL_STOP, ///< Signal stop (cannot be caught or ignored)
	/* enum max value */
	RZ_SIGNAL_ENUM_MAX,
} RzSignal;

typedef enum {
	RZ_PROCESS_STATE_UNKNOWN = 0,
	RZ_PROCESS_STATE_STOP, ///< The process has been stopped
	RZ_PROCESS_STATE_RUN, ///< The process is running
	RZ_PROCESS_STATE_SLEEP, ///< The process is sleeping in an interruptible wait
	RZ_PROCESS_STATE_ZOMBIE, ///< The process is a zombie
	RZ_PROCESS_STATE_DEAD, ///< The process is dead (i.e. not running anymore)
	/* enum max value */
	RZ_PROCESS_STATE_ENUM_MAX,
} RzProcessState;

typedef struct rz_process_info_t {
	RzPid id; ///< Process Identifier
	RzPid parent; ///< Process parent identifier
	RzProcessState state; ///< Process current state
	char *name; ///< Process name (can contain the executable name or path)
	char *owner; ///< Process owner (can be unix uid:gid or windows sid, etc..)
} RzProcessInfo;

typedef RzList /*<RzProcessInfo *>*/ *(*RzProcessInfoList)(void *context, const RzPid parent);
typedef bool (*RzProcessGetInfo)(void *context, const RzPid process, RzProcessInfo *info);
typedef bool (*RzProcessAction)(void *context, const RzPid process);
typedef bool (*RzProcessSelectAction)(void *context, const RzPid process, const RzPid thread);
typedef bool (*RzProcessActionSignal)(void *context, const RzPid process, const RzSignal signal_id);
typedef bool (*RzProcessActionSyscall)(void *context, const RzPid process, const RzSyscallId syscall_id);
typedef RzList /*<RzProcessTrace *>*/ *(*RzProcessBacktrace)(void *context, const RzPid process, const ut64 address);
typedef bool (*RzProcessRegisterAction)(void *context, const RzPid process, RzReg *reg, RzRegItem *item, bool read);
typedef bool (*RzProcessRegisterGetProfile)(void *context, const RzPid process, char **profile);
typedef bool (*RzProcessRegisterSetProfile)(void *context, const RzPid process, char *profile);
typedef RzList /*<RzProcessMemoryMap *>*/ *(*RzProcessMemoryMap)(void *context, const RzPid process);
typedef bool (*RzProcessFile)(void *context, const char *path, RzBuffer *dest);

typedef struct rz_debugger_plugin_t {
	const char *name; ///< Plugin name
	const char *license; ///< Plugin license
	const char *author; ///< Plugin author
	const char *version; ///< Plugin version
	/* plugin constructor/destructor */
	void *(*init)(void); ///< Constructor of the plugin
	void (*fini)(void *context); ///< Destructor of the plugin
	/* process information */
	RzProcessGetInfo info; ///< Returns the information regarding a process
	/* process actions */
	RzProcessAction attach; ///< Attach to a process
	RzProcessAction detach; ///< Detach from a process
	RzProcessSelectAction select; ///< Selects a thread/process linked to a process parent
	RzProcessInfoList threads; ///< Returns the list of processes/threads linked to a process id
	RzProcessInfoList processes; ///< Returns the list of processes linked to a parent id (parent 0 for all the processes)
	RzProcessAction step; ///< Steps over an instruction
	RzProcessAction step_over; ///< Steps over a call
	RzProcessActionSignal continue_signal; ///< Continue the process after a signal
	RzProcessActionSyscall continue_syscall; ///< Continue the process after a syscall
	RzProcessAction wait; ///< Awaits for the process
	RzProcessAction stop; ///< Stops the execution of the process
	RzProcessActionSignal kill; ///< Sends a signal to kill the process
	RzProcessBacktrace backtrace; ///< Returns the backtrace of a process at a given address
	/* process register */
	RzProcessRegisterAction register_sync; ///< Allows syncronization of one or all registers, from and to the debugger.
	RzProcessRegisterGetProfile profile_get; ///< Gets the process register profile
	RzProcessRegisterSetProfile profile_set; ///< Sets the process register profile
	/* process memory */
	RzProcessMemoryMap memory_get; ///< Returns the process memory mapping
	RzProcessMemoryMap modules_get; ///< Returns the process module mapping
	/* process file operations */
	RzProcessFile new_core_file; ///< Allows to generate a core file of the process
	RzProcessFile download_file; ///< Allows to download the binary from the remote location
} RzDebuggerPlugin;

typedef struct rz_debugger_t {
	const RzDebuggerPlugin *handle;
	void *handle_ctx;
	RzPid process_id;
	RzPid thread_id;
	RzList /*<RzDebuggerPlugin *>*/ *plugins;
} RzDebugger;

#ifdef RZ_API
RZ_API RZ_OWN RzDebugger *rz_debugger_new(void);
RZ_API void rz_debugger_free(RZ_NULLABLE RzDebugger *dbg);
RZ_API bool rz_debugger_plugin_add(RZ_NONNULL RzDebugger *dbg, RZ_NONNULL RzDebuggerPlugin *plugin);
RZ_API bool rz_debugger_plugin_del(RZ_NONNULL RzDebugger *dbg, RZ_NONNULL RzDebuggerPlugin *plugin);
RZ_API bool rz_debugger_use(RZ_NONNULL RzDebugger *dbg, RZ_NONNULL const char *name);

/* Debugger Process API */
RZ_API bool rz_debugger_process_info(RZ_NONNULL RzDebugger *dbg, RZ_NONNULL RzProcessInfo *info);
RZ_API bool rz_debugger_process_attach(RZ_NONNULL RzDebugger *dbg, const RzPid process);
RZ_API bool rz_debugger_process_detach(RZ_NONNULL RzDebugger *dbg);
RZ_API bool rz_debugger_process_select(RZ_NONNULL RzDebugger *dbg, const RzPid process, const RzPid thread);
RZ_API RzList /*<RzProcessInfo *>*/ *rz_debugger_process_threads(RZ_NONNULL RzDebugger *dbg);
RZ_API RzList /*<RzProcessInfo *>*/ *rz_debugger_process_processes(RZ_NONNULL RzDebugger *dbg);
RZ_API bool rz_debugger_process_step(RZ_NONNULL RzDebugger *dbg);
RZ_API bool rz_debugger_process_step_over(RZ_NONNULL RzDebugger *dbg);
RZ_API bool rz_debugger_process_continue_signal(RZ_NONNULL RzDebugger *dbg, const RzSignal signal_id);
RZ_API bool rz_debugger_process_continue_syscall(RZ_NONNULL RzDebugger *dbg, const RzSyscallId syscall_id);
RZ_API bool rz_debugger_process_wait(RZ_NONNULL RzDebugger *dbg);
RZ_API bool rz_debugger_process_stop(RZ_NONNULL RzDebugger *dbg);
RZ_API bool rz_debugger_process_kill(RZ_NONNULL RzDebugger *dbg, const RzSignal signal_id);
RZ_API RzList /*<RzProcessTrace *>*/ *rz_debugger_process_backtrace(RZ_NONNULL RzDebugger *dbg, const ut64 address);
RZ_API bool rz_debugger_process_register_sync(RZ_NONNULL RzDebugger *dbg, RZ_NONNULL RzReg *reg, RZ_NULLABLE RzRegItem *item, bool read);
RZ_API bool rz_debugger_process_profile_get(RZ_NONNULL RzDebugger *dbg, RZ_NONNULL RZ_OUT char **profile);
RZ_API bool rz_debugger_process_profile_set(RZ_NONNULL RzDebugger *dbg, RZ_NONNULL char *profile);
RZ_API RzList /*<RzProcessMemoryMap *>*/ *rz_debugger_process_memory_get(RZ_NONNULL RzDebugger *dbg);
RZ_API RzList /*<RzProcessMemoryMap *>*/ *rz_debugger_process_modules_get(RZ_NONNULL RzDebugger *dbg);
RZ_API bool rz_debugger_process_new_core_file(RZ_NONNULL RzDebugger *dbg, RZ_NONNULL const char *path, RZ_NONNULL RzBuffer *dest);
RZ_API bool rz_debugger_process_download_file(RZ_NONNULL RzDebugger *dbg, RZ_NONNULL const char *path, RZ_NONNULL RzBuffer *dest);
#endif /* RZ_API */

/* plugin pointers */
extern RzDebuggerPlugin rz_debugger_plugin_native;
extern RzDebuggerPlugin rz_debugger_plugin_null;

#ifdef __cplusplus
}
#endif

#endif /* RZ_DEBUGGER_H */
