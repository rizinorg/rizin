// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <errno.h>
#include <rz_io.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_cons.h>
#include <rz_core.h>
#include <rz_socket.h>
#include <rz_debug.h> /* only used for BSD PTRACE redefinitions */
#include <string.h>

#include "rz_io_plugins.h"

#define USE_RARUN 0

#if __linux__ || __APPLE__ || __WINDOWS__ || __NetBSD__ || __KFBSD__ || __OpenBSD__
#define DEBUGGER_SUPPORTED 1
#else
#define DEBUGGER_SUPPORTED 0
#endif

#if DEBUGGER && DEBUGGER_SUPPORTED
#define MAGIC_EXIT 123

// POSIX_SPAWN_CLOEXEC_DEFAULT is available since macOS 10.7, but known to cause kernel panics until 10.8.
#if __APPLE__ && defined(MAC_OS_X_VERSION_10_8)
#define USE_POSIX_SPAWN 1
#else
#define USE_POSIX_SPAWN 0
#endif

#include <signal.h>
#if __UNIX__
#include <rz_util/rz_ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif

#if USE_POSIX_SPAWN
#include <spawn.h>
#endif
#if __APPLE__
#include <sys/types.h>
#include <sys/wait.h>
#include <mach/exception_types.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_traps.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach/vm_map.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#endif

#if __WINDOWS__
#include <rz_windows.h>
#include <w32dbg_wrap.h>
#endif

/*
 * Creates a new process and returns the result:
 * -1 : error
 *  0 : ok
 */

#if __WINDOWS__
typedef struct {
	HANDLE hnd;
	ut64 winbase;
} RzIOW32;

static int setup_tokens(void) {
	HANDLE tok = NULL;
	TOKEN_PRIVILEGES tp;
	DWORD err = -1;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &tok)) {
		goto err_enable;
	}
	tp.PrivilegeCount = 1;
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
		goto err_enable;
	}
	// tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
	tp.Privileges[0].Attributes = 0; // SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(tok, 0, &tp, sizeof(tp), NULL, NULL)) {
		goto err_enable;
	}
	err = 0;
err_enable:
	if (tok) {
		CloseHandle(tok);
	}
	if (err) {
		rz_sys_perror("setup_tokens");
	}
	return err;
}

struct __createprocess_params {
	LPCTSTR appname;
	LPTSTR cmdline;
	PROCESS_INFORMATION *pi;
	DWORD flags;
};

static int __createprocess_wrap(void *params) {
	STARTUPINFO si = { 0 };
	// TODO: Add DEBUG_PROCESS to support child process debugging
	struct __createprocess_params *p = params;
	return CreateProcess(p->appname, p->cmdline, NULL, NULL, FALSE,
		p->flags, NULL, NULL, &si, p->pi);
}

static int fork_and_ptraceme(RzIO *io, int bits, const char *cmd) {
	RzCore *core = io->corebind.core;
	PROCESS_INFORMATION pi;
	STARTUPINFO si = { 0 };
	si.cb = sizeof(si);
	int pid, tid;
	if (!*cmd) {
		return -1;
	}
	setup_tokens();
	char *_cmd = io->args ? rz_str_appendf(strdup(cmd), " %s", io->args) : strdup(cmd);
	char **argv = rz_str_argv(_cmd, NULL);
	char *cmdline = NULL;
	// We need to build a command line with quoted argument and escaped quotes
	int i = 0;
	while (argv[i]) {
		rz_str_arg_unescape(argv[i]);
		cmdline = rz_str_appendf(cmdline, "\"%s\" ", argv[i]);
		i++;
	}

	LPTSTR appname_ = rz_sys_conv_utf8_to_win(argv[0]);
	LPTSTR cmdline_ = rz_sys_conv_utf8_to_win(cmdline);
	DWORD flags = DEBUG_ONLY_THIS_PROCESS;
	flags |= core->dbg->create_new_console ? CREATE_NEW_CONSOLE : 0;
	free(cmdline);
	struct __createprocess_params p = { appname_, cmdline_, &pi, flags };
	W32DbgWInst *wrap = (W32DbgWInst *)rz_io_get_w32dbg_wrap(io);
	wrap->params.type = W32_CALL_FUNC;
	wrap->params.func.func = __createprocess_wrap;
	wrap->params.func.user = &p;
	w32dbg_wrap_wait_ret(wrap);
	if (!w32dbgw_ret(wrap)) {
		w32dbgw_err(wrap);
		rz_sys_perror("fork_and_ptraceme/CreateProcess");
		free(appname_);
		free(cmdline_);
		return -1;
	}
	CloseHandle(pi.hThread);
	free(appname_);
	free(cmdline_);
	rz_str_argv_free(argv);

	/* get process id and thread id */
	pid = pi.dwProcessId;
	tid = pi.dwThreadId;

	eprintf("Spawned new process with pid %d, tid = %d\n", pid, tid);

	RzCore *c = io->corebind.core;
	c->dbg->plugin_data = wrap;
	/* catch create process event */
	int ret = c->dbg->cur->wait(c->dbg, pi.dwProcessId);
	/* check if is a create process debug event */
	if (ret != RZ_DEBUG_REASON_NEW_PID) {
		TerminateProcess(pi.hProcess, 1);
		core->dbg->cur->detach(core->dbg, wrap->pi.dwProcessId);
		CloseHandle(pi.hProcess);
		return -1;
	}
	CloseHandle(pi.hProcess);
	return pid;
}
#else // windows

static RzRunProfile *_get_run_profile(RzIO *io, int bits, char **argv) {
	int i;
	RzRunProfile *rp = rz_run_new(NULL);
	if (!rp) {
		return NULL;
	}
	for (i = 0; argv[i]; i++) {
		rp->_args[i] = argv[i];
	}
	rp->_args[i] = NULL;
	if (!argv[0]) {
		rz_run_free(rp);
		return NULL;
	}
	rp->_program = strdup(argv[0]);

	rp->_dodebug = true;
	if (RZ_STR_ISNOTEMPTY(io->runprofile)) {
		if (!rz_run_parsefile(rp, io->runprofile)) {
			RZ_LOG_ERROR("io_debug: can't find profile '%s'\n", io->runprofile);
			rz_run_free(rp);
			return NULL;
		}
		if (strstr(io->runprofile, RZ_SYS_DIR ".rz-run.")) {
			(void)rz_file_rm(io->runprofile);
		}
	} else if (RZ_STR_ISNOTEMPTY(io->envprofile) && !rz_run_parse(rp, io->envprofile)) {
		RZ_LOG_ERROR("io_debug: can't parse default rz-run profile\n");
		rz_run_free(rp);
		return NULL;
	}

	rp->_bits = bits;
	if (rz_run_config_env(rp)) {
		RZ_LOG_ERROR("io_debug: can't config the environment.\n");
		rz_run_free(rp);
		return NULL;
	}
	return rp;
}

#if USE_POSIX_SPAWN

static void handle_posix_error(int err) {
	switch (err) {
	case 0:
		// 0 means success
		break;
	case 22:
		RZ_LOG_ERROR("posix_spawnp: Invalid argument\n");
		break;
	case 86:
		RZ_LOG_ERROR("Unsupported architecture. Please specify -b 32\n");
		break;
	default:
		RZ_LOG_ERROR("posix_spawnp: unknown error %d\n", err);
		break;
	}
}

static void handle_posix_redirection(RzRunProfile *rp, posix_spawn_file_actions_t *fileActions) {
	const int mode = S_IRUSR | S_IWUSR;
	if (rp->_stdin) {
		posix_spawn_file_actions_addopen(fileActions, STDIN_FILENO, rp->_stdin, O_RDONLY, mode);
	}
	if (rp->_stdout) {
		posix_spawn_file_actions_addopen(fileActions, STDOUT_FILENO, rp->_stdout, O_WRONLY, mode);
	}
	if (rp->_stderr) {
		posix_spawn_file_actions_addopen(fileActions, STDERR_FILENO, rp->_stderr, O_WRONLY, mode);
	}
}

static int fork_and_ptraceme_for_unix(RzIO *io, int bits, const char *cmd) {
	pid_t p = -1;
	char **argv;
	posix_spawn_file_actions_t fileActions;
	ut32 ps_flags = POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK;
	sigset_t no_signals;
	sigset_t all_signals;
	size_t copied = 1;
	cpu_type_t cpu = CPU_TYPE_ANY;
	posix_spawnattr_t attr = { 0 };
	posix_spawnattr_init(&attr);

	sigemptyset(&no_signals);
	sigfillset(&all_signals);
	posix_spawnattr_setsigmask(&attr, &no_signals);
	posix_spawnattr_setsigdefault(&attr, &all_signals);

	posix_spawn_file_actions_init(&fileActions);
	posix_spawn_file_actions_addinherit_np(&fileActions, STDIN_FILENO);
	posix_spawn_file_actions_addinherit_np(&fileActions, STDOUT_FILENO);
	posix_spawn_file_actions_addinherit_np(&fileActions, STDERR_FILENO);

	ps_flags |= POSIX_SPAWN_CLOEXEC_DEFAULT;
	ps_flags |= POSIX_SPAWN_START_SUSPENDED;
#define _POSIX_SPAWN_DISABLE_ASLR 0x0100
	int ret;
	argv = rz_str_argv(cmd, NULL);
	if (!argv) {
		posix_spawn_file_actions_destroy(&fileActions);
		return -1;
	}
	RzRunProfile *rp = _get_run_profile(io, bits, argv);
	if (!rp) {
		rz_str_argv_free(argv);
		posix_spawn_file_actions_destroy(&fileActions);
		return -1;
	}
	handle_posix_redirection(rp, &fileActions);
	if (rp->_args[0]) {
		if (!rp->_aslr) {
			ps_flags |= _POSIX_SPAWN_DISABLE_ASLR;
		}
#if __x86_64__
		if (rp->_bits == 32) {
			cpu = CPU_TYPE_I386;
		}
#endif
		(void)posix_spawnattr_setflags(&attr, ps_flags);
		posix_spawnattr_setbinpref_np(&attr, 1, &cpu, &copied);
		ret = posix_spawnp(&p, rp->_args[0], &fileActions, &attr, rp->_args, NULL);
		handle_posix_error(ret);
	}
	rz_str_argv_free(argv);
	rz_run_free(rp);
	posix_spawn_file_actions_destroy(&fileActions);
	return p; // -1 ?
}

#else // USE_POSIX_SPAWN

typedef struct fork_child_data_t {
	RzIO *io;
	int bits;
	const char *cmd;
} fork_child_data;

#if __APPLE__ || __BSD__
static void inferior_abort_handler(int pid) {
	eprintf("Inferior received signal SIGABRT. Executing BKPT.\n");
}
#endif

static void trace_me(void) {
#if __APPLE__
	rz_sys_signal(SIGTRAP, SIG_IGN); // NEED BY STEP
#endif
#if __APPLE__ || __BSD__
	/* we can probably remove this #if..as long as PT_TRACE_ME is redefined for OSX in rz_debug.h */
	rz_sys_signal(SIGABRT, inferior_abort_handler);
	if (ptrace(PT_TRACE_ME, 0, 0, 0) != 0) {
		rz_sys_perror("ptrace-traceme");
	}
#if __APPLE__
	ptrace(PT_SIGEXC, getpid(), NULL, 0);
#endif
#else
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) {
		rz_sys_perror("ptrace-traceme");
		exit(MAGIC_EXIT);
	}
#endif
}

static void fork_child_callback(void *user) {
	fork_child_data *data = user;
	char **argv = rz_str_argv(data->cmd, NULL);
	if (!argv) {
		exit(1);
	}
	rz_sys_clearenv();
	RzRunProfile *rp = _get_run_profile(data->io, data->bits, argv);
	if (!rp) {
		rz_str_argv_free(argv);
		exit(1);
	}
	trace_me();
	rz_run_start(rp);
	rz_run_free(rp);
	rz_str_argv_free(argv);
	exit(1);
}

static int fork_and_ptraceme_for_unix(RzIO *io, int bits, const char *cmd) {
	int ret, status, child_pid;
	void *bed = NULL;
	fork_child_data child_data;
	child_data.io = io;
	child_data.bits = bits;
	child_data.cmd = cmd;
	child_pid = rz_io_ptrace_fork(io, fork_child_callback, &child_data);
	switch (child_pid) {
	case -1:
		perror("fork_and_ptraceme");
		break;
	case 0:
		return -1;
	default:
		/* XXX: clean this dirty code */
		do {
			ret = waitpid(child_pid, &status, WNOHANG);
			if (ret == -1) {
				perror("waitpid");
				return -1;
			}
			bed = rz_cons_sleep_begin();
			usleep(100000);
			rz_cons_sleep_end(bed);
		} while (ret != child_pid && !rz_cons_is_breaked());
		if (WIFSTOPPED(status)) {
			eprintf("Process with PID %d started...\n", (int)child_pid);
		} else if (WEXITSTATUS(status) == MAGIC_EXIT) {
			child_pid = -1;
		} else if (rz_cons_is_breaked()) {
			kill(child_pid, SIGSTOP);
		} else {
			eprintf("Killing child process %d due to an error\n", (int)child_pid);
			kill(child_pid, SIGSTOP);
		}
		break;
	}
	return child_pid;
}

#endif // USE_POSIX_SPAWN

static int fork_and_ptraceme(RzIO *io, int bits, const char *cmd) {
	// Before calling the platform implementation, append arguments to the command if they have been provided
	char *eff_cmd = io->args ? rz_str_appendf(strdup(cmd), " %s", io->args) : strdup(cmd);
	if (!eff_cmd) {
		return -1;
	}
	int r = 0;
	r = fork_and_ptraceme_for_unix(io, bits, eff_cmd);
	free(eff_cmd);
	return r;
}
#endif

static bool __plugin_open(RzIO *io, const char *file, bool many) {
	if (!strncmp(file, "waitfor://", 10)) {
		return true;
	}
	if (!strncmp(file, "pidof://", 8)) {
		return true;
	}
	return (!strncmp(file, "dbg://", 6) && file[6]);
}

#include <rz_core.h>
static int get_pid_of(RzIO *io, const char *procname) {
	RzCore *c = io->corebind.core;
	if (c && c->dbg && c->dbg->cur) {
		RzListIter *iter;
		RzDebugPid *proc;
		RzDebug *d = c->dbg;
		RzList *pids = d->cur->pids(d, 0);
		rz_list_foreach (pids, iter, proc) {
			if (strstr(proc->path, procname)) {
				eprintf("Matching PID %d %s\n", proc->pid, proc->path);
				return proc->pid;
			}
		}
	} else {
		eprintf("Cannot enumerate processes\n");
	}
	return -1;
}

static RzIODesc *__open(RzIO *io, const char *file, int rw, int mode) {
	RzIOPlugin *_plugin;
	RzIODesc *ret = NULL;
	char uri[128];
	if (!strncmp(file, "waitfor://", 10)) {
		const char *procname = file + 10;
		eprintf("Waiting for %s\n", procname);
		while (true) {
			int target_pid = get_pid_of(io, procname);
			if (target_pid != -1) {
				snprintf(uri, sizeof(uri), "dbg://%d", target_pid);
				file = uri;
				break;
			}
			rz_sys_usleep(100);
		}
	} else if (!strncmp(file, "pidof://", 8)) {
		const char *procname = file + 8;
		int target_pid = get_pid_of(io, procname);
		if (target_pid == -1) {
			eprintf("Cannot find matching process for %s\n", file);
			return NULL;
		}
		snprintf(uri, sizeof(uri), "dbg://%d", target_pid);
		file = uri;
	}
	if (__plugin_open(io, file, 0)) {
		const char *pidfile = file + 6;
		char *endptr;
		int pid = (int)strtol(pidfile, &endptr, 10);
		if (endptr == pidfile || pid < 0) {
			pid = -1;
		}
		if (pid == -1) {
			pid = fork_and_ptraceme(io, io->bits, file + 6);
			if (pid == -1) {
				return NULL;
			}
#if __WINDOWS__
			sprintf(uri, "w32dbg://%d", pid);
			_plugin = rz_io_plugin_resolve(io, (const char *)uri, false);
			if (!_plugin || !_plugin->open) {
				return NULL;
			}
			ret = _plugin->open(io, uri, rw, mode);
#elif __APPLE__
			sprintf(uri, "smach://%d", pid); // s is for spawn
			_plugin = rz_io_plugin_resolve(io, (const char *)uri + 1, false);
			if (!_plugin || !_plugin->open || !_plugin->close) {
				return NULL;
			}
			ret = _plugin->open(io, uri, rw, mode);
#else
			// TODO: use io_procpid here? faster or what?
			sprintf(uri, "ptrace://%d", pid);
			_plugin = rz_io_plugin_resolve(io, (const char *)uri, false);
			if (!_plugin || !_plugin->open) {
				return NULL;
			}
			ret = _plugin->open(io, uri, rw, mode);
#endif
		} else {
			sprintf(uri, "attach://%d", pid);
			_plugin = rz_io_plugin_resolve(io, (const char *)uri, false);
			if (!_plugin || !_plugin->open) {
				return NULL;
			}
			ret = _plugin->open(io, uri, rw, mode);
#if __WINDOWS__
			if (ret) {
				RzCore *c = io->corebind.core;
				c->dbg->plugin_data = ret->data;
			}
#endif
		}
		if (ret) {
			ret->plugin = _plugin;
			ret->referer = strdup(file); // kill this
		}
	}
	return ret;
}

static int __close(RzIODesc *desc) {
	int ret = -2;
	eprintf("something went wrong\n");
	if (desc) {
		eprintf("trying to close %d with io_debug\n", desc->fd);
		ret = -1;
	}
	rz_sys_backtrace();
	return ret;
}

RzIOPlugin rz_io_plugin_debug = {
	.name = "debug",
	.desc = "Attach to native debugger instance",
	.license = "LGPL3",
	.uris = "dbg://,pidof://,waitfor://",
	.author = "pancake",
	.version = "0.2.0",
	.open = __open,
	.close = __close,
	.check = __plugin_open,
	.isdbg = true,
};
#else
RzIOPlugin rz_io_plugin_debug = {
	.name = "debug",
	.desc = "Debug a program or pid. (NOT SUPPORTED FOR THIS PLATFORM)",
};
#endif

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_debug,
	.version = RZ_VERSION
};
#endif
