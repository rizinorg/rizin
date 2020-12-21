// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_UTIL_SUBPROCESS_H
#define RZ_UTIL_SUBPROCESS_H

/**
 * Enum used to determine how pipes should be created, if at all, in the
 * subprocess.
 */
typedef enum rz_process_pipe_t {
	///< No pipe should be created. It can be used for stdin, stdout and stderr.
	RZ_PROCESS_PIPE_NONE,
	///< A new pipe should be created. It can be used for stdin, stdout and stderr.
	RZ_PROCESS_PIPE_CREATE,
	///< Re-use the same pipe as stdout. It can be used for stderr only.
	RZ_PROCESS_PIPE_STDOUT,
} RzSubprocessPipe;

typedef struct rz_process_output_t {
	char *out; // stdout
	char *err; // stderr
	int ret; // exit code of the process
	bool timeout;
} RzSubprocessOutput;

/**
 * Specify how the new subprocess should be created.
 */
typedef struct rz_subprocess_opt_t {
	///< Name of the executable to run. It is searched also in PATH
	const char *file;
	///< Arguments to pass to the subprocess. These are just the arguments and do not include the program name (aka argv[0])
	const char **args;
	///< Number of arguments in \p args array
	size_t args_size;
	///< Names of environment variables that subprocess should have differently from parent
	const char **envvars;
	///< Values of environment variables that subprocess should have differently from parent
	const char **envvals;
	///< Number of elements contained in both \p envvars and \p envvals
	size_t env_size;
	///< Specify how to deal with subprocess stdin
	RzSubprocessPipe stdin_pipe;
	///< Specify how to deal with subprocess stdout
	RzSubprocessPipe stdout_pipe;
	///< Specify how to deal with subprocess stderr
	RzSubprocessPipe stderr_pipe;
} RzSubprocessOpt;

typedef struct rz_subprocess_t RzSubprocess;

RZ_API bool rz_subprocess_init(void);
RZ_API void rz_subprocess_fini(void);
RZ_API RzSubprocess *rz_subprocess_start(
	const char *file, const char *args[], size_t args_size,
	const char *envvars[], const char *envvals[], size_t env_size);
RZ_API RzSubprocess *rz_subprocess_start_opt(RzSubprocessOpt *opt);
RZ_API void rz_subprocess_free(RzSubprocess *proc);
RZ_API bool rz_subprocess_wait(RzSubprocess *proc, ut64 timeout_ms);
RZ_API void rz_subprocess_kill(RzSubprocess *proc);
RZ_API int rz_subprocess_ret(RzSubprocess *proc);
RZ_API char *rz_subprocess_out(RzSubprocess *proc);
RZ_API char *rz_subprocess_err(RzSubprocess *proc);
RZ_API void rz_subprocess_stdin_write(RzSubprocess *proc, const ut8 *buf, size_t buf_size);
RZ_API RzSubprocessOutput *rz_subprocess_drain(RzSubprocess *proc);
RZ_API void rz_subprocess_output_free(RzSubprocessOutput *out);

#endif