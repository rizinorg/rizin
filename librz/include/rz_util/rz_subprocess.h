// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_UTIL_SUBPROCESS_H
#define RZ_UTIL_SUBPROCESS_H

typedef struct rz_process_output_t {
	char *out; // stdout
	char *err; // stderr
	int ret; // exit code of the process
	bool timeout;
} RzSubprocessOutput;

typedef struct rz_subprocess_t RzSubprocess;

RZ_API bool rz_subprocess_init(void);
RZ_API void rz_subprocess_fini(void);
RZ_API void rz_subprocess_lock(void);
RZ_API void rz_subprocess_unlock(void);
RZ_API RzSubprocess *rz_subprocess_start(
	const char *file, const char *args[], size_t args_size,
	const char *envvars[], const char *envvals[], size_t env_size);
RZ_API void rz_subprocess_free(RzSubprocess *proc);
RZ_API bool rz_subprocess_wait(RzSubprocess *proc, ut64 timeout_ms);
RZ_API void rz_subprocess_kill(RzSubprocess *proc);
RZ_API void rz_subprocess_stdin_write(RzSubprocess *proc, const ut8 *buf, size_t buf_size);
RZ_API RzSubprocessOutput *rz_subprocess_drain(RzSubprocess *proc);
RZ_API void rz_subprocess_output_free(RzSubprocessOutput *out);

#endif