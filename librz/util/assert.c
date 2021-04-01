// SPDX-FileCopyrightText: 2018-2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

#ifdef RZ_ASSERT_STDOUT
static void stdout_log(const char *output, const char *funcname, const char *filename,
	ut32 lineno, RLogLevel level, const char *tag, const char *fmtstr, ...) {
	printf("%s", output);
}

static void print_message(RLogLevel level, const char *fmt, va_list args) {
	rz_log_add_callback(stdout_log);
	RZ_VLOG(level, NULL, fmt, args);
	rz_log_del_callback(stdout_log);
}
#else
static void print_message(RLogLevel level, const char *fmt, va_list args) {
	RZ_VLOG(level, NULL, fmt, args);
}
#endif
/*
 * It prints a message to the log and it provides a single point of entrance in
 * case of debugging. All rz_return_* functions call this.
 */
RZ_API void rz_assert_log(RLogLevel level, const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	print_message(level, fmt, args);
	va_end(args);
	char *env = rz_sys_getenv("RZ_DEBUG_ASSERT");
	if (env) {
		rz_sys_backtrace();
		if (*env && atoi(env)) {
			rz_sys_breakpoint();
		}
		free(env);
	}
}
