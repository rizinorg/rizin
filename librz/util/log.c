// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2007-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2007-2018 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include <rz_util.h>
#include <rz_th.h>
#include <stdarg.h>

typedef struct log_config_s {
	RzList /*<RzLogCallback *>*/ *callbacks;
	RzLogLevel level;
#if RZ_BUILD_DEBUG
	RzLogLevel abortlevel;
#endif
	bool show_sources;
	FILE *file;
	const char **tags;
	RzThreadLock *lock;
} log_config_t;

///< Log level to tag string lookup array
static const char *level_tags_no_colors[] = {
	[RZ_LOGLVL_VERBOSE] = "VERBOSE",
	[RZ_LOGLVL_DEBUG] = "DEBUG",
	[RZ_LOGLVL_INFO] = "INFO",
	[RZ_LOGLVL_WARN] = "WARNING",
	[RZ_LOGLVL_ERROR] = "ERROR",
	[RZ_LOGLVL_FATAL] = "FATAL",
};

static const char *level_tags_colors[] = {
	[RZ_LOGLVL_VERBOSE] = Color_GREEN "VERBOSE" Color_RESET,
	[RZ_LOGLVL_DEBUG] = Color_BLUE "DEBUG" Color_RESET,
	[RZ_LOGLVL_INFO] = Color_CYAN "INFO" Color_RESET,
	[RZ_LOGLVL_WARN] = Color_YELLOW "WARNING" Color_RESET,
	[RZ_LOGLVL_ERROR] = Color_RED "ERROR" Color_RESET,
	[RZ_LOGLVL_FATAL] = Color_MAGENTA "FATAL" Color_RESET,
};

static log_config_t logcfg = { 0 };

static void log_init() {
	if (logcfg.lock) {
		return;
	}
	logcfg.callbacks = NULL;
	logcfg.level = RZ_DEFAULT_LOGLVL;
#if RZ_BUILD_DEBUG
	logcfg.abortlevel = RZ_DEFAULT_LOGLVL_ABORT;
#endif
	logcfg.show_sources = false;
	logcfg.file = NULL;
	logcfg.tags = level_tags_no_colors;
	logcfg.lock = rz_th_lock_new(false);
}

/**
 * \brief      Sets the log level
 *
 * \param[in]  level  The log level to set.
 */
RZ_API void rz_log_set_level(RzLogLevel level) {
	log_init();
	rz_th_lock_enter(logcfg.lock);
	logcfg.level = level;
	rz_th_lock_leave(logcfg.lock);
}

/**
 * \brief      Sets the log level when to abort execution
 *
 * \param[in]  level  The abort log level to set.
 */
RZ_API void rz_log_set_abortlevel(RzLogLevel level) {
	log_init();
#if RZ_BUILD_DEBUG
	rz_th_lock_enter(logcfg.lock);
	logcfg.abortlevel = level;
	rz_th_lock_leave(logcfg.lock);
#else
	(void)level;
#endif
}

/**
 * \brief      When not empty, enable logging to a file.
 * This method allows to enable or disable logging to a file.
 * To enable logging, just pass a filename to write to and to
 * disable the logging is enough to pass an empty or NULL filename.
 *
 * \param[in]  filename  The file name to log to.
 */
RZ_API bool rz_log_set_file(RZ_NULLABLE const char *filename) {
	log_init();
	rz_th_lock_enter(logcfg.lock);
	bool ret = true;
	if (logcfg.file) {
		// if already open, then close the file handler.
		fclose(logcfg.file);
		logcfg.file = NULL;
	}

	if (RZ_STR_ISEMPTY(filename)) {
		// allow to have no filename
		goto end;
	}

	FILE *file = rz_sys_fopen(filename, "a+");
	if (!file) {
		file = rz_sys_fopen(filename, "w+");
	}
	if (file) {
		logcfg.file = file;
	} else {
		// failed to open the file.
		ret = false;
	}

end:
	rz_th_lock_leave(logcfg.lock);
	return ret;
}

/**
 * \brief      When true, shows the function name and the source lines in the logs.
 *
 * \param[in]  show_sources  The boolean value to set show_sources to.
 */
RZ_API void rz_log_set_show_sources(bool show_sources) {
	log_init();
	rz_th_lock_enter(logcfg.lock);
	logcfg.show_sources = show_sources;
	rz_th_lock_leave(logcfg.lock);
}

/**
 * \brief      Enables colored logs.
 *
 * \param[in]  show_colors  Sets the pointer to colored or not colored tags.
 */
RZ_API void rz_log_set_colors(bool show_colors) {
	log_init();
	rz_th_lock_enter(logcfg.lock);
	logcfg.tags = show_colors ? level_tags_colors : level_tags_no_colors;
	rz_th_lock_leave(logcfg.lock);
}

/**
 * \brief      Adds a logging callback.
 *
 * \param[in]  show_colors  RzLogCallback style function to be called.
 */
RZ_API void rz_log_add_callback(RZ_NULLABLE RzLogCallback cbfunc) {
	if (!cbfunc) {
		return;
	}
	log_init();
	rz_th_lock_enter(logcfg.lock);
	if (!logcfg.callbacks) {
		logcfg.callbacks = rz_list_new();
	}
	if (!rz_list_contains(logcfg.callbacks, cbfunc)) {
		rz_list_append(logcfg.callbacks, cbfunc);
	}
	rz_th_lock_leave(logcfg.lock);
}

/**
 * \brief        Removes a logging callback
 *
 * \param cbfunc RzLogCallback style function to be called
 */
RZ_API void rz_log_del_callback(RZ_NULLABLE RzLogCallback cbfunc) {
	if (!cbfunc) {
		return;
	}
	log_init();
	rz_th_lock_enter(logcfg.lock);
	if (logcfg.callbacks) {
		rz_list_delete_data(logcfg.callbacks, cbfunc);
	}
	rz_th_lock_leave(logcfg.lock);
}

#if RZ_BUILD_DEBUG
#define is_log_quiet(x) ((x) < logcfg.level && (x) < logcfg.abortlevel)
#else
#define is_log_quiet(x) ((x) < logcfg.level)
#endif /* RZ_BUILD_DEBUG */

RZ_API void rz_vlog(const char *funcname, const char *filename,
	ut32 lineno, RzLogLevel level, const char *tag, const char *fmtstr, va_list args) {
	log_init();

	if (is_log_quiet(level)) {
		// Don't print if output level is lower than current level
		// Don't ignore fatal/trap errors
		return;
	}

	// copy args only if we print the log
	va_list args_copy;
	va_copy(args_copy, args);

	// Build output string with src info, and formatted output
	RzStrBuf sb;
	rz_strbuf_init(&sb);

	if (!tag) {
		tag = RZ_BETWEEN(0, level, (RZ_LOGLVL_SIZE - 1)) ? logcfg.tags[level] : "";
	}
	rz_strbuf_append(&sb, tag);
	rz_strbuf_append(&sb, ": ");
	if (logcfg.show_sources) {
		rz_strbuf_appendf(&sb, "%s in %s:%i: ", funcname, filename, lineno);
	}
	rz_strbuf_vappendf(&sb, fmtstr, args);

	char *output_buf = rz_strbuf_drain_nofree(&sb);

	// critical section
	rz_th_lock_enter(logcfg.lock);
	if (rz_list_length(logcfg.callbacks) > 0) {
		// Print the log using the callbacks
		RzListIter *it;
		RzLogCallback cb;
		rz_list_foreach (logcfg.callbacks, it, cb) {
			cb(output_buf, funcname, filename, lineno, level, NULL, fmtstr, args_copy);
		}
	} else {
		// Print the log using stderr
		fputs(output_buf, stderr);
	}
	va_end(args_copy);

	// Log to file if enabled
	if (logcfg.file) {
		fputs(output_buf, logcfg.file);
		fflush(logcfg.file);
	}

#if RZ_BUILD_DEBUG
	if (level >= logcfg.abortlevel && level != RZ_LOGLVL_NONE) {
		// this will abort the execution
		// rz_sys_breakpoint is going to be called so we must flush buffers.
		fflush(stdout);
		fflush(stderr);
		rz_sys_breakpoint();
	}
#endif
	rz_th_lock_leave(logcfg.lock);
	free(output_buf);
}

/**
 * \brief Internal logging function used by preprocessor macros
 * \param funcname Contains the function name of the calling function
 * \param filename Contains the filename that funcname is defined in
 * \param lineno The line number that this log call is being made from in filename
 * \param lvl Logging level for output
 * \param fmtstr A printf like string

  This function is used by the RZ_LOG_* preprocessor macros for logging
*/
RZ_API void rz_log(const char *funcname, const char *filename,
	ut32 lineno, RzLogLevel level, const char *tag, const char *fmtstr, ...) {
	va_list args;

	va_start(args, fmtstr);
	rz_vlog(funcname, filename, lineno, level, tag, fmtstr, args);
	va_end(args);
}
