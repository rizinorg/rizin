// SPDX-FileCopyrightText: 2007-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2007-2018 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#define LOG_CONFIGSTR_SIZE 512
#define LOG_OUTPUTBUF_SIZE 512

#include <rz_core.h>
#include <stdarg.h>

// TODO: Use thread-local storage to make these variables thread-safe
static RzList *log_cbs = NULL; // Functions to call when outputting log string
static int cfg_loglvl = RZ_LOGLVL_WARN; // Log level output
static int cfg_logtraplvl = RZ_LOGLVL_FATAL; // Log trap level
static bool cfg_logsrcinfo = false; // Print out debug source info with the output
static bool cfg_logcolors = false; // Output colored log text based on level
static char cfg_logfile[LOG_CONFIGSTR_SIZE] = ""; // Output text to filename
static const char *level_tags[] = { // Log level to tag string lookup array
	[RZ_LOGLVL_SILLY] = "SILLY",
	[RZ_LOGLVL_VERBOSE] = "VERBOSE",
	[RZ_LOGLVL_DEBUG] = "DEBUG",
	[RZ_LOGLVL_INFO] = "INFO",
	[RZ_LOGLVL_WARN] = "WARNING",
	[RZ_LOGLVL_ERROR] = "ERROR",
	[RZ_LOGLVL_FATAL] = "FATAL"
};

// cconfig.c configuration callback functions below
RZ_API void rz_log_set_level(RLogLevel level) {
	cfg_loglvl = level;
}

RZ_API void rz_log_set_traplevel(RLogLevel level) {
	cfg_logtraplvl = level;
}

RZ_API void rz_log_set_file(const char *filename) {
	int value_len = rz_str_nlen(filename, LOG_CONFIGSTR_SIZE) + 1;
	strncpy(cfg_logfile, filename, value_len);
}

RZ_API void rz_log_set_srcinfo(bool show_info) {
	cfg_logsrcinfo = show_info;
}

RZ_API void rz_log_set_colors(bool show_info) {
	cfg_logcolors = show_info;
}

/**
 * \brief Add a logging callback
 * \param cbfunc RLogCallback style function to be called
 */
RZ_API void rz_log_add_callback(RLogCallback cbfunc) {
	if (!log_cbs) {
		log_cbs = rz_list_new();
	}
	if (!rz_list_contains(log_cbs, cbfunc)) {
		rz_list_append(log_cbs, cbfunc);
	}
}

/**
 * \brief Remove a logging callback
 * \param cbfunc RLogCallback style function to be called
 */
RZ_API void rz_log_del_callback(RLogCallback cbfunc) {
	if (log_cbs) {
		rz_list_delete_data(log_cbs, cbfunc);
	}
}

RZ_API void rz_vlog(const char *funcname, const char *filename,
	ut32 lineno, RLogLevel level, const char *tag, const char *fmtstr, va_list args) {
	va_list args_copy;
	va_copy(args_copy, args);

	if (level < cfg_loglvl && level < cfg_logtraplvl) {
		// Don't print if output level is lower than current level
		// Don't ignore fatal/trap errors
		va_end(args_copy);
		return;
	}

	// TODO: Colors

	// Build output string with src info, and formatted output
	char output_buf[LOG_OUTPUTBUF_SIZE] = ""; // Big buffer for building the output string
	if (!tag) {
		tag = RZ_BETWEEN(0, level, RZ_ARRAY_SIZE(level_tags) - 1) ? level_tags[level] : "";
	}
	int offset = snprintf(output_buf, LOG_OUTPUTBUF_SIZE, "%s: ", tag);
	if (cfg_logsrcinfo) {
		offset += snprintf(output_buf + offset, LOG_OUTPUTBUF_SIZE - offset, "%s in %s:%i: ", funcname, filename, lineno);
	}
	vsnprintf(output_buf + offset, LOG_OUTPUTBUF_SIZE - offset, fmtstr, args);

	// Actually print out the string with our callbacks
	if (log_cbs && rz_list_length(log_cbs) > 0) {
		RzListIter *it;
		RLogCallback cb;

		rz_list_foreach (log_cbs, it, cb) {
			cb(output_buf, funcname, filename, lineno, level, NULL, fmtstr, args_copy);
		}
	} else {
		fprintf(stderr, "%s", output_buf);
	}
	va_end(args_copy);

	// Log to file if enabled
	if (cfg_logfile[0] != 0x00) {
		FILE *file = rz_sys_fopen(cfg_logfile, "a+"); // TODO: Optimize (static? Needs to remake on cfg change though)
		if (!file) {
			file = rz_sys_fopen(cfg_logfile, "w+");
		}
		if (file) {
			fprintf(file, "%s", output_buf);
			fclose(file);
		} else {
			eprintf("%s failed to write to file: %s\n", MACRO_LOG_FUNC, cfg_logfile);
		}
	}

	if (level >= cfg_logtraplvl && level != RZ_LOGLVL_NONE) {
		fflush(stdout); // We're about to exit HARD, flush buffers before dying
		fflush(stderr);
		// TODO: call rz_cons_flush if librz_cons is being used
		rz_sys_breakpoint(); // *oof*
	}
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
	ut32 lineno, RLogLevel level, const char *tag, const char *fmtstr, ...) {
	va_list args;

	va_start(args, fmtstr);
	rz_vlog(funcname, filename, lineno, level, tag, fmtstr, args);
	va_end(args);
}
