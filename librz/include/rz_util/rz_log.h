#ifndef RZ_LOG_H
#define RZ_LOG_H

#include <rz_userconf.h>

#if (defined(_WIN32) || defined(_WIN64)) && !defined(__GNUC__)
#define MACRO_LOG_FUNC __FUNCTION__
// TODO: Windows weak symbols?
#elif defined(__EMSCRIPTEN__) // TODO: test upon Emscripten's version once it supports weak symbols
#define MACRO_LOG_FUNC __func__
#else
#define MACRO_LOG_FUNC __func__
#endif

typedef enum rz_log_level {
	RZ_LOGLVL_SILLY = 0,
	RZ_LOGLVL_DEBUG = 1,
	RZ_LOGLVL_VERBOSE = 2,
	RZ_LOGLVL_INFO = 3,
	RZ_LOGLVL_WARN = 4,
	RZ_LOGLVL_ERROR = 5,
	RZ_LOGLVL_FATAL = 6, // This will call rz_sys_breakpoint() and trap the process for debugging!
	RZ_LOGLVL_NONE = 0xFF
} RLogLevel;

#if RZ_CHECKS_LEVEL >= 2
#define RZ_DEFAULT_LOGLVL RZ_LOGLVL_WARN
#else
#define RZ_DEFAULT_LOGLVL RZ_LOGLVL_ERROR
#endif

typedef void (*RLogCallback)(const char *output, const char *funcname, const char *filename,
	ut32 lineno, RLogLevel level, const char *tag, const char *fmtstr, ...) RZ_PRINTF_CHECK(7, 8);

#define RZ_VLOG(lvl, tag, fmtstr, args) rz_vlog(MACRO_LOG_FUNC, __FILE__, \
	__LINE__, lvl, tag, fmtstr, args);

#define RZ_LOG(lvl, tag, fmtstr, ...) rz_log(MACRO_LOG_FUNC, __FILE__, \
	__LINE__, lvl, tag, fmtstr, ##__VA_ARGS__);

#if RZ_BUILD_DEBUG
#define RZ_LOG_SILLY(fmtstr, ...) rz_log(MACRO_LOG_FUNC, __FILE__, \
	__LINE__, RZ_LOGLVL_SILLY, NULL, fmtstr, ##__VA_ARGS__);
#define RZ_LOG_DEBUG(fmtstr, ...) rz_log(MACRO_LOG_FUNC, __FILE__, \
	__LINE__, RZ_LOGLVL_DEBUG, NULL, fmtstr, ##__VA_ARGS__);
#else
#define RZ_LOG_SILLY(fmtstr, ...)
#define RZ_LOG_DEBUG(fmtstr, ...)
#endif

#define RZ_LOG_VERBOSE(fmtstr, ...) rz_log(MACRO_LOG_FUNC, __FILE__, \
	__LINE__, RZ_LOGLVL_VERBOSE, NULL, fmtstr, ##__VA_ARGS__);
#define RZ_LOG_INFO(fmtstr, ...) rz_log(MACRO_LOG_FUNC, __FILE__, \
	__LINE__, RZ_LOGLVL_INFO, NULL, fmtstr, ##__VA_ARGS__);
#define RZ_LOG_WARN(fmtstr, ...) rz_log(MACRO_LOG_FUNC, __FILE__, \
	__LINE__, RZ_LOGLVL_WARN, NULL, fmtstr, ##__VA_ARGS__);
#define RZ_LOG_ERROR(fmtstr, ...) rz_log(MACRO_LOG_FUNC, __FILE__, \
	__LINE__, RZ_LOGLVL_ERROR, NULL, fmtstr, ##__VA_ARGS__);
#define RZ_LOG_FATAL(fmtstr, ...) rz_log(MACRO_LOG_FUNC, __FILE__, \
	__LINE__, RZ_LOGLVL_FATAL, NULL, fmtstr, ##__VA_ARGS__);

#ifdef __cplusplus
extern "C" {
#endif

// Called by rz_core to set the configuration variables
RZ_API void rz_log_set_level(RLogLevel level);
RZ_API void rz_log_set_file(const char *filename);
RZ_API void rz_log_set_srcinfo(bool show_info);
RZ_API void rz_log_set_colors(bool show_colors);
RZ_API void rz_log_set_traplevel(RLogLevel level);
// TODO: rz_log_set_options(enum RLogOptions)

// Functions for adding log callbacks
RZ_API void rz_log_add_callback(RLogCallback cbfunc);
RZ_API void rz_log_del_callback(RLogCallback cbfunc);
// TODO: rz_log_get_callbacks()

/* Define rz_log as weak so it can be 'overwritten' externally
   This allows another method of output redirection on POSIX (Windows?)
   You can override this function to handle all logging logic / output yourself */
RZ_API void rz_log(const char *funcname, const char *filename,
	ut32 lineno, RLogLevel level, const char *tag, const char *fmtstr, ...) RZ_PRINTF_CHECK(6, 7);

RZ_API void rz_vlog(const char *funcname, const char *filename,
	ut32 lineno, RLogLevel level, const char *tag, const char *fmtstr, va_list args);

#ifdef __cplusplus
}
#endif

#endif //  RZ_LOG_H
