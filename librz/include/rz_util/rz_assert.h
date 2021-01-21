#ifndef RZ_ASSERT_H
#define RZ_ASSERT_H

#include "rz_log.h"

#define RZ_STATIC_ASSERT(x) \
	switch (0) { \
	case 0: \
	case (x):; \
	}

RZ_API void rz_assert_log(RLogLevel level, const char *fmt, ...) RZ_PRINTF_CHECK(2, 3);

#if defined(__GNUC__) && defined(__cplusplus)
#define RZ_FUNCTION ((const char *)(__PRETTY_FUNCTION__))
#elif defined(__STDC__) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define RZ_FUNCTION ((const char *)(__func__))
#elif defined(__GNUC__) || (defined(_MSC_VER) && (_MSC_VER > 1300))
#define RZ_FUNCTION ((const char *)(__FUNCTION__))
#else
#warning Do not know how to get function name in this setup
#define RZ_FUNCTION ((const char *)("???"))
#endif

#define rz_warn_if_reached() \
	do { \
		rz_assert_log(RZ_LOGLVL_WARN, "(%s:%d):%s%s code should not be reached\n", \
			__FILE__, __LINE__, RZ_FUNCTION, RZ_FUNCTION[0] ? ":" : ""); \
	} while (0)

#define rz_warn_if_fail(expr) \
	do { \
		if (!(expr)) { \
			rz_assert_log(RZ_LOGLVL_WARN, "WARNING (%s:%d):%s%s runtime check failed: (%s)\n", \
				__FILE__, __LINE__, RZ_FUNCTION, RZ_FUNCTION[0] ? ":" : "", #expr); \
		} \
	} while (0)

/*
 * RZ_CHECKS_LEVEL determines the behaviour of the rz_return_* set of functions.
 *
 * 0: completely disable every function and make them like no-operation
 * 1: silently enable checks. Check expressions and do return, but do not log anything
 * 2: enable checks and logging (DEFAULT)
 * 3: transform them into real assertion
 */
#ifndef RZ_CHECKS_LEVEL
#define RZ_CHECKS_LEVEL 2
#endif

#if RZ_CHECKS_LEVEL == 0

#define rz_return_if_fail(expr) \
	do { \
		; \
	} while (0)
#define rz_return_val_if_fail(expr, val) \
	do { \
		; \
	} while (0)
#define rz_return_if_reached() \
	do { \
		; \
	} while (0)
#define rz_return_val_if_reached(val) \
	do { \
		; \
	} while (0)

#elif RZ_CHECKS_LEVEL == 1 || RZ_CHECKS_LEVEL == 2 // RZ_CHECKS_LEVEL

#if RZ_CHECKS_LEVEL == 1
#define H_LOG_(loglevel, fmt, ...)
#else
#define H_LOG_(loglevel, fmt, ...) rz_assert_log(loglevel, fmt, __VA_ARGS__)
#endif

/**
 * rz_return_if_fail:
 * @expr: the expression to check
 *
 * Verifies that the expression @expr, usually representing a precondition,
 * evaluates to `true`. If the function returns a value, use
 * rz_return_val_if_fail() instead.
 *
 * If @expr evaluates to %FALSE, the current function should be considered to
 * have undefined behaviour (a programmer error). The only correct solution
 * to such an error is to change the module that is calling the current
 * function, so that it avoids this incorrect call.
 *
 * To make this undefined behaviour visible, if @expr evaluates to %FALSE,
 * the result is usually that a critical message is logged and the current
 * function returns.
 *
 */
#define rz_return_if_fail(expr) \
	do { \
		if (!(expr)) { \
			H_LOG_(RZ_LOGLVL_WARN, "%s: assertion '%s' failed (line %d)\n", RZ_FUNCTION, #expr, __LINE__); \
			return; \
		} \
	} while (0)

#define rz_return_val_if_fail(expr, val) \
	do { \
		if (!(expr)) { \
			H_LOG_(RZ_LOGLVL_WARN, "%s: assertion '%s' failed (line %d)\n", RZ_FUNCTION, #expr, __LINE__); \
			return (val); \
		} \
	} while (0)

#define rz_return_if_reached() \
	do { \
		H_LOG_(RZ_LOGLVL_ERROR, "file %s: line %d (%s): should not be reached\n", __FILE__, __LINE__, RZ_FUNCTION); \
		return; \
	} while (0)

#define rz_return_val_if_reached(val) \
	do { \
		H_LOG_(RZ_LOGLVL_ERROR, "file %s: line %d (%s): should not be reached\n", __FILE__, __LINE__, RZ_FUNCTION); \
		return (val); \
	} while (0)

#else // RZ_CHECKS_LEVEL

#include <assert.h>

#define rz_return_if_fail(expr) \
	do { \
		assert(expr); \
	} while (0)
#define rz_return_val_if_fail(expr, val) \
	do { \
		assert(expr); \
	} while (0)
#define rz_return_if_reached() \
	do { \
		assert(false); \
	} while (0)
#define rz_return_val_if_reached(val) \
	do { \
		assert(false); \
	} while (0)

#endif // RZ_CHECKS_LEVEL

#endif
