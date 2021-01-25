#ifndef RZ_TYPES_H
#define RZ_TYPES_H

#undef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64

// defines like IS_DIGIT, etc'
#include <rz_userconf.h>
#include <rz_util/rz_str_util.h>
#include <stddef.h>
#include <assert.h>
#include <errno.h>

// TODO: fix this to make it crosscompile-friendly: RZ_SYS_OSTYPE ?
/* operating system */
#undef __BSD__
#undef __KFBSD__
#undef __UNIX__
#undef __WINDOWS__

#define RZ_MODE_PRINT     0x000
#define RZ_MODE_RIZINCMD  0x001
#define RZ_MODE_SET       0x002
#define RZ_MODE_SIMPLE    0x004
#define RZ_MODE_JSON      0x008
#define RZ_MODE_ARRAY     0x010
#define RZ_MODE_SIMPLEST  0x020
#define RZ_MODE_CLASSDUMP 0x040
#define RZ_MODE_EQUAL     0x080

/**
 * \brief Enum to describe the way data are printed
 */
typedef enum {
	RZ_OUTPUT_MODE_STANDARD = 1 << 0,
	RZ_OUTPUT_MODE_JSON = 1 << 1,
	RZ_OUTPUT_MODE_RIZIN = 1 << 2,
	RZ_OUTPUT_MODE_QUIET = 1 << 3,
	RZ_OUTPUT_MODE_SDB = 1 << 4,
	RZ_OUTPUT_MODE_LONG = 1 << 5,
	RZ_OUTPUT_MODE_LONG_JSON = 1 << 6,
	RZ_OUTPUT_MODE_TABLE = 1 << 7,
} RzOutputMode;

#define RZ_IN        /* do not use, implicit */
#define RZ_OUT       /* parameter is written, not read */
#define RZ_INOUT     /* parameter is read and written */
#define RZ_OWN       /* pointer ownership is transferred */
#define RZ_BORROW    /* pointer ownership is not transferred, it must not be freed by the receiver */
#define RZ_NONNULL   /* pointer can not be null */
#define RZ_NULLABLE  /* pointer can be null */
#define RZ_DEPRECATE /* should not be used in new code and should/will be removed in the future */
#define RZ_IFNULL(x) /* default value for the pointer when null */
#ifdef __GNUC__
#define RZ_UNUSED __attribute__((__unused__))
#else
#define RZ_UNUSED /* unused */
#endif

#ifdef RZ_NEW
#undef RZ_NEW
#endif

#ifdef RZ_NEW0
#undef RZ_NEW0
#endif

#ifdef RZ_FREE
#undef RZ_FREE
#endif

#ifdef RZ_NEWCOPY
#undef RZ_NEWCOPY
#endif

// used in debug, io, bin, analysis, ...
#define RZ_PERM_R      4
#define RZ_PERM_W      2
#define RZ_PERM_X      1
#define RZ_PERM_RW     (RZ_PERM_R | RZ_PERM_W)
#define RZ_PERM_RX     (RZ_PERM_R | RZ_PERM_X)
#define RZ_PERM_RWX    (RZ_PERM_R | RZ_PERM_W | RZ_PERM_X)
#define RZ_PERM_WX     (RZ_PERM_W | RZ_PERM_X)
#define RZ_PERM_SHAR   8
#define RZ_PERM_PRIV   16
#define RZ_PERM_ACCESS 32
#define RZ_PERM_CREAT  64

// HACK to fix capstone-android-mips build
#undef mips
#define mips mips

#if defined(__powerpc) || defined(__powerpc__)
#undef __POWERPC__
#define __POWERPC__ 1
#endif

#if __IPHONE_8_0 && TARGET_OS_IPHONE
#define LIBC_HAVE_SYSTEM 0
#else
#define LIBC_HAVE_SYSTEM 1
#endif

#if APPLE_SDK_IPHONEOS || APPLE_SDK_APPLETVOS || APPLE_SDK_WATCHOS || APPLE_SDK_APPLETVSIMULATOR || APPLE_SDK_WATCHSIMULATOR
#define LIBC_HAVE_PTRACE 0
#else
#define LIBC_HAVE_PTRACE 1
#endif

#if HAVE_FORK
#define LIBC_HAVE_FORK 1
#else
#define LIBC_HAVE_FORK 0
#endif

#if defined(__OpenBSD__)
#include <sys/param.h>
#undef MAXCOMLEN /* redefined in zipint.h */
#endif

/* release >= 5.9 */
#if __OpenBSD__ && OpenBSD >= 201605
#define LIBC_HAVE_PLEDGE 1
#else
#define LIBC_HAVE_PLEDGE 0
#endif

#if __sun
#define LIBC_HAVE_PRIV_SET 1
#else
#define LIBC_HAVE_PRIV_SET 0
#endif

#ifdef __GNUC__
#define UNUSED_FUNCTION(x) __attribute__((__unused__)) UNUSED_##x
#else
#define UNUSED_FUNCTION(x) UNUSED_##x
#endif

#ifdef __EMSCRIPTEN__
#define __UNIX__ 1
#endif

#ifdef __HAIKU__
#define __UNIX__ 1
#endif

#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
#define __KFBSD__ 1
#else
#define __KFBSD__ 0
#endif

#ifdef _MSC_VER
#define restrict
#define strcasecmp  stricmp
#define strncasecmp strnicmp
#define __WINDOWS__ 1

#include <time.h>
static inline struct tm *gmtime_r(const time_t *t, struct tm *r) {
	return (gmtime_s(r, t)) ? NULL : r;
}
#endif

#if defined(EMSCRIPTEN) || defined(__linux__) || defined(__APPLE__) || defined(__GNU__) || defined(__ANDROID__) || defined(__QNX__) || defined(__sun) || defined(__HAIKU__)
#define __BSD__  0
#define __UNIX__ 1
#endif
#if __KFBSD__ || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
#define __BSD__  1
#define __UNIX__ 1
#endif
#if __WINDOWS__ || _WIN32
#ifdef _MSC_VER
/* Must be included before windows.h */
#include <winsock2.h>
#include <ws2tcpip.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif
typedef int socklen_t;
#undef USE_SOCKETS
#define __WINDOWS__ 1
#undef __UNIX__
#undef __BSD__
#endif
#if __WINDOWS__ || _WIN32
#define __addr_t_defined
#include <windows.h>
#endif

#if defined(__APPLE__) && (__arm__ || __arm64__ || __aarch64__)
#define TARGET_OS_IPHONE 1
#else
#define TARGET_OS_IPHONE 0
#endif

#ifdef __GNUC__
#define FUNC_ATTR_MALLOC                __attribute__((malloc))
#define FUNC_ATTR_ALLOC_SIZE(x)         __attribute__((alloc_size(x)))
#define FUNC_ATTR_ALLOC_SIZE_PROD(x, y) __attribute__((alloc_size(x, y)))
#define FUNC_ATTR_ALLOC_ALIGN(x)        __attribute__((alloc_align(x)))
#define FUNC_ATTR_PURE                  __attribute__((pure))
#define FUNC_ATTR_CONST                 __attribute__((const))
#define FUNC_ATTR_USED                  __attribute__((used))
#define FUNC_ATTR_WARN_UNUSED_RESULT    __attribute__((warn_unused_result))
#define FUNC_ATTR_ALWAYS_INLINE         __attribute__((always_inline))

#ifdef __clang__
// clang only
#elif defined(__INTEL_COMPILER)
// intel only
#else
// gcc only
#endif
#else
#define FUNC_ATTR_MALLOC
#define FUNC_ATTR_ALLOC_SIZE(x)
#define FUNC_ATTR_ALLOC_SIZE_PROD(x, y)
#define FUNC_ATTR_ALLOC_ALIGN(x)
#define FUNC_ATTR_PURE
#define FUNC_ATTR_CONST
#define FUNC_ATTR_USED
#define FUNC_ATTR_WARN_UNUSED_RESULT
#define FUNC_ATTR_ALWAYS_INLINE
#endif

/* printf format check attributes */
#if defined(__clang__) || defined(__GNUC__)
#define RZ_PRINTF_CHECK(fmt, dots) __attribute__((format(printf, fmt, dots)))
#else
#define RZ_PRINTF_CHECK(fmt, dots)
#endif

#include <rz_types_base.h>

#undef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#undef _GNU_SOURCE
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h> /* for O_RDONLY */
#include <rz_endian.h> /* needs size_t */

#ifdef __cplusplus
extern "C" {
#endif

// TODO: FS or RZ_SYS_DIR ??
#undef FS
#if __WINDOWS__
#define FS            "\\"
#define RZ_SYS_DIR    "\\"
#define RZ_SYS_ENVSEP ";"
#define RZ_SYS_HOME   "USERPROFILE"
#define RZ_SYS_TMP    "TEMP"
#else
#define FS            "/"
#define RZ_SYS_DIR    "/"
#define RZ_SYS_ENVSEP ":"
#define RZ_SYS_HOME   "HOME"
#define RZ_SYS_TMP    "TMPDIR"
#endif

#define RZ_JOIN_2_PATHS(p1, p2)             p1 RZ_SYS_DIR p2
#define RZ_JOIN_3_PATHS(p1, p2, p3)         p1 RZ_SYS_DIR p2 RZ_SYS_DIR p3
#define RZ_JOIN_4_PATHS(p1, p2, p3, p4)     p1 RZ_SYS_DIR p2 RZ_SYS_DIR p3 RZ_SYS_DIR p4
#define RZ_JOIN_5_PATHS(p1, p2, p3, p4, p5) p1 RZ_SYS_DIR p2 RZ_SYS_DIR p3 RZ_SYS_DIR p4 RZ_SYS_DIR p5

#ifndef __packed
#define __packed __attribute__((__packed__))
#endif

typedef int (*PrintfCallback)(const char *str, ...) RZ_PRINTF_CHECK(1, 2);

/* compile-time introspection helpers */
#define CTO(y, z)    ((size_t) & ((y *)0)->z)
#define CTA(x, y, z) (x + CTO(y, z))
#define CTI(x, y, z) (*((size_t *)(CTA(x, y, z))))
#define CTS(x, y, z, t, v) \
	{ \
		t *_ = (t *)CTA(x, y, z); \
		*_ = v; \
	}

#ifdef RZ_IPI
#undef RZ_IPI
#endif

#define RZ_IPI

#ifdef RZ_HEAP
#undef RZ_HEAP
#endif
#define RZ_HEAP

#ifdef RZ_API
#undef RZ_API
#endif
#if RZ_SWIG
#define RZ_API export
#elif RZ_INLINE
#define RZ_API inline
#else
#if defined(__GNUC__) && __GNUC__ >= 4
#define RZ_API __attribute__((visibility("default")))
#elif defined(_MSC_VER)
#define RZ_API __declspec(dllexport)
#else
#define RZ_API
#endif
#endif

#define RZ_LIB_VERSION_HEADER(x) \
	RZ_API const char *x##_version(void)
#define RZ_LIB_VERSION(x) \
	RZ_API const char *x##_version(void) { return "" RZ_GITTAP; }

#define BITS2BYTES(x)    (((x) / 8) + (((x) % 8) ? 1 : 0))
#define ZERO_FILL(x)     memset(&x, 0, sizeof(x))
#define RZ_NEWS0(x, y)   (x *)calloc(y, sizeof(x))
#define RZ_NEWS(x, y)    (x *)malloc(sizeof(x) * (y))
#define RZ_NEW0(x)       (x *)calloc(1, sizeof(x))
#define RZ_NEW(x)        (x *)malloc(sizeof(x))
#define RZ_NEWCOPY(x, y) (x *)rz_new_copy(sizeof(x), y)

static inline void *rz_new_copy(int size, void *data) {
	void *a = malloc(size);
	if (a) {
		memcpy(a, data, size);
	}
	return a;
}
// TODO: Make RZ_NEW_COPY be 1 arg, not two
#define RZ_NEW_COPY(x, y) \
	x = (void *)malloc(sizeof(y)); \
	memcpy(x, y, sizeof(y))
#define RZ_MEM_ALIGN(x)  ((void *)(size_t)(((ut64)(size_t)x) & 0xfffffffffffff000LL))
#define RZ_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define RZ_PTR_MOVE(d, s) \
	d = s; \
	s = NULL;

#define RZ_PTR_ALIGN(v, t) \
	((char *)(((size_t)(v)) & ~(t - 1)))
#define RZ_PTR_ALIGN_NEXT(v, t) \
	((char *)(((size_t)(v) + (t - 1)) & ~(t - 1)))

#define RZ_BIT_SET(x, y)    (((ut8 *)x)[y >> 4] |= (1 << (y & 0xf)))
#define RZ_BIT_UNSET(x, y)  (((ut8 *)x)[y >> 4] &= ~(1 << (y & 0xf)))
#define RZ_BIT_TOGGLE(x, y) (RZ_BIT_CHK(x, y) ? RZ_BIT_UNSET(x, y) : RZ_BIT_SET(x, y))

//#define RZ_BIT_CHK(x,y) ((((const ut8*)x)[y>>4] & (1<<(y&0xf))))
#define RZ_BIT_CHK(x, y) (*(x) & (1 << (y)))

/* try for C99, but provide backwards compatibility */
#if defined(_MSC_VER) && (_MSC_VER <= 1800)
#define __func__ __FUNCTION__
#endif

#define PERROR_WITH_FILELINE 0

#if PERROR_WITH_FILELINE
/* make error messages useful by prepending file, line, and function name */
#define _perror(str, file, line, func) \
	{ \
		char buf[256]; \
		snprintf(buf, sizeof(buf), "[%s:%d %s] %s", file, line, func, str); \
		rz_sys_perror_str(buf); \
	}
#define perror(x)        _perror(x, __FILE__, __LINE__, __func__)
#define rz_sys_perror(x) _perror(x, __FILE__, __LINE__, __func__)
#else
#define rz_sys_perror(x) rz_sys_perror_str(x);
#endif

#if __UNIX__
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/time.h>
#ifdef __HAIKU__
// Original macro cast it to clockid_t
#undef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 0
#endif
#endif

#ifndef HAVE_EPRINTF
#define eprintf(...) fprintf(stderr, __VA_ARGS__)
#define HAVE_EPRINTF 1
#endif

#ifndef typeof
#define typeof(arg) __typeof__(arg)
#endif

// There is a bug of using "offsetof()" in the structure
// initialization in GCC < 5.0 versions
#if !(defined(__GNUC__) && __GNUC__ < 5)
#define rz_offsetof(type, member) offsetof(type, member)
#else
#if __SDB_WINDOWS__
#define rz_offsetof(type, member) ((unsigned long)(ut64) & ((type *)0)->member)
#else
#define rz_offsetof(type, member) ((unsigned long)&((type *)0)->member)
#endif
#endif

#define RZ_FREE(x) \
	{ \
		free((void *)x); \
		x = NULL; \
	}

#if __WINDOWS__
#define HAVE_REGEXP 0
#else
#define HAVE_REGEXP 1
#endif

#if __WINDOWS__
#define PFMT64x "I64x"
#define PFMT64d "I64d"
#define PFMT64u "I64u"
#define PFMT64o "I64o"
#define PFMTSZx "Ix"
#define PFMTSZd "Id"
#define PFMTSZu "Iu"
#define PFMTSZo "Io"
#define LDBLFMT "f"
#define HHXFMT  "x"
#else
#define PFMT64x "llx"
#define PFMT64d "lld"
#define PFMT64u "llu"
#define PFMT64o "llo"
#define PFMTSZx "zx"
#define PFMTSZd "zd"
#define PFMTSZu "zu"
#define PFMTSZo "zo"
#define LDBLFMT "Lf"
#define HHXFMT  "hhx"
#endif

#define PFMTDPTR "td"

#define PFMT32x "x"
#define PFMT32d "d"
#define PFMT32u "u"
#define PFMT32o "o"

#ifndef O_BINARY
#define O_BINARY 0
#endif

#if __APPLE__
#if __i386__
#define RZ_SYS_BASE ((ut64)0x1000)
#elif __x86_64__
#define RZ_SYS_BASE ((ut64)0x100000000)
#else
#define RZ_SYS_BASE ((ut64)0x1000)
#endif
#elif __WINDOWS__
#define RZ_SYS_BASE ((ut64)0x01001000)
#else // linux, bsd, ...
#if __arm__ || __arm64__
#define RZ_SYS_BASE ((ut64)0x4000)
#else
#define RZ_SYS_BASE ((ut64)0x8048000)
#endif
#endif

/* arch */
#if __i386__
#define RZ_SYS_ARCH   "x86"
#define RZ_SYS_BITS   RZ_SYS_BITS_32
#define RZ_SYS_ENDIAN 0
#elif __EMSCRIPTEN__
#define RZ_SYS_ARCH   "wasm"
#define RZ_SYS_BITS   (RZ_SYS_BITS_32 | RZ_SYS_BITS_64)
#define RZ_SYS_ENDIAN 0
#elif __x86_64__
#define RZ_SYS_ARCH   "x86"
#define RZ_SYS_BITS   (RZ_SYS_BITS_32 | RZ_SYS_BITS_64)
#define RZ_SYS_ENDIAN 0
#elif __POWERPC__
#define RZ_SYS_ARCH "ppc"
#ifdef __powerpc64__
#define RZ_SYS_BITS (RZ_SYS_BITS_32 | RZ_SYS_BITS_64)
#else
#define RZ_SYS_BITS RZ_SYS_BITS_32
#endif
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define RZ_SYS_ENDIAN 0
#else
#define RZ_SYS_ENDIAN 1
#endif
#elif __arm__
#define RZ_SYS_ARCH   "arm"
#define RZ_SYS_BITS   RZ_SYS_BITS_32
#define RZ_SYS_ENDIAN 0
#elif __arm64__ || __aarch64__
#define RZ_SYS_ARCH   "arm"
#define RZ_SYS_BITS   (RZ_SYS_BITS_32 | RZ_SYS_BITS_64)
#define RZ_SYS_ENDIAN 0
#elif __arc__
#define RZ_SYS_ARCH   "arc"
#define RZ_SYS_BITS   RZ_SYS_BITS_32
#define RZ_SYS_ENDIAN 0
#elif __s390x__
#define RZ_SYS_ARCH   "sysz"
#define RZ_SYS_BITS   RZ_SYS_BITS_64
#define RZ_SYS_ENDIAN 1
#elif __sparc__
#define RZ_SYS_ARCH   "sparc"
#define RZ_SYS_BITS   RZ_SYS_BITS_32
#define RZ_SYS_ENDIAN 1
#elif __mips__
#define RZ_SYS_ARCH   "mips"
#define RZ_SYS_BITS   RZ_SYS_BITS_32
#define RZ_SYS_ENDIAN 1
#elif __EMSCRIPTEN__
/* we should default to wasm when ready */
#define RZ_SYS_ARCH "x86"
#define RZ_SYS_BITS RZ_SYS_BITS_32
#elif __riscv__ || __riscv
#define RZ_SYS_ARCH   "riscv"
#define RZ_SYS_ENDIAN 0
#if __riscv_xlen == 32
#define RZ_SYS_BITS RZ_SYS_BITS_32
#else
#define RZ_SYS_BITS (RZ_SYS_BITS_32 | RZ_SYS_BITS_64)
#endif
#else
#ifdef _MSC_VER
#ifdef _WIN64
#define RZ_SYS_ARCH   "x86"
#define RZ_SYS_BITS   (RZ_SYS_BITS_32 | RZ_SYS_BITS_64)
#define RZ_SYS_ENDIAN 0
#define __x86_64__    1
#else
#define RZ_SYS_ARCH   "x86"
#define RZ_SYS_BITS   (RZ_SYS_BITS_32)
#define __i386__      1
#define RZ_SYS_ENDIAN 0
#endif
#else
#define RZ_SYS_ARCH   "unknown"
#define RZ_SYS_BITS   RZ_SYS_BITS_32
#define RZ_SYS_ENDIAN 0
#endif
#endif

#define RZ_SYS_ENDIAN_NONE   0
#define RZ_SYS_ENDIAN_LITTLE 1
#define RZ_SYS_ENDIAN_BIG    2
#define RZ_SYS_ENDIAN_BI     3

typedef enum {
	RZ_SYS_ARCH_NONE = 0,
	RZ_SYS_ARCH_X86,
	RZ_SYS_ARCH_ARM,
	RZ_SYS_ARCH_PPC,
	RZ_SYS_ARCH_M68K,
	RZ_SYS_ARCH_JAVA,
	RZ_SYS_ARCH_MIPS,
	RZ_SYS_ARCH_SPARC,
	RZ_SYS_ARCH_XAP,
	RZ_SYS_ARCH_MSIL,
	RZ_SYS_ARCH_OBJD,
	RZ_SYS_ARCH_BF,
	RZ_SYS_ARCH_SH,
	RZ_SYS_ARCH_AVR,
	RZ_SYS_ARCH_DALVIK,
	RZ_SYS_ARCH_Z80,
	RZ_SYS_ARCH_ARC,
	RZ_SYS_ARCH_I8080,
	RZ_SYS_ARCH_RAR,
	RZ_SYS_ARCH_8051,
	RZ_SYS_ARCH_TMS320,
	RZ_SYS_ARCH_EBC,
	RZ_SYS_ARCH_H8300,
	RZ_SYS_ARCH_CR16,
	RZ_SYS_ARCH_V850,
	RZ_SYS_ARCH_SYSZ,
	RZ_SYS_ARCH_XCORE,
	RZ_SYS_ARCH_PROPELLER,
	RZ_SYS_ARCH_MSP430,
	RZ_SYS_ARCH_CRIS,
	RZ_SYS_ARCH_HPPA,
	RZ_SYS_ARCH_V810,
	RZ_SYS_ARCH_LM32,
	RZ_SYS_ARCH_RISCV
} RzSysArch;

#if HAVE_CLOCK_NANOSLEEP && CLOCK_MONOTONIC && (__linux__ || (__FreeBSD__ && __FreeBSD_version >= 1101000) || (__NetBSD__ && __NetBSD_Version__ >= 700000000))
#define HAS_CLOCK_NANOSLEEP 1
#else
#define HAS_CLOCK_NANOSLEEP 0
#endif

/* os */
#if defined(__QNX__)
#define RZ_SYS_OS "qnx"
//#elif TARGET_OS_IPHONE
//#define RZ_SYS_OS "ios"
#elif defined(__APPLE__)
#define RZ_SYS_OS "darwin"
#elif defined(__linux__)
#define RZ_SYS_OS "linux"
#elif defined(__WINDOWS__)
#define RZ_SYS_OS "windows"
#elif defined(__NetBSD__)
#define RZ_SYS_OS "netbsd"
#elif defined(__OpenBSD__)
#define RZ_SYS_OS "openbsd"
#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
#define RZ_SYS_OS "freebsd"
#elif defined(__HAIKU__)
#define RZ_SYS_OS "haiku"
#else
#define RZ_SYS_OS "unknown"
#endif

#ifdef __cplusplus
}
#endif

static inline void rz_run_call1(void *fcn, void *arg1) {
	((void (*)(void *))(fcn))(arg1);
}

static inline void rz_run_call2(void *fcn, void *arg1, void *arg2) {
	((void (*)(void *, void *))(fcn))(arg1, arg2);
}

static inline void rz_run_call3(void *fcn, void *arg1, void *arg2, void *arg3) {
	((void (*)(void *, void *, void *))(fcn))(arg1, arg2, arg3);
}

static inline void rz_run_call4(void *fcn, void *arg1, void *arg2, void *arg3, void *arg4) {
	((void (*)(void *, void *, void *, void *))(fcn))(arg1, arg2, arg3, arg4);
}

static inline void rz_run_call5(void *fcn, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5) {
	((void (*)(void *, void *, void *, void *, void *))(fcn))(arg1, arg2, arg3, arg4, arg5);
}

static inline void rz_run_call6(void *fcn, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5,
	void *arg6) {
	((void (*)(void *, void *, void *, void *, void *, void *))(fcn))(arg1, arg2, arg3, arg4, arg5, arg6);
}

static inline void rz_run_call7(void *fcn, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5,
	void *arg6, void *arg7) {
	((void (*)(void *, void *, void *, void *, void *, void *, void *))(fcn))(arg1, arg2, arg3, arg4, arg5, arg6, arg7);
}

static inline void rz_run_call8(void *fcn, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5,
	void *arg6, void *arg7, void *arg8) {
	((void (*)(void *, void *, void *, void *, void *, void *, void *, void *))(fcn))(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
}

static inline void rz_run_call9(void *fcn, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5,
	void *arg6, void *arg7, void *arg8, void *arg9) {
	((void (*)(void *, void *, void *, void *, void *, void *, void *, void *, void *))(fcn))(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);
}

static inline void rz_run_call10(void *fcn, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5,
	void *arg6, void *arg7, void *arg8, void *arg9, void *arg10) {
	((void (*)(void *, void *, void *, void *, void *, void *, void *, void *, void *, void *))(fcn))(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
}

#define RZ_V_NOT(op, fail_ret) \
	if ((op) == (fail_ret)) \
	RZ_LOG_WARN(#op " at %s:%d failed: %s\n", __FILE__, __LINE__, strerror(errno))
#define rz_xwrite(fd, buf, count)           RZ_V_NOT(write(fd, buf, count), -1)
#define rz_xread(fd, buf, count)            RZ_V_NOT(read(fd, buf, count), -1)
#define rz_xfreopen(pathname, mode, stream) RZ_V_NOT(freopen(pathname, mode, stream), NULL)

#ifndef container_of
#ifdef _MSC_VER
#define container_of(ptr, type, member) ((type *)((char *)(ptr)-offsetof(type, member)))
#else
#define container_of(ptr, type, member) ((type *)((char *)(__typeof__(((type *)0)->member) *){ ptr } - offsetof(type, member)))
#endif
#endif

// reference counter
typedef int RRef;

#define RZ_REF_NAME    refcount
#define rz_ref(x)      x->RZ_REF_NAME++;
#define rz_ref_init(x) x->RZ_REF_NAME = 1
#define rz_unref(x, f) \
	{ \
		assert(x->RZ_REF_NAME > 0); \
		if (!--(x->RZ_REF_NAME)) { \
			f(x); \
		} \
	}

#define RZ_REF_TYPE RRef RZ_REF_NAME
#define RZ_REF_FUNCTIONS(s, n) \
	static inline void n##_ref(s *x) { x->RZ_REF_NAME++; } \
	static inline void n##_unref(s *x) { rz_unref(x, n##_free); }

#endif // RZ_TYPES_H
