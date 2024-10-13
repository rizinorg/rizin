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
#if HAVE_HEADER_INTTYPES_H
#include <inttypes.h>
#endif

// TODO: fix this to make it crosscompile-friendly: RZ_SYS_OSTYPE ?
/* operating system */
#undef __BSD__
#undef __KFBSD__
#undef __UNIX__
#undef __WINDOWS__

// TODO: these modes should be dropped when oldshell is removed in favour of RzOutputMode.
#define RZ_MODE_PRINT     0x000
#define RZ_MODE_RIZINCMD  0x001
#define RZ_MODE_SET       0x002
#define RZ_MODE_SIMPLE    0x004
#define RZ_MODE_JSON      0x008
#define RZ_MODE_ARRAY     0x010
#define RZ_MODE_SIMPLEST  0x020
#define RZ_MODE_CLASSDUMP 0x040
#define RZ_MODE_EQUAL     0x080

#define RZ_IN    /* do not use, implicit */
#define RZ_OUT   /* parameter is written, not read */
#define RZ_INOUT /* parameter is read and written */

#ifdef RZ_BINDINGS
#define RZ_OWN    __attribute__((annotate("RZ_OWN")))
#define RZ_BORROW __attribute__((annotate("RZ_BORROW")))

#define RZ_NONNULL   __attribute__((annotate("RZ_NONNULL")))
#define RZ_NULLABLE  __attribute__((annotate("RZ_NULLABLE")))
#define RZ_DEPRECATE __attribute__((annotate("RZ_DEPRECATE")))
#else
#define RZ_OWN       /* pointer ownership is transferred */
#define RZ_BORROW    /* pointer ownership is not transferred, it must not be freed by the receiver */
#define RZ_NONNULL   /* pointer can not be null */
#define RZ_NULLABLE  /* pointer can be null */
#define RZ_DEPRECATE /* should not be used in new code and should/will be removed in the future */
#endif

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

#if defined(__powerpc) || defined(__powerpc__)
#undef __POWERPC__
#define __POWERPC__ 1
#endif

#if defined(__OpenBSD__)
#include <sys/param.h>
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

#ifdef __MSYS__
#define __UNIX__ 1
#endif

#ifdef _MSC_VER
#define restrict
#define strcasecmp  stricmp
#define strncasecmp strnicmp
#define __WINDOWS__ 1
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
#define __WINDOWS__  1
#define _WINSOCKAPI_ /* Prevent inclusion of winsock.h in windows.h */
#undef __UNIX__
#undef __BSD__
#endif

#if defined(__APPLE__) && ((__arm__ || __arm64__ || __aarch64__) && IS_IOS)
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
#include <rz_constructor.h>

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

#if __WINDOWS__
#define RZ_SYS_DIR    "\\"
#define RZ_SYS_ENVSEP ";"
#define RZ_SYS_HOME   "USERPROFILE"
#define RZ_SYS_TMP    "TEMP"
#else
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
#ifdef RZ_BINDINGS
#define RZ_API __attribute__((annotate("RZ_API")))
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
	RZ_API const char *x##_version(void) { \
		return "" RZ_VERSION; \
	}

#define BITS2BYTES(x)    (((x) / 8) + (((x) % 8) ? 1 : 0))
#define ZERO_FILL(x)     memset(&x, 0, sizeof(x))
#define RZ_NEWS0(x, y)   (x *)calloc(y, sizeof(x))
#define RZ_NEWS(x, y)    (x *)malloc(sizeof(x) * (y))
#define RZ_NEW0(x)       (x *)calloc(1, sizeof(x))
#define RZ_NEW(x)        (x *)malloc(sizeof(x))
#define RZ_NEWCOPY(x, y) (x *)rz_new_copy(sizeof(x), y)

static inline void *rz_new_copy(int size, const void *data) {
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

#define RZ_BIT_MASK32(x, y) ((1UL << (x)) - (1UL << (y)))
#define RZ_BIT_MASK64(x, y) ((1ULL << (x)) - (1ULL << (y)))
#define RZ_BIT_SET(x, y)    (((ut8 *)x)[y >> 4] |= (1 << (y & 0xf)))
#define RZ_BIT_UNSET(x, y)  (((ut8 *)x)[y >> 4] &= ~(1 << (y & 0xf)))
#define RZ_BIT_TOGGLE(x, y) (RZ_BIT_CHK(x, y) ? RZ_BIT_UNSET(x, y) : RZ_BIT_SET(x, y))

// #define RZ_BIT_CHK(x,y) ((((const ut8*)x)[y>>4] & (1<<(y&0xf))))
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
#if !(defined(__GNUC__) && __GNUC__ < 5) || defined(__clang__)
#define rz_offsetof(type, member) offsetof(type, member)
#else
#if __WINDOWS__
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

#define RZ_FREE_CUSTOM(x, y) \
	{ \
		y(x); \
		x = NULL; \
	}

#if __WINDOWS__
#define PFMT64x  "I64x"
#define PFMT64d  "I64d"
#define PFMT64u  "I64u"
#define PFMT64o  "I64o"
#define PFMTSZx  "Ix"
#define PFMTSZd  "Id"
#define PFMTSZu  "Iu"
#define PFMTSZo  "Io"
#define LDBLFMTg "g"
#define LDBLFMTf "f"
#define HHXFMT   "x"
#else
#define PFMT64x  "llx"
#define PFMT64d  "lld"
#define PFMT64u  "llu"
#define PFMT64o  "llo"
#define PFMTSZx  "zx"
#define PFMTSZd  "zd"
#define PFMTSZu  "zu"
#define PFMTSZo  "zo"
#define LDBLFMTg "Lg"
#define LDBLFMTf "Lf"
#define HHXFMT   "hhx"
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
#if defined(_M_X64) || defined(_M_AMD64)
#define RZ_SYS_ARCH   "x86"
#define RZ_SYS_BITS   (RZ_SYS_BITS_32 | RZ_SYS_BITS_64)
#define RZ_SYS_ENDIAN 0
#define __x86_64__    1
#elif defined(_M_IX86)
#define RZ_SYS_ARCH   "x86"
#define RZ_SYS_BITS   (RZ_SYS_BITS_32)
#define RZ_SYS_ENDIAN 0
#define __i386__      1
#elif defined(_M_ARM64)
#define RZ_SYS_ARCH   "arm"
#define RZ_SYS_BITS   (RZ_SYS_BITS_32 | RZ_SYS_BITS_64)
#define RZ_SYS_ENDIAN 0
#define __arm64__     1
#elif defined(_M_ARM)
#define RZ_SYS_ARCH   "arm"
#define RZ_SYS_BITS   RZ_SYS_BITS_32
#define RZ_SYS_ENDIAN 0
#define __arm__       1
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
	RZ_SYS_ARCH_RISCV,
	RZ_SYS_ARCH_TRICORE,
} RzSysArch;

/* os */
#if defined(__QNX__)
#define RZ_SYS_OS "qnx"
// #elif TARGET_OS_IPHONE
// #define RZ_SYS_OS "ios"
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
typedef int RzRef;

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

#define RZ_REF_TYPE RzRef RZ_REF_NAME
#define RZ_REF_FUNCTIONS(s, n) \
	static inline void n##_ref(s *x) { \
		x->RZ_REF_NAME++; \
	} \
	static inline void n##_unref(s *x) { \
		rz_unref(x, n##_free); \
	}

typedef struct rz_core_t RzCore;

// Mimics order in RzCore.
struct dummy_rz_core_t {
	void *rasm;
	ut8 ptr_alignment_I;
	void *analysis;
	ut8 ptr_alignment_II;
	void *bin;
	ut8 ptr_alignment_III;
};

// Mimics order in RzAsm.
struct dummy_rz_asm_t {
	void *core;
	ut8 ptr_alignment_I;
	void *plugin_data;
	ut8 ptr_alignment_II;
};

// Mimics order in RzAnalysis.
struct dummy_rz_analysis_t {
	void *core;
	ut8 ptr_alignment_I;
};

/**
 * \brief The hacky way to get the RzAsm pointer from RzAnalysis.
 * Will be removed with the RzArch refactor.
 */
static inline void /*<RzAsm>*/ *rz_analysis_to_rz_asm(RZ_NONNULL void /*<RzAnalysis>*/ *rz_analysis) {
	assert(rz_analysis && "This function can only be used if RzAnalysis and RzAsm were set up before.");
	struct dummy_rz_analysis_t *analysis = (struct dummy_rz_analysis_t *) rz_analysis;
	struct dummy_rz_core_t *core = (struct dummy_rz_core_t *) analysis->core;
	if (!core) {
		return NULL;
	}
	void *rasm = core->rasm;
	assert(rasm && "This function can only be used if RzAnalysis and RzAsm were set up before.");
	return rasm;
}

/**
 * \brief The hacky way to get the RzAnalysis pointer from RzAsm.
 * Will be removed with the RzArch refactor.
 */
static inline void /*<RzAnalysis>*/ *rz_asm_to_rz_analysis(RZ_NONNULL void /*<RzAsm>*/ *rz_asm) {
	assert(rz_asm && "This function can only be used if RzAnalysis and RzAsm were set up before.");
	struct dummy_rz_asm_t *rasm = (struct dummy_rz_asm_t *) rz_asm;
	struct dummy_rz_core_t *core = (struct dummy_rz_core_t *) rasm->core;
	if (!core) {
		return NULL;
	}
	void *analysis = core->analysis;
	return analysis;
}

/**
 * \brief The hacky way to get the plugin data from RzAsm via RzAnalysis.
 * Will be removed with the RzArch refactor.
 */
static inline void *rz_asm_plugin_data_from_rz_analysis(RZ_NONNULL void /*<RzAnalysis>*/ *rz_analysis) {
	assert(rz_analysis && "This function can only be used if RzAnalysis and RzAsm were set up before.");
	struct dummy_rz_asm_t *rasm = (struct dummy_rz_asm_t *) rz_analysis_to_rz_asm(rz_analysis);
	assert(rasm && "This function can only be used if RzAnalysis and RzAsm were set up before.");
	return rasm->plugin_data;
}

#endif // RZ_TYPES_H
