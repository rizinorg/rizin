// SPDX-FileCopyrightText: 2011-2014 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_MAGIC_H
#define RZ_MAGIC_H

#include <rz_util/rz_rbtree.h>
#include <rz_util/rz_regex.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_magic);

#ifndef MAGICFILE
#define MAGICFILE "/etc/magic"
#endif

#ifdef RZ_API

#ifdef __EMX__
#define PATHSEP ';'
#else
#define PATHSEP ':'
#endif

/* limits */
#ifndef HOWMANY
#define HOWMANY (256 * 1024) /* how much of the file to look at */
#endif
#define MAXDESC   64
#define MAXMAGIS  8192 /* max entries in any one magic file or directory */
#define MAXstring 32 /* max leng of "string" types */

/* define this outside to fix build for g++ */
union VALUETYPE {
	ut8 b;
	ut16 h;
	ut32 l;
	ut64 q;
	ut8 hs[2]; /* 2 bytes of a fixed-endian "short" */
	ut8 hl[4]; /* 4 bytes of a fixed-endian "long" */
	ut8 hq[8]; /* 8 bytes of a fixed-endian "quad" */
	char s[MAXstring]; /* the search string or regex pattern */
	float f;
	double d;
}; /* either number or string */

/**
 * \brief Size of the buffer the rz_magic module checks for magics.
 */
#define RZ_MAGIC_BUF_SIZE (HOWMANY * (1 + sizeof(union VALUETYPE)))

/* constants */
#define MAGICNO        0xF11E041C
#define VERSIONNO      5
#define FILE_MAGICSIZE (32 * 6)

#define FILE_LOAD    0
#define FILE_CHECK   1
#define FILE_COMPILE 2

struct rz_magic {
	/* Word 1 */
	ut16 cont_level; /* level of ">" */
	ut8 flag;

#define INDIR       0x01 /* if '(...)' appears */
#define OFFADD      0x02 /* if '>&' or '>...(&' appears */
#define INDIROFFADD 0x04 /* if '>&(' appears */
#define UNSIGNED    0x08 /* comparison is unsigned */
#define NOSPACE     0x10 /* suppress space character before output */
#define BINTEST     0x20 /* test is for a binary type (set only for top-level tests) */
#define TEXTTEST    0 /* for passing to file_softmagic */

	ut8 dummy1;

	/* Word 2 */
	ut8 reln; /* relation (0=eq, '>'=gt, etc) */
	ut8 vallen; /* length of string value, if any */
	ut8 type; /* comparison type (FILE_*) */
	ut8 in_type; /* type of indirection */
#define FILE_INVALID    0
#define FILE_BYTE       1
#define FILE_SHORT      2
#define FILE_DEFAULT    3
#define FILE_LONG       4
#define FILE_STRING     5
#define FILE_DATE       6
#define FILE_BESHORT    7
#define FILE_BELONG     8
#define FILE_BEDATE     9
#define FILE_LESHORT    10
#define FILE_LELONG     11
#define FILE_LEDATE     12
#define FILE_PSTRING    13
#define FILE_LDATE      14
#define FILE_BELDATE    15
#define FILE_LELDATE    16
#define FILE_REGEX      17
#define FILE_BESTRING16 18
#define FILE_LESTRING16 19
#define FILE_SEARCH     20
#define FILE_MEDATE     21
#define FILE_MELDATE    22
#define FILE_MELONG     23
#define FILE_QUAD       24
#define FILE_LEQUAD     25
#define FILE_BEQUAD     26
#define FILE_QDATE      27
#define FILE_LEQDATE    28
#define FILE_BEQDATE    29
#define FILE_QLDATE     30
#define FILE_LEQLDATE   31
#define FILE_BEQLDATE   32
#define FILE_FLOAT      33
#define FILE_BEFLOAT    34
#define FILE_LEFLOAT    35
#define FILE_DOUBLE     36
#define FILE_BEDOUBLE   37
#define FILE_LEDOUBLE   38
#define FILE_NAMES_SIZE 39 /* size of array to contain all names */

#define MAGIC_IS_STRING(t) \
	((t) == FILE_STRING || \
		(t) == FILE_PSTRING || \
		(t) == FILE_BESTRING16 || \
		(t) == FILE_LESTRING16 || \
		(t) == FILE_REGEX || \
		(t) == FILE_SEARCH || \
		(t) == FILE_DEFAULT)

#define FILE_FMT_NONE   0
#define FILE_FMT_NUM    1 /* "cduxXi" */
#define FILE_FMT_STR    2 /* "s" */
#define FILE_FMT_QUAD   3 /* "ll" */
#define FILE_FMT_FLOAT  4 /* "eEfFgG" */
#define FILE_FMT_DOUBLE 5 /* "eEfFgG" */

	/* Word 3 */
	ut8 in_op; /* operator for indirection */
	ut8 mask_op; /* operator for mask */
	ut8 cond; /* conditional type */
	ut8 dummy2;

#define FILE_OPS        "&|^+-*/%"
#define FILE_OPAND      0
#define FILE_OPOR       1
#define FILE_OPXOR      2
#define FILE_OPADD      3
#define FILE_OPMINUS    4
#define FILE_OPMULTIPLY 5
#define FILE_OPDIVIDE   6
#define FILE_OPMODULO   7
#define FILE_OPS_MASK   0x07 /* mask for above ops */
#define FILE_UNUSED_1   0x08
#define FILE_UNUSED_2   0x10
#define FILE_UNUSED_3   0x20
#define FILE_OPINVERSE  0x40
#define FILE_OPINDIRECT 0x80

#define COND_NONE 0
#define COND_IF   1
#define COND_ELIF 2
#define COND_ELSE 3

	/* Word 4 */
	ut32 offset; /* offset to magic number */
	/* Word 5 */
	ut32 in_offset; /* offset from indirection */
	/* Word 6 */
	ut32 lineno; /* line number in magic file */
	/* Word 7,8 */
	union {
		ut64 _mask; /* for use with numeric and date types */
		struct {
			ut32 _count; /* repeat/line count */
			ut32 _flags; /* modifier flags */
		} _s; /* for use with string types */
	} _u;

#define num_mask  _u._mask
#define str_range _u._s._count
#define str_flags _u._s._flags

	/* Words 9-16 */
	union VALUETYPE value;
	/* Words 17..31 */
	char desc[MAXDESC]; /* description */
	/* Words 32..47 */
	char mimetype[MAXDESC]; /* MIME type */
};

#define BIT(A)                        (1 << (A))
#define STRING_COMPACT_BLANK          BIT(0)
#define STRING_COMPACT_OPTIONAL_BLANK BIT(1)
#define STRING_IGNORE_LOWERCASE       BIT(2)
#define STRING_IGNORE_UPPERCASE       BIT(3)
#define REGEX_OFFSET_START            BIT(4)
#define CHAR_COMPACT_BLANK            'B'
#define CHAR_COMPACT_OPTIONAL_BLANK   'b'
#define CHAR_IGNORE_LOWERCASE         'c'
#define CHAR_IGNORE_UPPERCASE         'C'
#define CHAR_REGEX_OFFSET_START       's'
#define STRING_IGNORE_CASE            (STRING_IGNORE_LOWERCASE | STRING_IGNORE_UPPERCASE)
#define STRING_DEFAULT_RANGE          100

/* list of magic entries */
struct mlist {
	struct rz_magic *magic; /* array of magic entries */
	ut32 nmagic; /* number of entries in array */
	int mapped; /* allocation type: 0 => apprentice_file
		     *                  1 => apprentice_map + malloc
		     *                  2 => apprentice_map + mmap */
	struct mlist *next, *prev;
};

#define MAGIC_STRING_SIZE         31
#define MAGIC_STRENGTH_MULTIPLIER 10

#define MAGIC_TEST_TEXT 0x1
#define MAGIC_TEST_MIME 0x2

/*
 * to select alternate encoding format
 */
#define VIS_OCTAL  0x01 /* use octal \ddd format */
#define VIS_CSTYLE 0x02 /* use \[nrft0..] where appropriate */

/*
 * to alter set of characters encoded (default is to encode all
 * non-graphic except space, tab, and newline).
 */
#define VIS_SP    0x04 /* also encode space */
#define VIS_TAB   0x08 /* also encode tab */
#define VIS_NL    0x10 /* also encode newline */
#define VIS_WHITE (VIS_SP | VIS_TAB | VIS_NL)
#define VIS_SAFE  0x20 /* only encode "unsafe" characters */
#define VIS_DQ    0x200 /* backslash-escape double quotes */
#define VIS_ALL   0x400 /* encode all characters */

/*
 * other
 */
#define VIS_NOSLASH 0x40 /* inhibit printing '\' */
#define VIS_GLOB    0x100 /* encode glob(3) magics and '#' */

enum magic_type {
	MAGIC_TYPE_NONE = 0,
	MAGIC_TYPE_BYTE,
	MAGIC_TYPE_SHORT,
	MAGIC_TYPE_LONG,
	MAGIC_TYPE_QUAD,
	MAGIC_TYPE_UBYTE,
	MAGIC_TYPE_USHORT,
	MAGIC_TYPE_ULONG,
	MAGIC_TYPE_UQUAD,
	MAGIC_TYPE_FLOAT,
	MAGIC_TYPE_DOUBLE,
	MAGIC_TYPE_STRING,
	MAGIC_TYPE_PSTRING,
	MAGIC_TYPE_DATE,
	MAGIC_TYPE_QDATE,
	MAGIC_TYPE_LDATE,
	MAGIC_TYPE_QLDATE,
	MAGIC_TYPE_UDATE,
	MAGIC_TYPE_UQDATE,
	MAGIC_TYPE_ULDATE,
	MAGIC_TYPE_UQLDATE,
	MAGIC_TYPE_BESHORT,
	MAGIC_TYPE_BELONG,
	MAGIC_TYPE_BEQUAD,
	MAGIC_TYPE_UBESHORT,
	MAGIC_TYPE_UBELONG,
	MAGIC_TYPE_UBEQUAD,
	MAGIC_TYPE_BEFLOAT,
	MAGIC_TYPE_BEDOUBLE,
	MAGIC_TYPE_BEDATE,
	MAGIC_TYPE_BEQDATE,
	MAGIC_TYPE_BELDATE,
	MAGIC_TYPE_BEQLDATE,
	MAGIC_TYPE_UBEDATE,
	MAGIC_TYPE_UBEQDATE,
	MAGIC_TYPE_UBELDATE,
	MAGIC_TYPE_UBEQLDATE,
	MAGIC_TYPE_BESTRING16,
	MAGIC_TYPE_LESHORT,
	MAGIC_TYPE_LELONG,
	MAGIC_TYPE_LEQUAD,
	MAGIC_TYPE_ULESHORT,
	MAGIC_TYPE_ULELONG,
	MAGIC_TYPE_ULEQUAD,
	MAGIC_TYPE_LEFLOAT,
	MAGIC_TYPE_LEDOUBLE,
	MAGIC_TYPE_LEDATE,
	MAGIC_TYPE_LEQDATE,
	MAGIC_TYPE_LELDATE,
	MAGIC_TYPE_LEQLDATE,
	MAGIC_TYPE_ULEDATE,
	MAGIC_TYPE_ULEQDATE,
	MAGIC_TYPE_ULELDATE,
	MAGIC_TYPE_ULEQLDATE,
	MAGIC_TYPE_LESTRING16,
	MAGIC_TYPE_MELONG,
	MAGIC_TYPE_MEDATE,
	MAGIC_TYPE_MELDATE,
	MAGIC_TYPE_REGEX,
	MAGIC_TYPE_SEARCH,
	MAGIC_TYPE_DEFAULT,
	MAGIC_TYPE_CLEAR,
	MAGIC_TYPE_NAME,
	MAGIC_TYPE_USE,
};

typedef struct rz_magic_line_t RzMagicLine;
typedef struct rz_magic_t RzMagic;

/**
 * \brief Represents a single parsed rule from a magic file.
 *
 * This structure contains all metadata and matching criteria for a single magic
 * rule, including its type, operators, matching strength, and any child rules.
 */
struct rz_magic_line_t {
	RBNode rb;
	RzMagic *root;
	ut32 line;
	ut32 strength;
	RzMagicLine *parent;

	char strength_operator;
	ut32 strength_value;

	int text;

	int64_t offset;
	int offset_relative;

	char indirect_type;
	int indirect_relative;
	int64_t indirect_offset;
	char indirect_operator;
	int64_t indirect_operand;

	char *name;

	enum magic_type type;
	char *type_string;
	char type_operator;
	int64_t type_operand;

	char test_operator;
	int test_not;
	char *test_string;
	size_t test_string_size;
	ut64 test_unsigned;
	int64_t test_signed;
	double test_double;

	int stringify;
	char *result;
	char *mimetype;

	RzList *children;
};

/**
 * \brief Container for magic rules and related metadata.
 *
 * Holds the path to the magic file(s), RBTree indexes for rule storage and lookup,
 * and precompiled regex patterns for various data types.
 */
struct rz_magic_t {
	char *path;

	RBTree magic_tree;
	RBTree magic_named_tree;

	int compiled;
	RzRegex *format_short;
	RzRegex *format_long;
	RzRegex *format_quad;
	RzRegex *format_float;
	RzRegex *format_string;
};

/**
 * \brief Represents the state of magic rules processing.
 *
 * This structure stores details about the data being analyzed.
 * It is used during magic rules evaluation.
 */
typedef struct rz_magic_state_t {
	char out[4096];
	const char *mimetype;
	int text;
	const char *base;
	size_t size;
	size_t offset;
	int matched;
	size_t start;
	int reverse;
} RzMagicState;

RZ_API RZ_OWN RzMagic *rz_magic_new();
RZ_API void rz_magic_free(RZ_NULLABLE RZ_OWN RzMagic *);
RZ_API RZ_OWN char *rz_magic_buffer(RZ_NONNULL const RzMagic *, RZ_NONNULL const ut8 *, size_t);
RZ_API bool rz_magic_load(RZ_NONNULL RZ_BORROW RzMagic *, RZ_NONNULL const char *);

#endif

#ifdef __cplusplus
}
#endif

#endif
