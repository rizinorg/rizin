// SPDX-FileCopyrightText: 2001-2004 Fabrice Bellard
// SPDX-License-Identifier: LGPL-3.0-or-later

#define DEF(id, str) str "\0"

static const enum token_id {
	TOK_DEFINE = 0,
	TOK_INCLUDE,
	TOK_INCLUDE_NEXT,
	TOK_IF,
	TOK_IFDEF,
	TOK_IFNDEF,
	TOK_ELSE,
	TOK_ELIF,
	TOK_ENDIF,
	TOK_DEFINED,
	TOK_UNDEF,
	TOK_ERROR,
	TOK_WARNING,
	TOK_LINE,
	TOK_PRAGMA,
	TOK___LINE__,
	TOK___FILE__,
	TOK___DATE__,
	TOK___TIME__,
	TOK___FUNCTION__,
	TOK___VA_ARGS__,
	TOK___FUNC__,
	TOK_pack,
	TOK_ASM_push,
	TOK_ASM_pop,
};

static const char preprocessor_tokens[] =
	// clang-format off
	DEF(TOK_DEFINE, "define")
	DEF(TOK_INCLUDE, "include")
	DEF(TOK_INCLUDE_NEXT, "include_next")
	DEF(TOK_IF, "if")
	DEF(TOK_IFDEF, "ifdef")
	DEF(TOK_IFNDEF, "ifndef")
	DEF(TOK_ELSE, "else")
	DEF(TOK_ELIF, "elif")
	DEF(TOK_ENDIF, "endif")
	DEF(TOK_DEFINED, "defined")
	DEF(TOK_UNDEF, "undef")
	DEF(TOK_ERROR, "error")
	DEF(TOK_WARNING, "warning")
	DEF(TOK_LINE, "line")
	DEF(TOK_PRAGMA, "pragma")
	DEF(TOK___LINE__, "__LINE__")
	DEF(TOK___FILE__, "__FILE__")
	DEF(TOK___DATE__, "__DATE__")
	DEF(TOK___TIME__, "__TIME__")
	DEF(TOK___FUNCTION__, "__FUNCTION__")
	DEF(TOK___VA_ARGS__, "__VA_ARGS__")

	/* special identifiers */
	DEF(TOK___FUNC__, "__func__")

	/* pragma */
	DEF(TOK_pack, "pack")
	/* already defined for assembler */
	DEF(TOK_ASM_push, "push")
	DEF(TOK_ASM_pop, "pop");
// clang-format on

#undef DEF

/* token values */

/* warning: the following compare tokens depend on i386 asm code */
#define TOK_ULT    0x92
#define TOK_UGE    0x93
#define TOK_EQ     0x94
#define TOK_NE     0x95
#define TOK_ULE    0x96
#define TOK_UGT    0x97
#define TOK_Nset   0x98
#define TOK_Nclear 0x99
#define TOK_LT     0x9c
#define TOK_GE     0x9d
#define TOK_LE     0x9e
#define TOK_GT     0x9f

#define TOK_LAND 0xa0
#define TOK_LOR  0xa1

#define TOK_DEC       0xa2
#define TOK_MID       0xa3 /* inc/dec, to void constant */
#define TOK_INC       0xa4
#define TOK_UDIV      0xb0 /* unsigned division */
#define TOK_UMOD      0xb1 /* unsigned modulo */
#define TOK_PDIV      0xb2 /* fast division with undefined rounding for pointers */
#define TOK_CINT      0xb3 /* number in tokc */
#define TOK_CCHAR     0xb4 /* char constant in tokc */
#define TOK_STR       0xb5 /* pointer to string in tokc */
#define TOK_TWOSHARPS 0xb6 /* ## preprocessing token */
#define TOK_LCHAR     0xb7
#define TOK_LSTR      0xb8
#define TOK_CFLOAT    0xb9 /* float constant */
#define TOK_LINENUM   0xba /* line number info */
#define TOK_CDOUBLE   0xc0 /* double constant */
#define TOK_CLDOUBLE  0xc1 /* long double constant */
#define TOK_UMULL     0xc2 /* unsigned 32x32 -> 64 mul */
#define TOK_ADDC1     0xc3 /* add with carry generation */
#define TOK_ADDC2     0xc4 /* add with carry use */
#define TOK_SUBC1     0xc5 /* add with carry generation */
#define TOK_SUBC2     0xc6 /* add with carry use */
#define TOK_CUINT     0xc8 /* unsigned int constant */
#define TOK_CLLONG    0xc9 /* long long constant */
#define TOK_CULLONG   0xca /* unsigned long long constant */
#define TOK_ARROW     0xcb
#define TOK_DOTS      0xcc /* three dots */
#define TOK_SHR       0xcd /* unsigned shift right */
#define TOK_PPNUM     0xce /* preprocessor number */
#define TOK_NOSUBST   0xcf /* means following token has already been pp'd */

#define TOK_SHL 0x01 /* shift left */
#define TOK_SAR 0x02 /* signed shift right */

/* assignement operators : normal operator or 0x80 */
#define TOK_A_MOD 0xa5
#define TOK_A_AND 0xa6
#define TOK_A_MUL 0xaa
#define TOK_A_ADD 0xab
#define TOK_A_SUB 0xad
#define TOK_A_DIV 0xaf
#define TOK_A_XOR 0xde
#define TOK_A_OR  0xfc
#define TOK_A_SHL 0x81
#define TOK_A_SAR 0x82

/* Special kinds of tokens */
#define TOK_EOF      (-1) /* end of file */
#define TOK_LINEFEED 10 /* line feed */

/* all identificators and strings have token above that */
#define TOK_IDENT 256
