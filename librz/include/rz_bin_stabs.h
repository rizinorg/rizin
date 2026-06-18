// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BIN_STABS_H
#define RZ_BIN_STABS_H

#include <rz_types.h>
#include <rz_vector.h>
#include <rz_type.h>
#include <rz_bin_source_line.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file rz_bin_stabs.h
 * \brief Parser for the STABS debugging information format.
 *
 * STABS (symbol table strings) is the legacy debug format emitted by old
 * toolchains (and by GCC up to version 12 with -gstabs). The information is
 * stored as an array of fixed 12-byte records in the `.stab` section, with the
 * strings kept in the separate `.stabstr` section.
 *
 * See https://sourceware.org/gdb/onlinedocs/stabs.html for the format details.
 */

/**
 * \brief STABS symbol descriptor types (the on-disk `n_type` field).
 *
 * The values are fixed by the format.
 * See https://sourceware.org/gdb/onlinedocs/stabs.html for details.
 */
typedef enum {
	RZ_BIN_STABS_N_UNDF = 0x00, ///< Header record (and undefined entries)
	RZ_BIN_STABS_N_GSYM = 0x20, ///< Global symbol
	RZ_BIN_STABS_N_FNAME = 0x22, ///< Function name (BSD Fortran)
	RZ_BIN_STABS_N_FUN = 0x24, ///< Function
	RZ_BIN_STABS_N_STSYM = 0x26, ///< Static symbol (data segment)
	RZ_BIN_STABS_N_LCSYM = 0x28, ///< Static symbol (bss segment)
	RZ_BIN_STABS_N_MAIN = 0x2a, ///< Name of main routine
	RZ_BIN_STABS_N_OPT = 0x3c, ///< Compiler options marker
	RZ_BIN_STABS_N_RSYM = 0x40, ///< Register variable
	RZ_BIN_STABS_N_SLINE = 0x44, ///< Source line number in the text segment
	RZ_BIN_STABS_N_DSLINE = 0x46, ///< Source line number in the data segment
	RZ_BIN_STABS_N_BSLINE = 0x48, ///< Source line number in the bss segment
	RZ_BIN_STABS_N_SO = 0x64, ///< Source file name
	RZ_BIN_STABS_N_LSYM = 0x80, ///< Local symbol or type definition
	RZ_BIN_STABS_N_BINCL = 0x82, ///< Beginning of an include file
	RZ_BIN_STABS_N_SOL = 0x84, ///< Name of an included source file
	RZ_BIN_STABS_N_PSYM = 0xa0, ///< Function parameter
	RZ_BIN_STABS_N_EINCL = 0xa2, ///< End of an include file
	RZ_BIN_STABS_N_LBRAC = 0xc0, ///< Beginning of a lexical block (scope)
	RZ_BIN_STABS_N_EXCL = 0xc2, ///< Placeholder for a deleted include file
	RZ_BIN_STABS_N_RBRAC = 0xe0, ///< End of a lexical block (scope)
} RzBinStabsType;

/** Size in bytes of a single on-disk STABS record. */
#define RZ_BIN_STABS_RECORD_SIZE 12

/**
 * \brief A single decoded STABS record.
 *
 * On disk every record is a fixed 12-byte little/big-endian structure laid out
 * as `strx` (4 bytes), `type` (1 byte), `other` (1 byte), `desc` (2 bytes) and
 * `value` (4 bytes). The fields are independent; the values below are the
 * already decoded fields.
 */
typedef struct rz_bin_stabs_entry_t {
	ut32 strx; ///< Offset of the associated string inside the current unit's string table slice
	RzBinStabsType type; ///< Symbol descriptor type
	ut8 other; ///< Reserved field, usually zero
	ut16 desc; ///< Description field, e.g. the line number for N_SLINE records
	ut64 value; ///< An address, a function-relative offset or, for an N_UNDF header, the byte size of the unit's string table slice
	RZ_NULLABLE const char *string; ///< The resolved string, borrowed from RzBinStabs.str (may be NULL)
} RzBinStabsEntry;

/**
 * \brief All STABS information parsed out of a binary.
 */
typedef struct rz_bin_stabs_t {
	RzVector /*<RzBinStabsEntry>*/ entries; ///< The decoded records, in file order
	char *str; ///< Copy of the `.stabstr` string table
	ut64 str_size; ///< Size of the string table in bytes
	bool big_endian; ///< Endianness used to decode the records
} RzBinStabs;

/**
 * \brief The kind of program object a STABS symbol describes.
 */
typedef enum {
	RZ_BIN_STABS_SYMBOL_FUNCTION, ///< A function (descriptor 'F' or 'f')
	RZ_BIN_STABS_SYMBOL_GLOBAL, ///< A global variable (descriptor 'G')
	RZ_BIN_STABS_SYMBOL_STATIC, ///< A static variable (descriptor 'S'/'V', or N_LCSYM)
	RZ_BIN_STABS_SYMBOL_PARAMETER, ///< A function parameter (descriptor 'p'/'P')
	RZ_BIN_STABS_SYMBOL_LOCAL, ///< A function local variable
} RzBinStabsSymbolKind;

/**
 * \brief A symbol (function, variable or parameter) recovered from STABS.
 */
typedef struct rz_bin_stabs_symbol_t {
	char *name; ///< Symbol name
	RzBinStabsSymbolKind kind; ///< What the symbol describes
	RZ_NULLABLE RzType *type; ///< Resolved type, owned by this symbol (may be NULL)
	ut64 value; ///< Absolute address for functions/globals/statics, frame offset for parameters/locals
	ut64 function; ///< For parameters and locals: address of the enclosing function
} RzBinStabsSymbol;

/**
 * \brief All higher level debug information recovered from STABS.
 *
 * The types and the function signatures are registered directly into the
 * RzTypeDB passed to rz_bin_stabs_debug_info(). The remaining symbols
 * (functions, globals, statics, parameters and locals) are returned here so the
 * caller can turn them into analysis objects.
 */
typedef struct rz_bin_stabs_debug_info_t {
	RzPVector /*<RzBinStabsSymbol *>*/ symbols; ///< Recovered symbols
} RzBinStabsDebugInfo;

struct rz_bin_file_t;

RZ_API RZ_OWN RzBinStabs *rz_bin_stabs_parse(RZ_NONNULL struct rz_bin_file_t *bf);
RZ_API void rz_bin_stabs_free(RZ_NULLABLE RzBinStabs *stabs);
RZ_API RZ_OWN RzBinSourceLineInfo *rz_bin_stabs_source_line_info(RZ_NONNULL const RzBinStabs *stabs);
RZ_API RZ_OWN RzBinStabsDebugInfo *rz_bin_stabs_debug_info(RZ_NONNULL const RzBinStabs *stabs, RZ_NONNULL RzTypeDB *typedb);
RZ_API void rz_bin_stabs_debug_info_free(RZ_NULLABLE RzBinStabsDebugInfo *di);

#ifdef __cplusplus
}
#endif

#endif
