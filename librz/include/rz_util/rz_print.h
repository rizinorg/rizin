#ifndef RZ_PRINT_H
#define RZ_PRINT_H

#include "rz_types.h"
#include "rz_cons.h"
#include "rz_bind.h"
#include "rz_io.h"
#include "rz_reg.h"
#include <rz_util/rz_strbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RZ_PRINT_FLAGS_COLOR    0x00000001
#define RZ_PRINT_FLAGS_ADDRMOD  0x00000002
#define RZ_PRINT_FLAGS_CURSOR   0x00000004
#define RZ_PRINT_FLAGS_HEADER   0x00000008
#define RZ_PRINT_FLAGS_SPARSE   0x00000010
#define RZ_PRINT_FLAGS_SEGOFF   0x00000020
#define RZ_PRINT_FLAGS_OFFSET   0x00000040
#define RZ_PRINT_FLAGS_REFS     0x00000080
#define RZ_PRINT_FLAGS_DIFFOUT  0x00000100 /* only show different rows in `cc` hexdiffing */
#define RZ_PRINT_FLAGS_ADDRDEC  0x00000200
#define RZ_PRINT_FLAGS_COMMENT  0x00000400
#define RZ_PRINT_FLAGS_COMPACT  0x00000800
#define RZ_PRINT_FLAGS_NONHEX   0x00001000
#define RZ_PRINT_FLAGS_SECSUB   0x00002000
#define RZ_PRINT_FLAGS_HDROFF   0x00008000
#define RZ_PRINT_FLAGS_STYLE    0x00010000
#define RZ_PRINT_FLAGS_NONASCII 0x00020000
#define RZ_PRINT_FLAGS_ALIGN    0x00040000
#define RZ_PRINT_FLAGS_UNALLOC  0x00080000
#define RZ_PRINT_FLAGS_BGFILL   0x00100000
#define RZ_PRINT_FLAGS_SECTION  0x00200000

typedef const char *(*RzPrintNameCallback)(void *user, ut64 addr);
typedef int (*RzPrintSizeCallback)(void *user, ut64 addr);
typedef char *(*RzPrintCommentCallback)(void *user, ut64 addr);
typedef const char *(*RzPrintSectionGet)(void *user, ut64 addr);
typedef const char *(*RzPrintColorFor)(void *user, ut64 addr, bool verbose);
typedef char *(*RzPrintHasRefs)(void *user, ut64 addr, int mode);

typedef enum {
	RZ_ASM_TOKEN_UNKNOWN = 0, ///< Does not fit to any token below.
	RZ_ASM_TOKEN_MNEMONIC, ///< Asm mnemonics like: mov, push, lea...
	RZ_ASM_TOKEN_OPERATOR, ///< Arithmetic operators: +,-,<< etc.
	RZ_ASM_TOKEN_NUMBER, ///< Numbers
	RZ_ASM_TOKEN_REGISTER, ///< Registers
	RZ_ASM_TOKEN_SEPARATOR, ///< Brackets, comma etc.
	RZ_ASM_TOKEN_META, ///< Meta information (e.g Hexagon packet prefix, ARM & Hexagon number prefix).

	RZ_ASM_TOKEN_LAST,
} RzAsmTokenType;

/**
 *  \brief A token of an asm string holding meta data.
 */
typedef struct {
	size_t start; ///< byte-offset into `str` where this token starts. Must be exactly at a utf-8 codepoint boundary.
	size_t len; ///< `str` length of token in bytes.
	RzAsmTokenType type;
	union {
		ut64 number; ///< Number of RZ_ASM_TOKEN_NUMBER
	} val;
} RzAsmToken;

/**
 * \brief A tokenized asm string.
 */
typedef struct {
	ut32 op_type; ///< RzAnalysisOpType. Mnemonic color depends on this.
	RzStrBuf *str; ///< Contains the raw asm string
	RzVector /*<RzAsmToken>*/ *tokens; ///< Contains only the tokenization meta-info without strings, ordered by start for log2(n) access
} RzAsmTokenString;

typedef struct {
	const RzRegSet *reg_sets; ///< Array of reg sets used to lookup register names during parsing.
	ut32 ana_op_type; ///< Analysis op type (see: _RzAnalysisOpType) of the token string to parse.
} RzAsmParseParam;

/**
 * \brief Pattern for a asm string token.
 */
typedef struct {
	RzAsmTokenType type; ///< Asm token type.
	char *pattern; ///< The regex pattern describing the tokens.
	RzRegex *regex; ///< Compiled regex pattern.
} RzAsmTokenPattern;

/**
 * \brief Holds certain options to alter the colorizing of asm strings.
 *
 */
typedef struct {
	bool reset_bg; ///< Reset the background color?
	ut64 hl_addr; ///< Address which should be highlighted. Usually the function address.
} RzPrintAsmColorOpts;

typedef struct rz_print_zoom_t {
	ut8 *buf;
	ut64 from;
	ut64 to;
	int size;
	int mode;
} RzPrintZoom;

typedef struct rz_print_t {
	void *user;
	RzIOBind iob;
	bool pava;
	RzCoreBind coreb;
	const char *cfmt;
	char datefmt[32];
	int datezone;
	int (*write)(const unsigned char *buf, int len);
	PrintfCallback cb_printf;
	char *(*cb_color)(int idx, int last, bool bg);
	bool scr_prompt;
	int (*disasm)(void *p, ut64 addr);
	PrintfCallback oprintf;
	int big_endian;
	int width;
	int limit;
	int bits;
	bool histblock;
	// true if the cursor is enabled, false otherwise
	bool cur_enabled;
	// offset of the selected byte from the first displayed one
	int cur;
	// offset of the selected byte from the first displayed one, when a
	// range of bytes is selected. -1 is used if no bytes are selected.
	int ocur;
	int cols;
	int flags;
	int seggrn;
	bool use_comments;
	int addrmod;
	int col;
	int stride;
	int bytespace;
	int pairs;
	bool resetbg;
	RzPrintZoom *zoom;
	RzPrintNameCallback offname;
	RzPrintSizeCallback offsize;
	RzPrintColorFor colorfor;
	RzPrintHasRefs hasrefs;
	RzPrintCommentCallback get_comments;
	RzPrintSectionGet get_section_name;
	Sdb *sdb_types;
	RzCons *cons;
	RzConsBind consbind;
	RzNum *num;
	RzReg *reg;
	RzRegItem *(*get_register)(RzReg *reg, const char *name, int type);
	ut64 (*get_register_value)(RzReg *reg, RzRegItem *item);
	bool (*exists_var)(struct rz_print_t *print, ut64 func_addr, char *str);
	bool esc_bslash;
	bool wide_offsets;
	const char *strconv_mode;
	char io_unalloc_ch;
	bool show_offset;

	// when true it uses row_offsets
	bool calc_row_offsets;
	// offset of the first byte of each printed row.
	// Last elements is marked with a UT32_MAX.
	ut32 *row_offsets;
	// size of row_offsets
	int row_offsets_sz;
	// when true it makes visual mode flush the buffer to screen
	bool vflush;
	// represents the first not-visible offset on the screen
	// (only when in visual disasm mode)
	ut64 screen_bounds;
	// Memoized current row number to calculate screen_bounds
	int rows;
	RzPrintAsmColorOpts colorize_opts; ///< Coloize options for asm strings.
} RzPrint;

#ifdef RZ_API

/* RzConsBreak handlers */
typedef bool (*RzPrintIsInterruptedCallback)();

RZ_API bool rz_print_is_interrupted(void);
RZ_API void rz_print_set_is_interrupted_cb(RzPrintIsInterruptedCallback cb);

/* ... */
RZ_API char *rz_print_hexpair(RzPrint *p, const char *str, int idx);
RZ_API RzPrint *rz_print_new(void);
RZ_API RzPrint *rz_print_free(RzPrint *p);
RZ_API void rz_print_set_flags(RzPrint *p, int _flags);
RZ_API void rz_print_addr(RzPrint *p, ut64 addr);
RZ_API char *rz_print_section_str(RzPrint *p, ut64 at);
RZ_API void rz_print_hexii(RzPrint *p, ut64 addr, const ut8 *buf, int len, int step);
RZ_API RZ_OWN char *rz_print_hexdump_str(RZ_NONNULL RzPrint *p, ut64 addr, RZ_NONNULL const ut8 *buf, int len, int base, int step, size_t zoomsz);
RZ_API RZ_OWN char *rz_print_jsondump_str(RZ_NONNULL RzPrint *p, RZ_NONNULL const ut8 *buf, int len, int wordsize);
RZ_API RZ_OWN char *rz_print_hexdiff_str(RZ_NONNULL RzPrint *p, ut64 aa, RZ_NONNULL const ut8 *_a, ut64 ba, RZ_NONNULL const ut8 *_b, int len, int scndcol);
RZ_API void rz_print_bytes(RzPrint *p, const ut8 *buf, int len, const char *fmt);
RZ_API void rz_print_byte(RzPrint *p, const char *fmt, int idx, ut8 ch);
RZ_API const char *rz_print_byte_color(RzPrint *p, int ch);
RZ_API void rz_print_raw(RzPrint *p, ut64 addr, const ut8 *buf, int len);
RZ_API bool rz_print_have_cursor(RzPrint *p, int cur, int len);
RZ_API bool rz_print_cursor_pointer(RzPrint *p, int cur, int len);
RZ_API int rz_print_get_cursor(RzPrint *p);
RZ_API void rz_print_set_cursor(RzPrint *p, int curset, int ocursor, int cursor);
#define SEEFLAG    -2
#define JSONOUTPUT -3

/* mode values for rz_print_format_* API */
#define RZ_PRINT_MUSTSEE   (1) // enable printing of data in specified fmt
#define RZ_PRINT_ISFIELD   (1 << 1)
#define RZ_PRINT_SEEFLAGS  (1 << 2)
#define RZ_PRINT_JSON      (1 << 3)
#define RZ_PRINT_MUSTSET   (1 << 4)
#define RZ_PRINT_UNIONMODE (1 << 5)
#define RZ_PRINT_VALUE     (1 << 6)
#define RZ_PRINT_DOT       (1 << 7)
#define RZ_PRINT_QUIET     (1 << 8)
#define RZ_PRINT_STRUCT    (1 << 9)

RZ_API void rz_print_offset(RzPrint *p, ut64 off, int invert, int opt, int dec, int delta, const char *label);
RZ_API void rz_print_offset_sg(RzPrint *p, ut64 off, int invert, int offseg, int seggrn, int offdec, int delta, const char *label);
RZ_API const char *rz_print_color_op_type(RZ_NONNULL RzPrint *p, ut32 /* RzAnalaysisOpType */ analysis_type);
RZ_API void rz_print_init_rowoffsets(RzPrint *p);
RZ_API ut32 rz_print_rowoff(RzPrint *p, int i);
RZ_API void rz_print_set_rowoff(RzPrint *p, int i, ut32 offset, bool overwrite);
RZ_API int rz_print_row_at_off(RzPrint *p, ut32 offset);

// WIP
RZ_API void rz_print_set_screenbounds(RzPrint *p, ut64 addr);
RZ_API char *rz_print_json_indent(const char *s, bool color, const char *tab, const char **colors);
RZ_API char *rz_print_json_human(const char *s);
RZ_API char *rz_print_json_path(const char *s, int pos);

RZ_API RZ_OWN RzStrBuf *rz_print_colorize_asm_str(RZ_BORROW RzPrint *p, const RzAsmTokenString *toks);
RZ_API void rz_print_colored_help_option(const char *option, const char *arg, const char *description, size_t maxOptionAndArgLength);
#endif

#ifdef __cplusplus
}
#endif

#endif
