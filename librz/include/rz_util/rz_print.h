#ifndef RZ_PRINT_H
#define RZ_PRINT_H

#include "rz_types.h"
#include "rz_cons.h"
#include "rz_bind.h"
#include "rz_io.h"
#include "rz_reg.h"

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
#define RZ_PRINT_FLAGS_RAINBOW  0x00004000
#define RZ_PRINT_FLAGS_HDROFF   0x00008000
#define RZ_PRINT_FLAGS_STYLE    0x00010000
#define RZ_PRINT_FLAGS_NONASCII 0x00020000
#define RZ_PRINT_FLAGS_ALIGN    0x00040000
#define RZ_PRINT_FLAGS_UNALLOC  0x00080000
#define RZ_PRINT_FLAGS_BGFILL   0x00100000
#define RZ_PRINT_FLAGS_SECTION  0x00200000

typedef int (*RzPrintZoomCallback)(void *user, int mode, ut64 addr, ut8 *bufz, ut64 size);
typedef const char *(*RzPrintNameCallback)(void *user, ut64 addr);
typedef int (*RzPrintSizeCallback)(void *user, ut64 addr);
typedef char *(*RzPrintCommentCallback)(void *user, ut64 addr);
typedef const char *(*RzPrintSectionGet)(void *user, ut64 addr);
typedef const char *(*RzPrintColorFor)(void *user, ut64 addr, bool verbose);
typedef char *(*RzPrintHasRefs)(void *user, ut64 addr, int mode);

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
	PrintfCallback cb_eprintf;
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
	Sdb *formats;
	Sdb *sdb_types;
	RzCons *cons;
	RzConsBind consbind;
	RNum *num;
	RzReg *reg;
	RzRegItem *(*get_register)(RzReg *reg, const char *name, int type);
	ut64 (*get_register_value)(RzReg *reg, RzRegItem *item);
	bool (*exists_var)(struct rz_print_t *print, ut64 func_addr, char *str);
	bool esc_bslash;
	bool wide_offsets;
	const char *strconv_mode;
	RzList *vars;
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
} RzPrint;

#ifdef RZ_API

/* RzConsBreak handlers */
typedef bool (*RzPrintIsInterruptedCallback)();

RZ_API bool rz_print_is_interrupted(void);
RZ_API void rz_print_set_is_interrupted_cb(RzPrintIsInterruptedCallback cb);

/* ... */
RZ_API char *rz_print_hexpair(RzPrint *p, const char *str, int idx);
RZ_API void rz_print_hex_from_bin(RzPrint *p, char *bin_str);
RZ_API RzPrint *rz_print_new(void);
RZ_API RzPrint *rz_print_free(RzPrint *p);
RZ_API bool rz_print_mute(RzPrint *p, int x);
RZ_API void rz_print_set_flags(RzPrint *p, int _flags);
RZ_API void rz_print_unset_flags(RzPrint *p, int flags);
RZ_API void rz_print_addr(RzPrint *p, ut64 addr);
RZ_API void rz_print_section(RzPrint *p, ut64 at);
RZ_API void rz_print_columns(RzPrint *p, const ut8 *buf, int len, int height);
RZ_API void rz_print_hexii(RzPrint *p, ut64 addr, const ut8 *buf, int len, int step);
RZ_API void rz_print_hexdump(RzPrint *p, ut64 addr, const ut8 *buf, int len, int base, int step, size_t zoomsz);
RZ_API void rz_print_hexdump_simple(const ut8 *buf, int len);
RZ_API int rz_print_jsondump(RzPrint *p, const ut8 *buf, int len, int wordsize);
RZ_API void rz_print_hexpairs(RzPrint *p, ut64 addr, const ut8 *buf, int len);
RZ_API void rz_print_hexdiff(RzPrint *p, ut64 aa, const ut8 *a, ut64 ba, const ut8 *b, int len, int scndcol);
RZ_API void rz_print_bytes(RzPrint *p, const ut8 *buf, int len, const char *fmt);
RZ_API void rz_print_fill(RzPrint *p, const ut8 *arr, int size, ut64 addr, int step);
RZ_API void rz_print_byte(RzPrint *p, const char *fmt, int idx, ut8 ch);
RZ_API const char *rz_print_byte_color(RzPrint *p, int ch);
RZ_API void rz_print_c(RzPrint *p, const ut8 *str, int len);
RZ_API void rz_print_raw(RzPrint *p, ut64 addr, const ut8 *buf, int len);
RZ_API bool rz_print_have_cursor(RzPrint *p, int cur, int len);
RZ_API bool rz_print_cursor_pointer(RzPrint *p, int cur, int len);
RZ_API void rz_print_cursor(RzPrint *p, int cur, int len, int set);
RZ_API void rz_print_cursor_range(RzPrint *p, int cur, int to, int set);
RZ_API int rz_print_get_cursor(RzPrint *p);
RZ_API void rz_print_set_cursor(RzPrint *p, int curset, int ocursor, int cursor);
RZ_API void rz_print_code(RzPrint *p, ut64 addr, const ut8 *buf, int len, char lang);
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
RZ_API int rz_print_format_struct_size(RzPrint *p, const char *format, int mode, int n);
RZ_API int rz_print_format(RzPrint *p, ut64 seek, const ut8 *buf, const int len, const char *fmt, int elem, const char *setval, char *field);
RZ_API const char *rz_print_format_byname(RzPrint *p, const char *name);
RZ_API void rz_print_offset(RzPrint *p, ut64 off, int invert, int opt, int dec, int delta, const char *label);
RZ_API void rz_print_offset_sg(RzPrint *p, ut64 off, int invert, int offseg, int seggrn, int offdec, int delta, const char *label);
#define RZ_PRINT_STRING_WIDE      1
#define RZ_PRINT_STRING_ZEROEND   2
#define RZ_PRINT_STRING_URLENCODE 4
#define RZ_PRINT_STRING_WRAP      8
#define RZ_PRINT_STRING_WIDE32    16
#define RZ_PRINT_STRING_ESC_NL    32
RZ_API int rz_print_string(RzPrint *p, ut64 seek, const ut8 *str, int len, int options);
RZ_API int rz_print_date_dos(RzPrint *p, const ut8 *buf, int len);
RZ_API int rz_print_date_hfs(RzPrint *p, const ut8 *buf, int len);
RZ_API int rz_print_date_w32(RzPrint *p, const ut8 *buf, int len);
RZ_API int rz_print_date_unix(RzPrint *p, const ut8 *buf, int len);
RZ_API int rz_print_date_get_now(RzPrint *p, char *str);
RZ_API void rz_print_zoom(RzPrint *p, void *user, RzPrintZoomCallback cb, ut64 from, ut64 to, int len, int maxlen);
RZ_API void rz_print_zoom_buf(RzPrint *p, void *user, RzPrintZoomCallback cb, ut64 from, ut64 to, int len, int maxlen);
RZ_API void rz_print_progressbar(RzPrint *pr, int pc, int _cols);
RZ_API void rz_print_portionbar(RzPrint *p, const ut64 *portions, int n_portions);
RZ_API void rz_print_rangebar(RzPrint *p, ut64 startA, ut64 endA, ut64 min, ut64 max, int cols);
RZ_API char *rz_print_randomart(const ut8 *dgst_raw, ut32 dgst_raw_len, ut64 addr);
RZ_API void rz_print_2bpp_row(RzPrint *p, ut8 *buf);
RZ_API void rz_print_2bpp_tiles(RzPrint *p, ut8 *buf, ut32 tiles);
RZ_API char *rz_print_colorize_opcode(RzPrint *print, char *p, const char *reg, const char *num, bool partial_reset, ut64 func_addr);
RZ_API const char *rz_print_color_op_type(RzPrint *p, ut32 analysis_type);
RZ_API void rz_print_set_interrupted(int i);
RZ_API void rz_print_init_rowoffsets(RzPrint *p);
RZ_API ut32 rz_print_rowoff(RzPrint *p, int i);
RZ_API void rz_print_set_rowoff(RzPrint *p, int i, ut32 offset, bool overwrite);
RZ_API int rz_print_row_at_off(RzPrint *p, ut32 offset);
RZ_API int rz_print_pie(RzPrint *p, ut64 *values, int nvalues, int size);

RZ_API const char *rz_print_rowlog(RzPrint *print, const char *str);
RZ_API void rz_print_rowlog_done(RzPrint *print, const char *str);

// WIP
RZ_API int rz_print_unpack7bit(const char *src, char *dest);
RZ_API int rz_print_pack7bit(const char *src, char *dest);
RZ_API void rz_print_set_screenbounds(RzPrint *p, ut64 addr);
RZ_API int rz_util_lines_getline(ut64 *lines_cache, int lines_cache_sz, ut64 off);
RZ_API char *rz_print_json_indent(const char *s, bool color, const char *tab, const char **colors);
RZ_API char *rz_print_json_human(const char *s);
RZ_API char *rz_print_json_path(const char *s, int pos);

#endif

#ifdef __cplusplus
}
#endif

#endif
