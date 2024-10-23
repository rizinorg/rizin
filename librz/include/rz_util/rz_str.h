#ifndef RZ_STR_H
#define RZ_STR_H

#include <wchar.h>
#include "rz_str_util.h"
#include "rz_list.h"
#include "rz_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	RZ_STRING_TYPE_RAW, ///< The raw sequence of bytes without any marker of beginning or end
	RZ_STRING_TYPE_ZERO, ///< C-style strings (ASCII or UTF-8) with zero as the end marker
	RZ_STRING_TYPE_SIZED, ///< Pascal-style strings with the first byte marking the size of the string
} RzStrType;

typedef enum {
	RZ_STRING_ENC_8BIT = 'b', // unknown 8bit encoding but with ASCII from 0 to 0x7f
	RZ_STRING_ENC_UTF8 = '8',
	RZ_STRING_ENC_MUTF8 = 'm', // modified utf8
	RZ_STRING_ENC_UTF16LE = 'u',
	RZ_STRING_ENC_UTF32LE = 'U',
	RZ_STRING_ENC_UTF16BE = 'n',
	RZ_STRING_ENC_UTF32BE = 'N',
	RZ_STRING_ENC_BASE64 = '6',
	RZ_STRING_ENC_IBM037 = 'c',
	RZ_STRING_ENC_IBM290 = 'd',
	RZ_STRING_ENC_EBCDIC_UK = 'k',
	RZ_STRING_ENC_EBCDIC_US = 's',
	RZ_STRING_ENC_EBCDIC_ES = 't',
	RZ_STRING_ENC_GUESS = 'g',
} RzStrEnc;

/**
 * \brief Group together some common options used by string escaping functions
 */
typedef struct {
	bool show_asciidot; ///< When true, dots `.` are placed instead of unprintable characters
	bool esc_bslash; ///< When true, backslashes `\` are quoted with `\\`
	bool esc_double_quotes; ///< When true, double quotes `"` are quoted with `\"`
	bool dot_nl; ///< When true, \n is converted into the graphiz-compatible newline \l
} RzStrEscOptions;

/**
 * \brief Convenience macro for local temporary strings
 * \param buf Target buffer, **must** be an array type, not a pointer.
 *
 * This eases the common pattern where a stack-allocated string of a fixed
 * size is created and filled with `snprintf()` to be used as a temporary string.
 *
 * Example:
 *
 *     char k[32];
 *     char v[32];
 *     sdb_set(db, rz_strf(k, "key.%d", 42), rz_strf(v, "val.%d", 123));
 */
#define rz_strf(buf, ...) ( \
	snprintf(buf, sizeof(buf), __VA_ARGS__) < 0 \
	? rz_assert_log(RZ_LOGLVL_FATAL, "rz_strf error while using snprintf"), \
	NULL \
	: buf)

typedef int (*RzStrRangeCallback)(void *, int);

#define RZ_STR_ISEMPTY(x)    (!(x) || !*(x))
#define RZ_STR_ISNOTEMPTY(x) ((x) && *(x))
#define RZ_STR_DUP(x)        ((x) ? strdup((x)) : NULL)
#define RZ_STR_EQ(x, y)      (rz_str_cmp((x), (y), -1) == 0)
#define RZ_STR_NE(x, y)      (rz_str_cmp((x), (y), -1) != 0)
#define rz_str_array(x, y)   ((y >= 0 && y < (sizeof(x) / sizeof(*x))) ? x[y] : "")
RZ_API const char *rz_str_enc_as_string(RzStrEnc enc);
RZ_API RzStrEnc rz_str_enc_string_as_type(RZ_NULLABLE const char *enc);
RZ_API RZ_OWN char *rz_str_repeat(const char *str, ut16 times);
RZ_API RZ_OWN char *rz_str_pad(const char ch, int len);
RZ_API const char *rz_str_rstr(const char *base, const char *p);
RZ_API const char *rz_strstr_ansi(RZ_NONNULL const char *a, RZ_NONNULL const char *b, bool icase);
RZ_API const char *rz_str_rchr(const char *base, const char *p, int ch);
RZ_API const char *rz_str_closer_chr(const char *b, const char *s);
RZ_API int rz_str_bounds(const char *str, int *h);
RZ_API char *rz_str_crop(const char *str, unsigned int x, unsigned int y, unsigned int x2, unsigned int y2);
RZ_API char *rz_str_scale(const char *r, int w, int h);
RZ_API bool rz_str_range_in(const char *r, ut64 addr);
RZ_API size_t rz_str_len_utf8(const char *s);
RZ_API size_t rz_str_len_utf8_ansi(const char *str);
RZ_API size_t rz_str_len_utf8char(const char *s, int left);
RZ_API size_t rz_str_utf8_charsize(const char *str);
RZ_API size_t rz_str_utf8_charsize_prev(const char *str, int prev_len);
RZ_API size_t rz_str_utf8_charsize_last(const char *str);
RZ_API void rz_str_filter_zeroline(char *str, int len);
RZ_API size_t rz_str_utf8_codepoint(const char *s, size_t left);
RZ_API bool rz_str_char_fullwidth(const char *s, size_t left);
RZ_API int rz_str_write(int fd, const char *b);
RZ_API size_t rz_str_ncpy(char *dst, const char *src, size_t n);
RZ_API void rz_str_sanitize(char *c);
RZ_API char *rz_str_sanitize_sdb_key(const char *s);
RZ_API const char *rz_str_casestr(const char *a, const char *b);
RZ_API const char *rz_str_firstbut(const char *s, char ch, const char *but);
RZ_API const char *rz_str_lastbut(const char *s, char ch, const char *but);
RZ_API size_t rz_str_split(char *str, char ch);
RZ_API RzList /*<char *>*/ *rz_str_split_list(char *str, const char *c, int n);
RZ_API RZ_OWN RzList /*<char *>*/ *rz_str_split_list_regex(RZ_NONNULL char *str, RZ_NONNULL const char *r, int n);
RZ_API RzList /*<char *>*/ *rz_str_split_duplist(const char *str, const char *c, bool trim);
RZ_API RzList /*<char *>*/ *rz_str_split_duplist_n(const char *str, const char *c, int n, bool trim);
RZ_API RZ_OWN RzList /*<char *>*/ *rz_str_split_duplist_n_regex(RZ_NONNULL const char *_str, RZ_NONNULL const char *r, int n, bool trim);
RZ_API size_t *rz_str_split_lines(char *str, size_t *count);
RZ_API RZ_OWN char *rz_str_replace(RZ_OWN char *str, const char *key, const char *val, int g);
RZ_API char *rz_str_replace_icase(char *str, const char *key, const char *val, int g, int keep_case);
RZ_API char *rz_str_replace_in(char *str, ut32 sz, const char *key, const char *val, int g);
#define rz_str_cpy(x, y) memmove((x), (y), strlen(y) + 1);
#define rz_str_cat(x, y) memmove((x) + strlen(x), (y), strlen(y) + 1);
RZ_API int rz_str_bits(char *strout, const ut8 *buf, int len, const char *bitz);
RZ_API int rz_str_bits64(char *strout, ut64 in);
RZ_API ut64 rz_str_bits_from_string(const char *buf, const char *bitz);
RZ_API int rz_str_rwx(const char *str);
RZ_API int rz_str_replace_ch(char *s, char a, char b, bool g);
RZ_API int rz_str_replace_char(char *s, int a, int b);
RZ_API int rz_str_replace_char_once(char *s, int a, int b);
RZ_API void rz_str_remove_char(char *str, char c);
RZ_API const char *rz_str_rwx_i(int rwx);
RZ_API int rz_str_fmtargs(const char *fmt);
RZ_API char *rz_str_arg_escape(const char *arg);
RZ_API int rz_str_arg_unescape(char *arg);
RZ_API char **rz_str_argv(const char *str, int *_argc);
RZ_API void rz_str_argv_free(char **argv);
RZ_API int rz_snprintf(char *string, int len, const char *fmt, ...) RZ_PRINTF_CHECK(3, 4);
RZ_API bool rz_str_is_whitespace(RZ_NONNULL const char *str);
RZ_API bool rz_str_is_ascii(const char *str);
RZ_API bool rz_str_is_utf8(RZ_NONNULL const char *str);
RZ_API char *rz_str_nextword(char *s, char ch);
RZ_API bool rz_str_is_printable(const char *str);
RZ_API bool rz_str_is_printable_limited(const char *str, int size);
RZ_API bool rz_str_is_printable_incl_newlines(const char *str);
RZ_API char *rz_str_appendlen(char *ptr, const char *string, int slen);
RZ_API char *rz_str_newf(const char *fmt, ...) RZ_PRINTF_CHECK(1, 2);
RZ_API char *rz_str_newlen(const char *str, int len);
RZ_API const char *rz_str_sysbits(const int v);
RZ_API char *rz_str_trunc_ellipsis(const char *str, int len);
RZ_API const char *rz_str_bool(int b);
RZ_API bool rz_str_is_true(const char *s);
RZ_API bool rz_str_is_false(const char *s);
RZ_API bool rz_str_is_bool(const char *val);
RZ_API const char *rz_str_ansi_chrn(const char *str, size_t n);
RZ_API size_t rz_str_ansi_len(const char *str);
RZ_API size_t rz_str_ansi_nlen(const char *str, size_t len);
RZ_API int rz_str_ansi_trim(char *str, int str_len, int n);
RZ_API int rz_str_ansi_filter(char *str, char **out, int **cposs, int len);
RZ_API char *rz_str_ansi_crop(const char *str, unsigned int x, unsigned int y, unsigned int x2, unsigned int y2);
RZ_API int rz_str_word_count(const char *string);
RZ_API int rz_str_char_count(const char *string, char ch);
RZ_API char *rz_str_word_get0set(char *stra, int stralen, int idx, const char *newstr, int *newlen);
RZ_API int rz_str_word_set0(char *str);
RZ_API int rz_str_word_set0_stack(char *str);
static inline const char *rz_str_word_get_next0(const char *str) {
	return str + strlen(str) + 1;
}
RZ_API const char *rz_str_word_get0(const char *str, int idx);
RZ_API RZ_OWN char *rz_str_skip_separator_chars(RZ_NONNULL const char *string);
RZ_API void rz_str_trim(RZ_NONNULL RZ_INOUT char *str);
RZ_API void rz_str_trim_char(RZ_NONNULL RZ_INOUT char *str, const char c);
RZ_API char *rz_str_trim_dup(const char *str);
RZ_API char *rz_str_trim_lines(char *str);
RZ_API void rz_str_trim_head(RZ_NONNULL RZ_INOUT char *str);
RZ_API void rz_str_trim_head_char(RZ_NONNULL RZ_INOUT char *str, const char c);
RZ_API const char *rz_str_trim_head_ro(RZ_NONNULL const char *str);
RZ_API const char *rz_str_trim_head_wp(RZ_NONNULL const char *str);
RZ_API RZ_BORROW char *rz_str_trim_tail(RZ_NONNULL char *str);
RZ_API void rz_str_trim_tail_char(RZ_NONNULL RZ_INOUT char *str, const char c);
RZ_API ut64 rz_str_djb2_hash(const char *str);
RZ_API char *rz_str_trim_nc(char *str);
RZ_API bool rz_str_is2utf8(RZ_NONNULL const char *c);
RZ_API bool rz_str_is3utf8(RZ_NONNULL const char *c);
RZ_API bool rz_str_is4utf8(RZ_NONNULL const char *c);
RZ_API bool rz_str_isXutf8(RZ_NONNULL const char *c, ut8 x);
RZ_API const char *rz_str_strchr(RZ_NONNULL const char *str, RZ_NONNULL const char *c);
RZ_API const char *rz_str_nstr(const char *from, const char *to, int size);
RZ_API const char *rz_str_case_nstr(RZ_NONNULL const char *from, RZ_NONNULL const char *to, int size);
RZ_API const char *rz_str_lchr(const char *str, char chr);
RZ_API const char *rz_sub_str_lchr(RZ_NONNULL const char *str, int start, int end, char chr);
RZ_API const char *rz_sub_str_rchr(RZ_NONNULL const char *str, int start, int end, char chr);
RZ_API RZ_OWN char *rz_sub_str_ptr(RZ_NONNULL const char *str, RZ_NONNULL const char *start, RZ_NONNULL const char *end);
RZ_API char *rz_str_ichr(char *str, char chr);
RZ_API bool rz_str_ccmp(const char *dst, const char *orig, int ch);
RZ_API bool rz_str_cmp_list(const char *list, const char *item, char sep);
RZ_API int rz_str_cmp(RZ_NULLABLE const char *dst, RZ_NULLABLE const char *orig, int len);
RZ_API int rz_str_casecmp(const char *dst, const char *orig);
RZ_API int rz_str_ncasecmp(const char *dst, const char *orig, size_t n);
RZ_API int rz_str_ccpy(char *dst, char *orig, int ch);
static inline const char *rz_str_get(const char *str) {
	return str ? str : "";
}
static inline const char *rz_str_get_null(const char *str) {
	return str ? str : "(null)";
}
RZ_API char *rz_str_ndup(RZ_NULLABLE const char *ptr, int len);
RZ_API RZ_OWN char *rz_str_dup(RZ_NULLABLE const char *str);
RZ_API int rz_str_delta(char *p, char a, char b);
RZ_API void rz_str_filter(char *str);
RZ_API const char *rz_str_tok(const char *str1, const char b, size_t len);
RZ_API const char *rz_str_str_xy(const char *s, const char *word, const char *prev, int *x, int *y);

typedef void (*str_operation)(char *c);

RZ_API int rz_str_do_until_token(str_operation op, char *str, const char tok);

RZ_API void rz_str_reverse(char *str);
RZ_API int rz_str_path_unescape(char *path);
RZ_API char *rz_str_path_escape(const char *path);
RZ_API int rz_str_unescape(char *buf);
RZ_API RZ_OWN char *rz_str_escape(RZ_NONNULL const char *buf);
RZ_API char *rz_str_escape_sh(const char *buf);
RZ_API char *rz_str_escape_dot(const char *buf);
RZ_API char *rz_str_escape_8bit(const char *buf, bool colors, RzStrEscOptions *opt);
RZ_API char *rz_str_escape_utf8(const char *buf, RzStrEscOptions *opt);
RZ_API char *rz_str_escape_utf8_keep_printable(const char *buf, RzStrEscOptions *opt); // like escape_utf8 but leaves valid \uXXXX chars directly in utf-8
RZ_API char *rz_str_escape_utf16le(const char *buf, int buf_size, RzStrEscOptions *opt);
RZ_API char *rz_str_escape_utf32le(const char *buf, int buf_size, RzStrEscOptions *opt);
RZ_API char *rz_str_escape_utf16be(const char *buf, int buf_size, RzStrEscOptions *opt);
RZ_API char *rz_str_escape_utf32be(const char *buf, int buf_size, RzStrEscOptions *opt);
RZ_API void rz_str_byte_escape(const char *p, char **dst, RzStrEscOptions *opt);
RZ_API char *rz_str_format_msvc_argv(size_t argc, const char **argv);
RZ_API void rz_str_uri_decode(char *buf);
RZ_API char *rz_str_uri_encode(const char *buf);
RZ_API char *rz_str_utf16_decode(const ut8 *s, int len);
RZ_API int rz_str_utf16_to_utf8(ut8 *dst, int len_dst, const ut8 *src, int len_src, bool little_endian);
RZ_API char *rz_str_utf16_encode(const char *s, int len);
RZ_API char *rz_str_escape_utf8_for_json(const char *s, int len);
RZ_API char *rz_str_escape_mutf8_for_json(const char *s, int len);
RZ_API char *rz_str_home(const char *str);
RZ_API size_t rz_str_nlen(const char *s, size_t n);
RZ_API size_t rz_str_nlen_w(const char *s, int n);
RZ_API size_t rz_wstr_clen(const char *s);
RZ_API char *rz_str_prepend(char *ptr, const char *string);
RZ_API char *rz_str_prefix_all(const char *s, const char *pfx);
RZ_API RZ_OWN char *rz_str_append(RZ_OWN RZ_NULLABLE char *ptr, const char *string);
RZ_API char *rz_str_append_owned(char *ptr, char *string);
RZ_API RZ_OWN char *rz_str_appendf(RZ_OWN RZ_NULLABLE char *ptr, const char *fmt, ...) RZ_PRINTF_CHECK(2, 3);
RZ_API char *rz_str_appendch(char *x, char y);
RZ_API void rz_str_case(char *str, bool up);
RZ_API void rz_str_trim_path(char *s);
RZ_API ut8 rz_str_contains_macro(const char *input_value);
RZ_API void rz_str_truncate_cmd(char *string);
RZ_API char *rz_str_replace_thunked(char *str, char *clean, int *thunk, int clen,
	const char *key, const char *val, int g);
RZ_API bool rz_str_glob(const char *str, const char *glob);
RZ_API int rz_str_binstr2bin(const char *str, ut8 *out, int outlen);
RZ_API char *rz_str_between(const char *str, const char *prefix, const char *suffix);
RZ_API bool rz_str_startswith(RZ_NONNULL const char *str, RZ_NONNULL const char *needle);
RZ_API bool rz_str_startswith_icase(RZ_NONNULL const char *str, RZ_NONNULL const char *needle);
RZ_API bool rz_str_endswith(RZ_NONNULL const char *str, RZ_NONNULL const char *needle);
RZ_API bool rz_str_endswith_icase(RZ_NONNULL const char *str, RZ_NONNULL const char *needle);
RZ_API bool rz_str_isnumber(const char *str);
RZ_API const char *rz_str_last(const char *in, const char *ch);
RZ_API char *rz_str_highlight(char *str, const char *word, const char *color, const char *color_reset);
RZ_API char *rz_str_from_ut64(ut64 val);
RZ_API void rz_str_stripLine(char *str, const char *key);
RZ_API char *rz_str_list_join(RzList /*<char *>*/ *str, const char *sep);
RZ_API char *rz_str_array_join(const char **a, size_t n, const char *sep);
RZ_API RzList /*<char *>*/ *rz_str_wrap(char *str, size_t width);

RZ_API const char *rz_str_sep(const char *base, const char *sep);
RZ_API const char *rz_str_rsep(const char *base, const char *p, const char *sep);

typedef struct rz_str_stringify_opt_t {
	const ut8 *buffer; ///< String buffer (cannot be NULL).
	ut32 length; ///< String buffer length.
	RzStrEnc encoding; ///< String encoding type (cannot be RZ_STRING_ENC_GUESS)
	ut32 wrap_at; ///< Adds a new line the output when it exeeds this value.
	bool escape_nl; ///< When enabled escapes new lines (\n).
	bool json; ///< Encodes the output as a JSON string.
	bool stop_at_nil; ///< When enabled stops printing when '\0' is found.
	bool urlencode; ///< Encodes the output following RFC 3986.
} RzStrStringifyOpt;

RZ_API RzStrEnc rz_str_guess_encoding_from_buffer(RZ_NONNULL const ut8 *buffer, ut32 length);
RZ_API RZ_OWN char *rz_str_stringify_raw_buffer(RzStrStringifyOpt *option, RZ_NULLABLE RZ_OUT ut32 *length);

RZ_API const char *rz_str_indent(int indent);

#ifdef __cplusplus
}
#endif

#endif // RZ_STR_H
