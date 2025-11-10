// SPDX-FileCopyrightText: 2023 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_REGEX_H
#define RZ_REGEX_H

#include <rz_util/rz_strbuf.h>
#include <rz_vector.h>
#include <rz_types.h>
#include <rz_list.h>
#include <sys/types.h>

#define RZ_REGEX_SIZE size_t

// Some basic PCRE2 macros. There are way more defined
// and should be added here if needed.
#define RZ_REGEX_ERROR_NOMATCH (-1) /* PCRE2_ERROR_NOMATCH */
#define RZ_REGEX_ERROR_PARTIAL (-2) /* PCRE2_ERROR_PARTIAL */

/**
 * \brief Regex compilation flags. They are only used for rz_regex_new()
 * C   alters what is compiled by rz_regex_new()
 * J   alters what is compiled by rz_regex_new() (with JIT enabled).
 * M   is inspected during rz_regex_match() execution
 * D   is inspected during pcre2_dfa_match() execution (not used).
 */
#define RZ_REGEX_DEFAULT  0
#define RZ_REGEX_LITERAL  0x02000000u /* PCRE2_LITERAL       - C      */
#define RZ_REGEX_CASELESS 0x00000008u /* PCRE2_CASELESS      - C      */
/**
 * \brief If RZ_REGEX_EXTENDED is passed to rz_regex_new_16() or rz_regex_new_32()
 * spaces in the pattern **will** be skipped! You need to replace them with \s.
 * This is in accordance with the PCRE2 documentation.
 *
 * If RZ_REGEX_EXTENDED is passed to rz_regex_new() (the UTF-8 regular expressions)
 * the spaces **will not** be skipped but interally be replaced with '\s'.
 * This was done to keep our interal regex matching stable.
 *
 * Values can be passed as cflags.
 */
#define RZ_REGEX_EXTENDED      0x00000080u /* PCRE2_EXTENDED      - C      */
#define RZ_REGEX_EXTENDED_MORE 0x01000000u /* PCRE2_EXTENDED_MORE - C      */
#define RZ_REGEX_MULTILINE     0x00000400u /* PCRE2_MULTILINE     - C      */
#define RZ_REGEX_DOTALL        0x00000020u /* PCRE2_DOTALL        - C      */

// Can be passed as jflags
#define RZ_REGEX_JIT_PARTIAL_SOFT 0x00000002u /* PCRE2_JIT_PARTIAL_SOFT */
#define RZ_REGEX_JIT_PARTIAL_HARD 0x00000004u /* PCRE2_JIT_PARTIAL_HARD */

// Can be passed for mflags
#define RZ_REGEX_PARTIAL_SOFT 0x00000010u /* PCRE2_PARTIAL_SOFT */
#define RZ_REGEX_PARTIAL_HARD 0x00000020u /* PCRE2_PARTIAL_HARD */

#define RZ_REGEX_UNSET           (~(RZ_REGEX_SIZE)0) /* PCRE2_UNSET */
#define RZ_REGEX_ZERO_TERMINATED (~(RZ_REGEX_SIZE)0) /* PCRE2_ZERO_TERMINATED */

typedef int RzRegexStatus; ///< An status number returned by the regex API.
typedef size_t RzRegexSize; ///< Size of a text or regex. This is the size measured in code width. For UTF-8: bytes.
typedef ut32 RzRegexFlags; ///< Regex flag bits.
typedef uint8_t *RzRegexPattern; ///< A regex pattern string.
typedef void RzRegex; ///< A regex expression for UTF-8 strings.
typedef void RzRegexCompContext; ///< A PCRE2 compile context for UTF-8 strings.
typedef void RzRegex16; ///< A regex expression for UTF-16 strings (host endianess).
typedef void RzRegexCompContext16; ///< A PCRE2 compile context for UTF-16 strings (host endianess).
typedef void RzRegex32; ///< A regex expression for UTF-32 strings (host endianess).
typedef void RzRegexCompContext32; ///< A PCRE2 compile context for UTF-32 strings (host endianess).

typedef enum {
	RZ_REGEX_UTF8,
	RZ_REGEX_UTF16,
	RZ_REGEX_UTF32,
} RzRegexType;

typedef struct {
	RzRegexType re_type;
	RzRegexFlags compile_flags_jit;
	union {
		RzRegex *re8;
		RzRegex16 *re16;
		RzRegex32 *re32;
	};
	void *jit_stack; ///< The JIT stack for this pattern. Must be used only by one thread at a time.
} RzRegexMulti;

typedef struct {
	RzRegexSize group_idx; ///< Index of the group. Used to determine name if any was given.
	/**
	 * \brief Start offset into the text where the match starts.
	 * The offset is in code units, not in characters!
	 * One code unit is 1 byte for UTF-8, 2 bytes for UTF-16, and 4 bytes for UTF-32.
	 */
	RzRegexSize start;
	/**
	 * \brief The length of the match in number of code units.
	 * One code unit is 1 byte for UTF-8, 2 bytes for UTF-16, and 4 bytes for UTF-32.
	 */
	RzRegexSize len; ///< Length of match in bytes.
} RzRegexMatch;

typedef void RzRegexMatchData; ///< PCRE2 internal match data type

RZ_API RZ_OWN RzRegex *rz_regex_new(RZ_NONNULL const char *pattern, RzRegexFlags cflags, RzRegexFlags jflags,
	RzRegexCompContext *ccontext);
RZ_API RZ_OWN RzRegex16 *rz_regex_new_16(RZ_NONNULL const char *pattern, RzRegexFlags cflags, RzRegexFlags jflags,
	RzRegexCompContext *ccontext);
RZ_API RZ_OWN RzRegex32 *rz_regex_new_32(RZ_NONNULL const char *pattern, RzRegexFlags cflags, RzRegexFlags jflags,
	RzRegexCompContext *ccontext);
RZ_API RZ_OWN RzRegexMulti *rz_regex_new_multi(RZ_NONNULL const char *pattern, RzRegexFlags cflags, RzRegexFlags jflags,
	RzRegexCompContext *ccontext, RzRegexType type);
RZ_API RZ_OWN RzRegex *rz_regex_new_bytes(RZ_NONNULL const ut8 *pattern, size_t pattern_len, RzRegexFlags cflags, RzRegexFlags jflags,
	RzRegexCompContext *ccontext);
RZ_API void rz_regex_free(RZ_OWN RzRegex *regex);
RZ_API void rz_regex_free_16(RZ_OWN RzRegex16 *regex);
RZ_API void rz_regex_free_32(RZ_OWN RzRegex32 *regex);
RZ_API void rz_regex_free_multi(RZ_NULLABLE RZ_OWN RzRegexMulti *regex);
RZ_API RZ_OWN RzRegexMulti *rz_regex_multi_clone(RZ_NONNULL RzRegexMulti *regex, bool clone_jit);
RZ_API void rz_regex_free_multi_clone(RZ_NULLABLE RZ_OWN RzRegexMulti *regex);
RZ_API void rz_regex_error_msg(RzRegexStatus errcode, RZ_OUT char *errbuf, RzRegexSize errbuf_size);
RZ_API const ut8 *rz_regex_get_match_name(RZ_NONNULL const RzRegex *regex, ut32 name_idx);
RZ_API st32 rz_regex_get_group_idx_by_name(RZ_NONNULL const RzRegex *regex, const char *group);
RZ_API RzRegexStatus rz_regex_match(RZ_NONNULL const RzRegex *regex, RZ_NONNULL const char *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags);
RZ_API RZ_OWN RzPVector /*<RzRegexMatch *>*/ *rz_regex_match_all_not_grouped(
	RZ_NONNULL const RzRegex *regex,
	RZ_NONNULL const char *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags);
RZ_API RZ_OWN RzPVector /*<RzRegexMatch *>*/ *rz_regex_match_first(
	RZ_NONNULL const RzRegex *regex,
	RZ_NONNULL const char *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags);
RZ_API RZ_OWN RzPVector /*<RzRegexMatch *>*/ *rz_regex_match_first_16(
	RZ_NONNULL const RzRegex16 *regex,
	RZ_NONNULL const ut16 *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags);
RZ_API RZ_OWN RzPVector /*<RzRegexMatch *>*/ *rz_regex_match_first_32(
	RZ_NONNULL const RzRegex32 *regex,
	RZ_NONNULL const ut32 *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags);
RZ_API RZ_OWN RzPVector /*<RzVector<RzRegexMatch *> *>*/ *rz_regex_match_all(
	RZ_NONNULL const RzRegex *regex,
	RZ_NONNULL const char *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags);
RZ_API RZ_OWN RzPVector /*<RzVector<RzRegexMatch *> *>*/ *rz_regex_match_all_overlap(
	RZ_NONNULL const RzRegex *regex,
	RZ_NONNULL const char *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags);
RZ_API RZ_OWN RzPVector /*<RzVector<RzRegexMatch *> *>*/ *rz_regex_match_all_16(
	RZ_NONNULL const RzRegex16 *regex,
	RZ_NONNULL const ut16 *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags);
RZ_API RZ_OWN RzPVector /*<RzVector<RzRegexMatch *> *>*/ *rz_regex_match_all_overlap_16(
	RZ_NONNULL const RzRegex16 *regex,
	RZ_NONNULL const ut16 *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags);
RZ_API RZ_OWN RzPVector /*<RzVector<RzRegexMatch *> *>*/ *rz_regex_match_all_32(
	RZ_NONNULL const RzRegex32 *regex,
	RZ_NONNULL const ut32 *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags);
RZ_API RZ_OWN RzPVector /*<RzVector<RzRegexMatch *> *>*/ *rz_regex_match_all_overlap_32(
	RZ_NONNULL const RzRegex32 *regex,
	RZ_NONNULL const ut32 *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags);
RZ_API RZ_OWN RzPVector /*<RzVector<RzRegexMatch *> *>*/ *rz_regex_match_all_multi(
	RZ_NONNULL const RzRegexMulti *regex,
	RZ_NONNULL const ut8 *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags);
RZ_API RZ_OWN RzPVector /*<RzVector<RzRegexMatch *> *>*/ *rz_regex_match_all_overlap_multi(
	RZ_NONNULL const RzRegexMulti *regex,
	RZ_NONNULL const ut8 *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags);
RZ_API bool rz_regex_contains(RZ_NONNULL const char *pattern, RZ_NONNULL const char *text,
	RzRegexSize text_size,
	RzRegexFlags cflags, RzRegexFlags mflags);
RZ_API RzRegexSize rz_regex_find(RZ_NONNULL const char *pattern, RZ_NONNULL RZ_BORROW char *text,
	RzRegexSize text_size, RzRegexSize text_offset,
	RzRegexFlags cflags, RzRegexFlags mflags);
RZ_API RZ_OWN RzStrBuf *rz_regex_full_match_str(RZ_NONNULL const char *pattern, RZ_NONNULL const char *text,
	RzRegexSize text_size,
	RzRegexFlags cflags, RzRegexFlags mflags, RZ_NONNULL const char *separator);
RZ_API RZ_OWN RzRegexCompContext *rz_regex_compile_context_new();
RZ_API void rz_regex_compile_context_free(RzRegexCompContext *ccontext);
RZ_API void rz_regex_set_nul_as_newline(RZ_NONNULL RzRegexCompContext *ccontext);
RZ_API RzRegexFlags rz_regex_parse_flag_desc(RZ_NULLABLE const char *re_flags_desc);
RZ_API RZ_OWN char *rz_regex_create_wildcard_pattern(size_t min_len, size_t max_len);

#endif /* RZ_REGEX_H */
