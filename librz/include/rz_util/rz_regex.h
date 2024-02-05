// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
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

#define RZ_REGEX_DEFAULT       0
#define RZ_REGEX_CASELESS      0x00000008u /* PCRE2_CASELESS */
#define RZ_REGEX_EXTENDED      0x00000080u /* PCRE2_EXTENDED */
#define RZ_REGEX_EXTENDED_MORE 0x01000000u /* PCRE2_EXTENDED_MORE */
#define RZ_REGEX_MULTILINE     0x00000400u /* PCRE2_MULTILINE */

#define RZ_REGEX_JIT_PARTIAL_SOFT 0x00000002u /* PCRE2_JIT_PARTIAL_SOFT */
#define RZ_REGEX_JIT_PARTIAL_HARD 0x00000004u /* PCRE2_JIT_PARTIAL_HARD */

#define RZ_REGEX_PARTIAL_SOFT 0x00000010u /* PCRE2_PARTIAL_SOFT */
#define RZ_REGEX_PARTIAL_HARD 0x00000020u /* PCRE2_PARTIAL_HARD */

#define RZ_REGEX_UNSET           (~(RZ_REGEX_SIZE)0) /* PCRE2_UNSET */
#define RZ_REGEX_ZERO_TERMINATED (~(RZ_REGEX_SIZE)0) /* PCRE2_ZERO_TERMINATED */

typedef int RzRegexStatus; ///< An status number returned by the regex API.
typedef size_t RzRegexSize; ///< Size of a text or regex. This is the size measured in code width. For UTF-8: bytes.
typedef ut32 RzRegexFlags; ///< Regex flag bits.
typedef uint8_t *RzRegexPattern; ///< A regex pattern string.
typedef void RzRegex; ///< A regex expression.

typedef struct {
	RzRegexSize group_idx; ///< Index of the group. Used to determine name if any was given.
	RzRegexSize start; ///< Start offset into the text where the match starts.
	RzRegexSize len; ///< Length of match in bytes.
} RzRegexMatch;

typedef void RzRegexMatchData; ///< PCRE2 internal match data type

RZ_API RZ_OWN RzRegex *rz_regex_new(RZ_NONNULL const char *pattern, RzRegexFlags cflags, RzRegexFlags jflags);
RZ_API void rz_regex_free(RZ_OWN RzRegex *regex);
RZ_API void rz_regex_error_msg(RzRegexStatus errcode, RZ_OUT char *errbuf, RzRegexSize errbuf_size);
RZ_API const ut8 *rz_regex_get_match_name(RZ_NONNULL const RzRegex *regex, ut32 name_idx);
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
RZ_API RZ_OWN RzPVector /*<RzVector<RzRegexMatch *> *>*/ *rz_regex_match_all(
	RZ_NONNULL const RzRegex *regex,
	RZ_NONNULL const char *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags);
RZ_API bool rz_regex_contains(RZ_NONNULL const char *pattern, RZ_NONNULL const char *text,
	RzRegexSize text_size,
	RzRegexFlags cflags, RzRegexFlags mflags);
RZ_API RZ_OWN RzStrBuf *rz_regex_full_match_str(RZ_NONNULL const char *pattern, RZ_NONNULL const char *text,
	RzRegexSize text_size,
	RzRegexFlags cflags, RzRegexFlags mflags, RZ_NONNULL const char *separator);

#endif /* RZ_REGEX_H */
