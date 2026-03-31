// SPDX-FileCopyrightText: 2023 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#define PCRE2_STATIC
#define PCRE2_CODE_UNIT_WIDTH 0
#include <pcre2.h>

#include <rz_util/rz_strbuf.h>
#include <rz_vector.h>
#include <rz_util/rz_regex.h>
#include <rz_types.h>
#include <rz_util/rz_assert.h>
#include <rz_util.h>
#include <rz_types.h>

// Default JIT stack size is 32KiB.
// But the wildcard pattern we have for strings takes more.
#define RZ_REGEX_JIT_STACK_MIN (32 * 1024)
// 1MiB are documented as reasoable maxima.
#define RZ_REGEX_JIT_STACK_MAX (1024 * 1024)

typedef pcre2_general_context_8 RzRegexGeneralContext8; ///< General context.
// typedef pcre2_compile_context RzRegexCompContext; ///< The context for compiling.
typedef pcre2_match_context_8 RzRegexMatchContext8; ///< The context for matching.

typedef struct {
	RzRegexGeneralContext8 *general;
	RzRegexCompContext *compile;
	RzRegexMatchContext8 *match;
} RzRegexContexts8;

static void check_faulty_pcre2_word_width(size_t pcre2_word_width) {
	if (pcre2_word_width != 8 && pcre2_word_width != 16 && pcre2_word_width != 32) {
		RZ_LOG_FATAL("PCRE2 word with of %" PFMTSZu " is not supported.\n", pcre2_word_width);
		abort();
	}
}

static void print_pcre2_err(RZ_NULLABLE const char *utf8_pattern, RzRegexStatus err_num, size_t err_off) {
	PCRE2_UCHAR8 buffer[256];
	pcre2_get_error_message_8(err_num, buffer, sizeof(buffer));
	RZ_LOG_ERROR("Regex compilation for '%s' failed at %" PFMTSZu ": %s\n", utf8_pattern ? utf8_pattern : "(null)", err_off,
		buffer);
}

static RZ_OWN void *regex_new(RZ_NONNULL const char *pattern, RzRegexFlags cflags, RzRegexFlags jflags,
	RzRegexCompContext *ccontext, size_t pcre2_word_width) {
	rz_return_val_if_fail(pattern, NULL);
	check_faulty_pcre2_word_width(pcre2_word_width);
	if (jflags == RZ_REGEX_DEFAULT) {
		jflags = PCRE2_JIT_COMPLETE;
	}

	RzRegexStatus err_num;
	RzRegexSize err_off;
	ut32 supported = 0;
	if (pcre2_word_width == 8) {
		pcre2_config_8(PCRE2_CONFIG_UNICODE, &supported);
	} else if (pcre2_word_width == 16) {
		pcre2_config_16(PCRE2_CONFIG_UNICODE, &supported);
	} else {
		pcre2_config_32(PCRE2_CONFIG_UNICODE, &supported);
	}
	if (supported != 1) {
		RZ_LOG_ERROR("Unicode not supported by PCRE2 library.\n");
		return NULL;
	}
	char *fixed_pat = NULL;
	const char *pat = NULL;
	if (((cflags & RZ_REGEX_EXTENDED) || (cflags & RZ_REGEX_EXTENDED_MORE))) {
		// In PCRE2 with the extended flag set, ascii space characters ' ' are skipped.
		// We need to replace them with \s unfortunately to keep our API stable.
		if (!strchr(pattern, ' ')) {
			pat = pattern;
		} else {
			fixed_pat = rz_str_replace(rz_str_dup(pattern), " ", "\\s", 1);
			pat = fixed_pat;
		}
	} else {
		pat = pattern;
	}
	if (!(cflags & PCRE2_LITERAL)) {
		cflags |= PCRE2_UCP;
	}

	void *regex;
	if (pcre2_word_width == 8) {
		regex = pcre2_compile_8(
			(PCRE2_SPTR8)pat,
			PCRE2_ZERO_TERMINATED,
			cflags | PCRE2_UTF | PCRE2_NO_UTF_CHECK | PCRE2_MATCH_INVALID_UTF,
			&err_num,
			&err_off,
			ccontext);
		if (!regex) {
			print_pcre2_err(pat, err_num, err_off);
			free(fixed_pat);
			return NULL;
		}
#ifdef SUPPORTS_PCRE2_JIT
		RzRegexStatus jit_err = pcre2_jit_compile_8(regex, jflags);

		if (jit_err < 0) {
			print_pcre2_err(pat, jit_err, 0);
		}
#endif
	} else if (pcre2_word_width == 16) {
		ut16 *utf16_pat = rz_str_utf8_to_utf16(pat, RZ_HOST_IS_BIG_ENDIAN);
		regex = pcre2_compile_16(
			(PCRE2_SPTR16)utf16_pat,
			PCRE2_ZERO_TERMINATED,
			cflags | PCRE2_UTF | PCRE2_NO_UTF_CHECK | PCRE2_MATCH_INVALID_UTF,
			&err_num,
			&err_off,
			ccontext);
		if (!regex) {
			print_pcre2_err(pat, err_num, err_off);
			RZ_LOG_WARN("PCRE2 pattern offset might be invalid, due to different encoding.\n");
			free(fixed_pat);
			free(utf16_pat);
			return NULL;
		}
		free(utf16_pat);
#ifdef SUPPORTS_PCRE2_JIT
		RzRegexStatus jit_err = pcre2_jit_compile_16(regex, jflags);
		if (jit_err < 0) {
			print_pcre2_err(pat, jit_err, 0);
		}
#endif
	} else {
		ut32 *utf32_pat = rz_str_utf8_to_utf32(pat, RZ_HOST_IS_BIG_ENDIAN);
		regex = pcre2_compile_32(
			(PCRE2_SPTR32)utf32_pat,
			PCRE2_ZERO_TERMINATED,
			cflags | PCRE2_UTF | PCRE2_NO_UTF_CHECK | PCRE2_MATCH_INVALID_UTF,
			&err_num,
			&err_off,
			ccontext);
		if (!regex) {
			print_pcre2_err(pat, err_num, err_off / 4);
			free(fixed_pat);
			free(utf32_pat);
			return NULL;
		}
		free(utf32_pat);
#ifdef SUPPORTS_PCRE2_JIT
		RzRegexStatus jit_err = pcre2_jit_compile_32(regex, jflags);
		if (jit_err < 0) {
			print_pcre2_err(pat, jit_err, 0);
		}
#endif
	}
	free(fixed_pat);
	return regex;
}

/**
 * \brief Compile a regex pattern to a RzRegex and return it.
 * In case of an error, an error message is printed and NULL is returned.
 *
 * NOTE: If RZ_REGEX_EXTENDED is passed, spaces in the pattern will **not** be skipped!
 * This is contrary to the PCRE2 documentation. But keeps our internal regex usage stable.
 *
 * \param pattern The regex pattern string.
 * \param cflags The compilation flags or zero for default.
 *        PCRE2_UTF | PCRE2_NO_UTF_CHECK | PCRE2_MATCH_INVALID_UTF and PCRE2_UCP are enforced currently.
 * \param jflags The compilation flags for the JIT compiler.
 *        You can pass RZ_REGEX_JIT_PARTIAL_SOFT or RZ_REGEX_JIT_PARTIAL_HARD if you
 *        intend to use the pattern for partial matching. Otherwise set it to 0.
 * \param ccontext A compile context or NULL.
 *
 * \return The compiled regex or NULL in case of failure.
 */
RZ_API RZ_OWN RzRegex *rz_regex_new(RZ_NONNULL const char *pattern, RzRegexFlags cflags, RzRegexFlags jflags,
	RzRegexCompContext *ccontext) {
	rz_return_val_if_fail(pattern, NULL);
	return regex_new(pattern, cflags, jflags, ccontext, 8);
}

/**
 * \brief Compile an UTF-16 regex pattern to a RzRegex16 and return it.
 * In case of an error, an error message is printed and NULL is returned.
 *
 * NOTE: The pattern and matching will always be in the host's endianness.
 * NOTE: If RZ_REGEX_EXTENDED is passed, spaces in the pattern **will** be skipped!
 * This is the opposite behavior to the default UTF-8 regular expressions.
 *
 * \param pattern The regex pattern string. It must be an UTF-8 encoded string.
 * \param cflags The compilation flags or zero for default.
 *        PCRE2_UTF | PCRE2_NO_UTF_CHECK | PCRE2_MATCH_INVALID_UTF and PCRE2_UCP are enforced currently.
 * \param jflags The compilation flags for the JIT compiler.
 *        You can pass RZ_REGEX_JIT_PARTIAL_SOFT or RZ_REGEX_JIT_PARTIAL_HARD if you
 *        intend to use the pattern for partial matching. Otherwise set it to 0.
 * \param ccontext A compile context or NULL.
 *
 * \return The compiled regex or NULL in case of failure.
 */
RZ_API RZ_OWN RzRegex16 *rz_regex_new_16(RZ_NONNULL const char *pattern, RzRegexFlags cflags, RzRegexFlags jflags,
	RzRegexCompContext16 *ccontext) {
	rz_return_val_if_fail(pattern, NULL);
	return regex_new(pattern, cflags, jflags, ccontext, 16);
}

/**
 * \brief Compile an UTF-32 regex pattern to a RzRegex32 and return it.
 * In case of an error, an error message is printed and NULL is returned.
 *
 * NOTE: The pattern and matching will always be in the host's endianness.
 *
 * \param pattern The regex pattern string. It must be an UTF-8 encoded string.
 * \param cflags The compilation flags or zero for default.
 *        PCRE2_UTF | PCRE2_NO_UTF_CHECK | PCRE2_MATCH_INVALID_UTF and PCRE2_UCP are enforced currently.
 * \param jflags The compilation flags for the JIT compiler.
 *        You can pass RZ_REGEX_JIT_PARTIAL_SOFT or RZ_REGEX_JIT_PARTIAL_HARD if you
 *        intend to use the pattern for partial matching. Otherwise set it to 0.
 * \param ccontext A compile context or NULL.
 *
 * \return The compiled regex or NULL in case of failure.
 */
RZ_API RZ_OWN RzRegex32 *rz_regex_new_32(RZ_NONNULL const char *pattern, RzRegexFlags cflags, RzRegexFlags jflags,
	RzRegexCompContext32 *ccontext) {
	rz_return_val_if_fail(pattern, NULL);
	return regex_new(pattern, cflags, jflags, ccontext, 32);
}

/**
 * \brief Compile an Regex pattern of \p type.
 *
 * NOTE: The pattern and matching will always be in the host's endianness.
 *
 * \param pattern The regex pattern string. It must be an UTF-8 encoded string.
 * \param cflags The compilation flags or zero for default.
 *        PCRE2_UCP | PCRE2_UTF | PCRE2_NO_UTF_CHECK | PCRE2_MATCH_INVALID_UTF are enforced currently.
 * \param jflags The compilation flags for the JIT compiler.
 *        You can pass RZ_REGEX_JIT_PARTIAL_SOFT or RZ_REGEX_JIT_PARTIAL_HARD if you
 *        intend to use the pattern for partial matching. Otherwise set it to RZ_REGEX_DEFAULT.
 * \param ccontext A compile context or NULL.
 * \param type The string encoding type the pattern should match.
 *
 * \return The compiled regex or NULL in case of failure.
 */
RZ_API RZ_OWN RzRegexMulti *rz_regex_new_multi(RZ_NONNULL const char *pattern, RzRegexFlags cflags, RzRegexFlags jflags,
	RzRegexCompContext *ccontext, RzRegexType type) {
	RzRegexMulti *re = RZ_NEW0(RzRegexMulti);
	if (!re) {
		return NULL;
	}
	if (jflags == RZ_REGEX_DEFAULT) {
		jflags = PCRE2_JIT_COMPLETE;
	}
	re->re_type = type;
	re->compile_flags_jit = jflags;
	switch (type) {
	default:
		rz_warn_if_reached();
		free(re);
		return NULL;
	case RZ_REGEX_UTF8:
		re->re8 = rz_regex_new(pattern, cflags, jflags, ccontext);
		break;
	case RZ_REGEX_UTF16:
		re->re16 = rz_regex_new_16(pattern, cflags, jflags, ccontext);
		break;
	case RZ_REGEX_UTF32:
		re->re32 = rz_regex_new_32(pattern, cflags, jflags, ccontext);
		break;
	}
	if (!re->re8 && !re->re16 && !re->re32) {
		free(re);
		return NULL;
	}
#ifdef SUPPORTS_PCRE2_JIT
	switch (type) {
	default:
		rz_warn_if_reached();
		return NULL;
	case RZ_REGEX_UTF8:
		re->jit_stack = pcre2_jit_stack_create_8(RZ_REGEX_JIT_STACK_MIN, RZ_REGEX_JIT_STACK_MAX, NULL);
		break;
	case RZ_REGEX_UTF16:
		re->jit_stack = pcre2_jit_stack_create_16(RZ_REGEX_JIT_STACK_MIN, RZ_REGEX_JIT_STACK_MAX, NULL);
		break;
	case RZ_REGEX_UTF32:
		re->jit_stack = pcre2_jit_stack_create_32(RZ_REGEX_JIT_STACK_MIN, RZ_REGEX_JIT_STACK_MAX, NULL);
		break;
	}
	if (!re->jit_stack) {
		rz_warn_if_reached();
		rz_regex_free_multi(re);
		return NULL;
	}
#endif
	return re;
}

/**
 * \brief Compile a regex pattern with raw bytes.
 * In case of an error, an error message is printed and NULL is returned.
 *
 * Unlike `rz_regex_new()` it doesn't compile the pattern with the PCRE2_UTF flag.
 * So any byte can be part of a pattern, not just UTF-8 compatible ones.
 *
 * \param pattern The pattern. Bytes must not be escaped.
 * \param pattern_len The pattern length.
 * \param cflags The compilation flags.
 * \param jflags The compilation flags for the JIT compiler.
 *        You can pass RZ_REGEX_JIT_PARTIAL_SOFT or RZ_REGEX_JIT_PARTIAL_HARD if you
 *        intend to use the pattern for partial matching. Otherwise set it to 0.
 * \param ccontext A compile context or NULL.
 *
 * \return The compiled regex or NULL in case of failure.
 */
RZ_API RZ_OWN RzRegex *rz_regex_new_bytes(RZ_NONNULL const ut8 *pattern, size_t pattern_len, RzRegexFlags cflags, RzRegexFlags jflags,
	RzRegexCompContext *ccontext) {
	rz_return_val_if_fail(pattern, NULL);
	if (jflags == RZ_REGEX_DEFAULT) {
		jflags = PCRE2_JIT_COMPLETE;
	}

	RzRegexStatus err_num;
	RzRegexSize err_off;

	RzRegex *regex = pcre2_compile_8(
		pattern,
		pattern_len,
		cflags,
		&err_num,
		&err_off,
		ccontext);
	if (!regex) {
		print_pcre2_err((const char *)pattern, err_num, err_off);
		return NULL;
	}
#ifdef SUPPORTS_PCRE2_JIT
	RzRegexStatus jit_err = pcre2_jit_compile_8(regex, jflags);
	if (jit_err < 0) {
		print_pcre2_err((const char *)pattern, jit_err, 0);
	}
#endif
	return regex;
}

/**
 * \brief Frees a given RzRegex.
 *
 * \param regex The RzRegex to free.
 */
RZ_API void rz_regex_free(RZ_OWN RzRegex *regex) {
	pcre2_code_free_8(regex);
}

/**
 * \brief Frees a given RzRegex16.
 *
 * \param regex The RzRegex16 to free.
 */
RZ_API void rz_regex_free_16(RZ_OWN RzRegex16 *regex) {
	pcre2_code_free_8(regex);
}

/**
 * \brief Frees a given RzRegex32.
 *
 * \param regex The RzRegex32 to free.
 */
RZ_API void rz_regex_free_32(RZ_OWN RzRegex32 *regex) {
	pcre2_code_free_8(regex);
}

/**
 * \brief Makes a clone of the given multi \p regex object.
 *
 * NOTE: Cloning is only performed if the library is build with JIT support.
 * JIT patterns cannot be used by multiple threads.
 * Patterns without JIT matching can be used by multiple threads.
 * So JIT compiled patterns need to be clonedbefore being used
 * in a thread save manner.
 *
 * After usage the returned pointer should always
 * be freed via rz_regex_free_multi_clone().
 *
 * \param regex The multi regex to clone.
 * \param clone_jit If set, the clone will also have JIT pattern matching.
 *        If unset it still clones the pattern, but the clone won't support
 *        JIT pattern matching.
 *
 * \return The clone for \p regex or NULL in case of failure.
 */
RZ_API RZ_OWN RzRegexMulti *rz_regex_multi_clone(RZ_NONNULL RzRegexMulti *regex, bool clone_jit) {
	rz_return_val_if_fail(regex, NULL);
#ifndef SUPPORTS_PCRE2_JIT
	return regex;
#else
	RzRegexMulti *clone = RZ_NEW0(RzRegexMulti);
	if (!clone) {
		return NULL;
	}
	clone->re_type = regex->re_type;
	clone->compile_flags_jit = regex->compile_flags_jit;
	switch (regex->re_type) {
	case RZ_REGEX_UTF8:
		clone->re8 = pcre2_code_copy_with_tables_8(regex->re8);
		if (clone_jit) {
			pcre2_jit_compile_8(clone->re8, clone->compile_flags_jit);
		}
		break;
	case RZ_REGEX_UTF16:
		clone->re16 = pcre2_code_copy_with_tables_16(regex->re16);
		if (clone_jit) {
			pcre2_jit_compile_16(clone->re16, clone->compile_flags_jit);
		}
		break;
	case RZ_REGEX_UTF32:
		clone->re32 = pcre2_code_copy_with_tables_32(regex->re32);
		if (clone_jit) {
			pcre2_jit_compile_32(clone->re32, clone->compile_flags_jit);
		}
		break;
	}
	if (!(clone->re8 || clone->re16 || clone->re32)) {
		free(clone);
		return NULL;
	}
	return clone;
#endif
}

/**
 * \brief Frees a cloned RzRegexMulti object.
 * Only RzRegexMulti returned by rz_regex_clone_multi() should be passed here.
 *
 * This function behaves differently if Rizin is compiled with or without
 * JIT support. Without JIT support enabled, it will just return.
 * With JIT support it will free the \p regex.
 *
 * Please see rz_regex_clone_multi() for details.
 *
 * \param regex The cloned multi regex to free.
 */
RZ_API void rz_regex_free_multi_clone(RZ_NULLABLE RZ_OWN RzRegexMulti *regex) {
#ifndef SUPPORTS_PCRE2_JIT
	return;
#else
	rz_regex_free_multi(regex);
#endif
}

/**
 * \brief Frees a given RzRegexMulti.
 *
 * \param regex The RzRegexMulti to free.
 */
RZ_API void rz_regex_free_multi(RZ_NULLABLE RZ_OWN RzRegexMulti *regex_multi) {
	if (!regex_multi) {
		return;
	}
	switch (regex_multi->re_type) {
	case RZ_REGEX_UTF8:
		rz_regex_free(regex_multi->re8);
		break;
	case RZ_REGEX_UTF16:
		rz_regex_free_16(regex_multi->re16);
		break;
	case RZ_REGEX_UTF32:
		rz_regex_free_32(regex_multi->re32);
		break;
	}
#ifdef SUPPORTS_PCRE2_JIT
	switch (regex_multi->re_type) {
	case RZ_REGEX_UTF8:
		pcre2_jit_stack_free_8(regex_multi->jit_stack);
		break;
	case RZ_REGEX_UTF16:
		pcre2_jit_stack_free_16(regex_multi->jit_stack);
		break;
	case RZ_REGEX_UTF32:
		pcre2_jit_stack_free_32(regex_multi->jit_stack);
		break;
	}
#endif
	free(regex_multi);
}

static void rz_regex_match_data_free(RZ_OWN RzRegexMatchData *match_data) {
	pcre2_match_data_free_8(match_data);
}

/**
 * \brief Matches the \p regex in the \p text and returns a status code with the result.
 *
 * \param regex The regex pattern to match.
 * \param text The text to search in.
 * \param text_size The length of the buffer pointed to by \p text.
 *        Can be set to RZ_REGEX_ZERO_TERMINATED if the buffer is a zero terminated string.
 * \param text_offset The offset into \p text from where the search starts.
 * \param mflags Match flags. PCRE2_NO_UTF_CHECK is enforced currently.
 *
 * \return A status code which describes the result.
 */
RZ_API RzRegexStatus rz_regex_match(RZ_NONNULL const RzRegex *regex, RZ_NONNULL const char *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags) {
	rz_return_val_if_fail(regex && text, RZ_REGEX_ERROR_NOMATCH);

	pcre2_match_data_8 *mdata = pcre2_match_data_create_from_pattern_8(regex, NULL);
	RzRegexStatus rc = pcre2_match_8(regex, (PCRE2_SPTR8)text, text_size, text_offset, mflags | PCRE2_NO_UTF_CHECK, mdata, NULL);
	pcre2_match_data_free_8(mdata);
	return rc;
}

/**
 * \brief Matches the \p regex in the \p text and returns a status code with the result.
 *
 * NOTE: This matches against UTF-16 strings (host-endianness).
 *
 * \param regex The regex pattern to match.
 * \param text The text to search in. UTF-16 encoded in the host's endianness.
 * \param text_size The length of the buffer pointed to by \p text.
 *        Can be set to RZ_REGEX_ZERO_TERMINATED if the buffer is a zero terminated string.
 * \param text_offset The offset into \p text from where the search starts.
 * \param mflags Match flags. PCRE2_NO_UTF_CHECK is enforced currently.
 *
 * \return A status code which describes the result.
 */
RZ_API RzRegexStatus rz_regex_match_16(RZ_NONNULL const RzRegex16 *regex, RZ_NONNULL const ut16 *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags) {
	rz_return_val_if_fail(regex && text, RZ_REGEX_ERROR_NOMATCH);

	pcre2_match_data_16 *mdata = pcre2_match_data_create_from_pattern_16(regex, NULL);
	RzRegexStatus rc = pcre2_match_16(regex, (PCRE2_SPTR16)text, text_size, text_offset, mflags | PCRE2_NO_UTF_CHECK, mdata, NULL);
	pcre2_match_data_free_16(mdata);
	return rc;
}

/**
 * \brief Matches the \p regex in the \p text and returns a status code with the result.
 *
 * NOTE: This matches against UTF-32 strings (host-endianness).
 *
 * \param regex The regex pattern to match.
 * \param text The text to search in. UTF-32 encoded in the host's endianness.
 * \param text_size The length of the buffer pointed to by \p text.
 *        Can be set to RZ_REGEX_ZERO_TERMINATED if the buffer is a zero terminated string.
 * \param text_offset The offset into \p text from where the search starts.
 * \param mflags Match flags. PCRE2_NO_UTF_CHECK is enforced currently.
 *
 * \return A status code which describes the result.
 */
RZ_API RzRegexStatus rz_regex_match_32(RZ_NONNULL const RzRegex32 *regex, RZ_NONNULL const ut32 *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags) {
	rz_return_val_if_fail(regex && text, RZ_REGEX_ERROR_NOMATCH);

	pcre2_match_data_32 *mdata = pcre2_match_data_create_from_pattern_32(regex, NULL);
	RzRegexStatus rc = pcre2_match_32(regex, (PCRE2_SPTR32)text, text_size, text_offset, mflags | PCRE2_NO_UTF_CHECK, mdata, NULL);
	pcre2_match_data_free_32(mdata);
	return rc;
}

/**
 * \brief Generates the error message to \p errcode.
 *
 * \param errcode The error code.
 * \param errbuf The error message buffer.
 * \param errbuf_size The error message buffer size in bytes.
 */
RZ_API void rz_regex_error_msg(RzRegexStatus errcode, RZ_OUT char *errbuf, RzRegexSize errbuf_size) {
	pcre2_get_error_message_8(errcode, (PCRE2_UCHAR8 *)errbuf, errbuf_size);
}

/**
 * \brief Returns the name of a group.
 *
 * \param regex The regex expression with named groups.
 * \param group_idx The index of the group to get the name for.
 *
 * \return The name of the group or NULL in case of failure or non is was set.
 */
RZ_API const ut8 *rz_regex_get_match_name(RZ_NONNULL const RzRegex *regex, ut32 group_idx) {
	rz_return_val_if_fail(regex, NULL);

	ut32 namecount;
	ut32 name_entry_size;
	PCRE2_SPTR8 nametable_ptr;

	pcre2_pattern_info_8(
		regex,
		PCRE2_INFO_NAMECOUNT,
		&namecount);

	pcre2_pattern_info_8(
		regex,
		PCRE2_INFO_NAMETABLE,
		&nametable_ptr);

	pcre2_pattern_info_8(
		regex,
		PCRE2_INFO_NAMEENTRYSIZE,
		&name_entry_size);

	for (size_t i = 0; i < namecount; i++) {
		int n = (nametable_ptr[0] << 8) | nametable_ptr[1];
		if (n == group_idx) {
			return nametable_ptr + 2;
		}
		nametable_ptr += name_entry_size;
	}
	return NULL;
}

/**
 * \brief Returns the index of a group in the pattern \p regex.
 *
 * \param regex The regex expression with named groups.
 * \param group The group name to get the index for.
 *
 * \return The index of the group or RZ_REGEX_ERROR_NOMATCH in case of failure or if no name was given.
 */
RZ_API RzRegexStatus rz_regex_get_group_idx_by_name(RZ_NONNULL const RzRegex *regex, const char *group) {
	rz_return_val_if_fail(regex, RZ_REGEX_ERROR_NOMATCH);

	ut32 namecount;
	ut32 name_entry_size;
	PCRE2_SPTR8 nametable_ptr;

	pcre2_pattern_info_8(
		regex,
		PCRE2_INFO_NAMECOUNT,
		&namecount);

	pcre2_pattern_info_8(
		regex,
		PCRE2_INFO_NAMETABLE,
		&nametable_ptr);

	pcre2_pattern_info_8(
		regex,
		PCRE2_INFO_NAMEENTRYSIZE,
		&name_entry_size);

	for (size_t i = 0; i < namecount; i++) {
		int n = (nametable_ptr[0] << 8) | nametable_ptr[1];
		if (RZ_STR_EQ((const char *)nametable_ptr + 2, group)) {
			return n;
		}
		nametable_ptr += name_entry_size;
	}
	return RZ_REGEX_ERROR_NOMATCH;
}

static RZ_OWN RzPVector /*<RzRegexMatch *>*/ *match_first_8(
	RZ_NONNULL const void *regex,
	RZ_NONNULL const ut8 *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags,
	RZ_NULLABLE void *jit_stack) {
	rz_return_val_if_fail(regex && text, NULL);

	RzPVector *matches = NULL;
	RzRegexMatchData *mdata = NULL;
	mdata = pcre2_match_data_create_from_pattern_8(regex, NULL);

	pcre2_match_context_8 *mcontext = NULL;
#ifdef SUPPORTS_PCRE2_JIT
	if (jit_stack) {
		mcontext = pcre2_match_context_create_8(NULL);
		if (!mcontext) {
			goto fini;
		}
		pcre2_jit_stack_assign_8(mcontext, NULL, jit_stack);
	}
#endif
	RzRegexStatus rc = 0;
	rc = pcre2_match_8(regex, (PCRE2_SPTR8)text, text_size, text_offset, mflags | PCRE2_NO_UTF_CHECK, mdata, mcontext);

	if (rc == PCRE2_ERROR_NOMATCH) {
		// Nothing matched return empty vector.
		goto fini;
	}

	if (rc < 0) {
		// Some error happend. Inform the user.
		PCRE2_UCHAR8 buffer[256];
		pcre2_get_error_message_8(rc, buffer, sizeof(buffer));
		RZ_LOG_WARN("Regex matching failed: %s\n", buffer);
		goto fini;
	}

	// Add groups to vector
	PCRE2_SIZE *ovector;
	ovector = pcre2_get_ovector_pointer_8(mdata);

	ut32 name_entry_size;
	PCRE2_SPTR8 nametable_ptr8;

	pcre2_pattern_info_8(
		regex,
		PCRE2_INFO_NAMETABLE,
		&nametable_ptr8);

	pcre2_pattern_info_8(
		regex,
		PCRE2_INFO_NAMEENTRYSIZE,
		&name_entry_size);

	matches = rz_pvector_new(free);
	for (size_t i = 0; i < rc; i++) {
		if (ovector[2 * i] > ovector[2 * i + 1]) {
			// This happens for \K lookaround. We fail if used.
			// See pcre2demo.c for details.
			RZ_LOG_ERROR("Usage of \\K to set start of the pattern later than the end, is not implemented.\n");
			goto fini;
		}

		// Offset and length of match
		RzRegexMatch *match = RZ_NEW0(RzRegexMatch);
		match->start = ovector[2 * i];
		match->len = ovector[2 * i + 1] - match->start;
		match->group_idx = i;
		nametable_ptr8 += name_entry_size;
		rz_pvector_push(matches, match);
	}

fini:
	rz_regex_match_data_free(mdata);
	pcre2_match_context_free_8(mcontext);
	return matches;
}

static RZ_OWN RzPVector /*<RzRegexMatch *>*/ *match_first_16(
	RZ_NONNULL const void *regex,
	RZ_NONNULL const ut16 *text,
	RzRegexSize text_size_code_units,
	RzRegexSize text_offset_code_units,
	RzRegexFlags mflags,
	RZ_NULLABLE void *jit_stack) {
	rz_return_val_if_fail(regex && text, NULL);

	RzPVector *matches = NULL;
	RzRegexMatchData *mdata = NULL;
	mdata = pcre2_match_data_create_from_pattern_16(regex, NULL);

	pcre2_match_context_16 *mcontext = NULL;
#ifdef SUPPORTS_PCRE2_JIT
	if (jit_stack) {
		mcontext = pcre2_match_context_create_16(NULL);
		if (!mcontext) {
			goto fini;
		}
		pcre2_jit_stack_assign_16(mcontext, NULL, jit_stack);
	}
#endif
	RzRegexStatus rc = 0;
	rc = pcre2_match_16(regex, (PCRE2_SPTR16)text, text_size_code_units, text_offset_code_units, mflags | PCRE2_NO_UTF_CHECK, mdata, mcontext);

	if (rc == PCRE2_ERROR_NOMATCH) {
		// Nothing matched, return an empty vector
		goto fini;
	}

	if (rc < 0) {
		// Some error happend. Inform the user.
		PCRE2_UCHAR8 buffer[256];
		pcre2_get_error_message_8(rc, buffer, sizeof(buffer));
		RZ_LOG_WARN("Regex matching failed: %s\n", buffer);
		goto fini;
	}

	// Add groups to vector
	PCRE2_SIZE *ovector;
	ovector = pcre2_get_ovector_pointer_16(mdata);

	ut32 name_entry_size;
	PCRE2_SPTR16 nametable_ptr16;

	pcre2_pattern_info_16(
		regex,
		PCRE2_INFO_NAMETABLE,
		&nametable_ptr16);

	pcre2_pattern_info_16(
		regex,
		PCRE2_INFO_NAMEENTRYSIZE,
		&name_entry_size);

	matches = rz_pvector_new(free);
	for (size_t i = 0; i < rc; i++) {
		if (ovector[2 * i] > ovector[2 * i + 1]) {
			// This happens for \K lookaround. We fail if used.
			// See pcre2demo.c for details.
			RZ_LOG_ERROR("Usage of \\K to set start of the pattern later than the end, is not implemented.\n");
			goto fini;
		}

		// Offset and length of match
		RzRegexMatch *match = RZ_NEW0(RzRegexMatch);
		match->start = ovector[2 * i];
		match->len = ovector[2 * i + 1] - match->start;
		match->group_idx = i;
		nametable_ptr16 += name_entry_size;
		rz_pvector_push(matches, match);
	}

fini:
	rz_regex_match_data_free(mdata);
	pcre2_match_context_free_16(mcontext);
	return matches;
}

static RZ_OWN RzPVector /*<RzRegexMatch *>*/ *match_first_32(
	RZ_NONNULL const void *regex,
	RZ_NONNULL const ut32 *text,
	RzRegexSize text_size_code_units,
	RzRegexSize text_offset_code_units,
	RzRegexFlags mflags,
	RZ_NULLABLE void *jit_stack) {
	rz_return_val_if_fail(regex && text, NULL);

	RzPVector *matches = NULL;
	RzRegexMatchData *mdata = NULL;
	mdata = pcre2_match_data_create_from_pattern_32(regex, NULL);

	pcre2_match_context_32 *mcontext = NULL;
#ifdef SUPPORTS_PCRE2_JIT
	if (jit_stack) {
		mcontext = pcre2_match_context_create_32(NULL);
		if (!mcontext) {
			goto fini;
		}
		pcre2_jit_stack_assign_32(mcontext, NULL, jit_stack);
	}
#endif
	RzRegexStatus rc = 0;
	rc = pcre2_match_32(regex, (PCRE2_SPTR32)text, text_size_code_units, text_offset_code_units, mflags | PCRE2_NO_UTF_CHECK, mdata, mcontext);

	if (rc == PCRE2_ERROR_NOMATCH) {
		// Nothing matched return empty vector.
		goto fini;
	}

	if (rc < 0) {
		// Some error happend. Inform the user.
		PCRE2_UCHAR8 buffer[256];
		pcre2_get_error_message_8(rc, buffer, sizeof(buffer));
		RZ_LOG_WARN("Regex matching failed: %s\n", buffer);
		goto fini;
	}

	// Add groups to vector
	PCRE2_SIZE *ovector;
	ovector = pcre2_get_ovector_pointer_32(mdata);

	ut32 name_entry_size;
	PCRE2_SPTR32 nametable_ptr32;

	pcre2_pattern_info_32(
		regex,
		PCRE2_INFO_NAMETABLE,
		&nametable_ptr32);

	pcre2_pattern_info_32(
		regex,
		PCRE2_INFO_NAMEENTRYSIZE,
		&name_entry_size);

	matches = rz_pvector_new(free);
	for (size_t i = 0; i < rc; i++) {
		if (ovector[2 * i] > ovector[2 * i + 1]) {
			// This happens for \K lookaround. We fail if used.
			// See pcre2demo.c for details.
			RZ_LOG_ERROR("Usage of \\K to set start of the pattern later than the end, is not implemented.\n");
			goto fini;
		}

		// Offset and length of match
		RzRegexMatch *match = RZ_NEW0(RzRegexMatch);
		match->start = ovector[2 * i];
		match->len = ovector[2 * i + 1] - match->start;
		match->group_idx = i;
		nametable_ptr32 += name_entry_size;
		rz_pvector_push(matches, match);
	}

fini:
	rz_regex_match_data_free(mdata);
	pcre2_match_context_free_32(mcontext);
	return matches;
}

/**
 * \brief Finds the first match in a text and returns it as a pvector.
 * First element in the vector is always the whole match, the following possible groups.
 *
 * \param regex The regex pattern to match.
 * \param text The text to search in.
 * \param text_size The length of the buffer pointed to by \p text.
 *        Can be set to RZ_REGEX_ZERO_TERMINATED if the buffer is a zero terminated string.
 * \param text_offset The offset into \p text from where the search starts.
 * \param mflags Match flags.
 *
 * \return The matches as pvector. NULL in case of failure. Empty for no matches or regex related errors.
 */
RZ_API RZ_OWN RzPVector /*<RzRegexMatch *>*/ *rz_regex_match_first(
	RZ_NONNULL const RzRegex *regex,
	RZ_NONNULL const char *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags) {
	rz_return_val_if_fail(regex && text, NULL);
	return match_first_8(
		regex,
		(ut8 *)text,
		text_size,
		text_offset,
		mflags, NULL);
}

/**
 * \brief Finds the first match in a UTF-16 text and returns it as a pvector.
 * First element in the vector is always the whole match, the following possible groups.
 *
 * NOTE: This matches against UTF-16 host's endianness strings.
 *
 * \param regex The regex pattern to match.
 * \param text The text to search in. It should be UTF-16 (host-endianness) encoded.
 * \param text_size The length of the buffer pointed to by \p text in code units.
 *        Can be set to RZ_REGEX_ZERO_TERMINATED if the buffer is a zero terminated string.
 * \param text_offset The offset into \p text from where the search starts in code units.
 * \param mflags Match flags.
 *
 * \return The matches as pvector. NULL in case of failure. Empty for no matches or regex related errors.
 */
RZ_API RZ_OWN RzPVector /*<RzRegexMatch *>*/ *rz_regex_match_first_16(
	RZ_NONNULL const RzRegex16 *regex,
	RZ_NONNULL const ut16 *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags) {
	rz_return_val_if_fail(regex && text, NULL);
	return match_first_16(
		regex,
		text,
		text_size,
		text_offset,
		mflags, NULL);
}

/**
 * \brief Finds the first match in a UTF-32 text and returns it as a pvector.
 * First element in the vector is always the whole match, the following possible groups.
 *
 * NOTE: This matches against UTF-32 host's endianness strings.
 *
 * \param regex The regex pattern to match.
 * \param text The text to search in. It should be UTF-32 (host-endianness) encoded.
 * \param text_size The length of the buffer pointed to by \p text in code units.
 *        Can be set to RZ_REGEX_ZERO_TERMINATED if the buffer is a zero terminated string.
 * \param text_offset The offset into \p text from where the search starts in code units.
 * \param mflags Match flags.
 *
 * \return The matches as pvector. NULL in case of failure. Empty for no matches or regex related errors.
 */
RZ_API RZ_OWN RzPVector /*<RzRegexMatch *>*/ *rz_regex_match_first_32(
	RZ_NONNULL const RzRegex32 *regex,
	RZ_NONNULL const ut32 *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags) {
	rz_return_val_if_fail(regex && text, NULL);
	return match_first_32(
		regex,
		text,
		text_size,
		text_offset,
		mflags, NULL);
}

/**
 * \brief Finds all matches in a text and returns them as vector.
 * The result is a flat vector of matches. A single match with multiple
 * groups is simply appeneded to the resulting vector.
 *
 * \param regex The regex pattern to match.
 * \param text The text to search in.
 * \param text_size The length of the buffer pointed to by \p text.
 *        Can be set to RZ_REGEX_ZERO_TERMINATED if the buffer is a zero terminated string.
 * \param text_offset The offset into \p text from where the search starts.
 * \param mflags Match flags.
 *
 * \return A vector of all matches or NULL in case of failure.
 * Sub-groups of a match are appended after their main match.
 */
RZ_API RZ_OWN RzPVector /*<RzRegexMatch *>*/ *rz_regex_match_all_not_grouped(
	RZ_NONNULL const RzRegex *regex,
	RZ_NONNULL const char *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags) {
	rz_return_val_if_fail(regex && text, NULL);

	RzPVector *all_matches = rz_pvector_new(free);
	RzPVector *matches = rz_regex_match_first(regex, text, text_size, text_offset, mflags);
	while (matches && rz_pvector_len(matches) > 0) {
		RzRegexMatch *whole_match = rz_pvector_head(matches);
		text_offset = whole_match->start + whole_match->len;

		size_t mlen = rz_pvector_len(matches);
		for (size_t i = 0; i < mlen; ++i) {
			RzRegexMatch *m = rz_pvector_pop_front(matches);
			rz_pvector_push(all_matches, m);
		}
		rz_pvector_free(matches);
		// Search again after the whole first match.
		matches = rz_regex_match_first(regex, text, text_size, text_offset, mflags);
	}

	// Free last vector without matches.
	rz_pvector_free(matches);
	return all_matches;
}

static RZ_OWN RzPVector /*<RzVector<RzRegexMatch *> *>*/ *match_all_internal_8(
	RZ_NONNULL const RzRegex *regex,
	RZ_NONNULL const ut8 *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags,
	bool allow_overlap,
	RZ_NULLABLE void *jit_stack) {
	rz_return_val_if_fail(regex && text, NULL);

	RzPVector *all_matches = rz_pvector_new((RzPVectorFree)rz_pvector_free);
	RzPVector *matches = NULL;
	matches = match_first_8(regex, text, text_size, text_offset, mflags, jit_stack);
	while (matches && rz_pvector_len(matches) > 0) {
		rz_pvector_push(all_matches, matches);
		RzRegexMatch *m = rz_pvector_head(matches);
		// Search again after the last match.
		text_offset = allow_overlap ? m->start + 1 : m->start + m->len;
		matches = match_first_8(regex, text, text_size, text_offset, mflags, jit_stack);
	}

	// Free last vector without matches.
	rz_pvector_free(matches);
	return all_matches;
}

static RZ_OWN RzPVector /*<RzVector<RzRegexMatch *> *>*/ *match_all_internal_16(
	RZ_NONNULL const RzRegex *regex,
	RZ_NONNULL const ut16 *text,
	RzRegexSize text_size_code_units,
	RzRegexSize text_offset_code_units,
	RzRegexFlags mflags,
	bool allow_overlap,
	RZ_NULLABLE void *jit_stack) {
	rz_return_val_if_fail(regex && text, NULL);

	RzPVector *all_matches = rz_pvector_new((RzPVectorFree)rz_pvector_free);
	RzPVector *matches = NULL;
	matches = match_first_16(regex, text, text_size_code_units, text_offset_code_units, mflags, jit_stack);
	while (matches && rz_pvector_len(matches) > 0) {
		rz_pvector_push(all_matches, matches);
		RzRegexMatch *m = rz_pvector_head(matches);
		// Search again after the last match.
		text_offset_code_units = allow_overlap ? m->start + 1 : m->start + m->len;
		matches = match_first_16(regex, text, text_size_code_units, text_offset_code_units, mflags, jit_stack);
	}

	// Free last vector without matches.
	rz_pvector_free(matches);
	return all_matches;
}

static RZ_OWN RzPVector /*<RzVector<RzRegexMatch *> *>*/ *match_all_internal_32(
	RZ_NONNULL const RzRegex *regex,
	RZ_NONNULL const ut32 *text,
	RzRegexSize text_size_code_units,
	RzRegexSize text_offset_code_units,
	RzRegexFlags mflags,
	bool allow_overlap,
	RZ_NULLABLE void *jit_stack) {
	rz_return_val_if_fail(regex && text, NULL);

	RzPVector *all_matches = rz_pvector_new((RzPVectorFree)rz_pvector_free);
	RzPVector *matches = NULL;
	matches = match_first_32(regex, text, text_size_code_units, text_offset_code_units, mflags, jit_stack);
	while (matches && rz_pvector_len(matches) > 0) {
		rz_pvector_push(all_matches, matches);
		RzRegexMatch *m = rz_pvector_head(matches);
		// Search again after the last match.
		text_offset_code_units = allow_overlap ? m->start + 1 : m->start + m->len;
		matches = match_first_32(regex, text, text_size_code_units, text_offset_code_units, mflags, jit_stack);
	}

	// Free last vector without matches.
	rz_pvector_free(matches);
	return all_matches;
}

/**
 * \brief Finds all matches in a text and returns them as vector of vector matches.
 *
 * \param pattern The regex pattern to match.
 * \param text The text to search in.
 * \param text_size The length of the buffer pointed to by \p text.
 *        Can be set to RZ_REGEX_ZERO_TERMINATED if the buffer is a zero terminated string.
 * \param text_offset The offset into \p text from where the search starts.
 * \param mflags Match flags.
 * \param allow_overlap If true it will match also overlapping patterns.
 *
 * \return PVector of every match in the given string or NULL in case of failure.
 *         One match with all its groups is again assembled in a pvector.
 */
RZ_API RZ_OWN RzPVector /*<RzVector<RzRegexMatch *> *>*/ *rz_regex_match_all_overlap(
	RZ_NONNULL const RzRegex *regex,
	RZ_NONNULL const char *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags) {
	return match_all_internal_8(regex, (ut8 *)text, text_size, text_offset, mflags, true, NULL);
}

/**
 * \brief Finds all matches in a text and returns them as vector of vector matches.
 *
 * \param pattern The regex pattern to match.
 * \param text The text to search in.
 * \param text_size The length of the buffer pointed to by \p text.
 *        Can be set to RZ_REGEX_ZERO_TERMINATED if the buffer is a zero terminated string.
 * \param text_offset The offset into \p text from where the search starts.
 * \param mflags Match flags.
 *
 * \return PVector of every match in the given string or NULL in case of failure.
 *         One match with all its groups is again assembled in a pvector.
 */
RZ_API RZ_OWN RzPVector /*<RzVector<RzRegexMatch *> *>*/ *rz_regex_match_all(
	RZ_NONNULL const RzRegex *regex,
	RZ_NONNULL const char *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags) {
	return match_all_internal_8(regex, (ut8 *)text, text_size, text_offset, mflags, false, NULL);
}

/**
 * \brief Finds all matches in a text and returns them as vector of vector matches.
 *
 * NOTE: This matches against UTF-16 host's endianness strings.
 *
 * \param pattern The regex pattern to match.
 * \param text The text to search in. It should be UTF-16 host-endianness encoded.
 * \param text_size The length of the buffer pointed to by \p text in code units..
 *        Can be set to RZ_REGEX_ZERO_TERMINATED if the buffer is a zero terminated string.
 * \param text_offset The offset into \p text from where the search starts in code units..
 * \param mflags Match flags.
 * \param allow_overlap If true it will match also overlapping patterns.
 *
 * \return PVector of every match in the given string or NULL in case of failure.
 *         One match with all its groups is again assembled in a pvector.
 */
RZ_API RZ_OWN RzPVector /*<RzVector<RzRegexMatch *> *>*/ *rz_regex_match_all_overlap_16(
	RZ_NONNULL const RzRegex16 *regex,
	RZ_NONNULL const ut16 *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags) {
	return match_all_internal_16(regex, text, text_size, text_offset, mflags, true, NULL);
}

/**
 * \brief Finds all matches in a text and returns them as vector of vector matches.
 *
 * NOTE: This matches against UTF-16 host's endianness strings.
 *
 * \param pattern The regex pattern to match.
 * \param text The text to search in. It should be UTF-16 host-endianness encoded.
 * \param text_size The length of the buffer pointed to by \p text in code units..
 *        Can be set to RZ_REGEX_ZERO_TERMINATED if the buffer is a zero terminated string.
 * \param text_offset The offset into \p text from where the search starts in code units..
 * \param mflags Match flags.
 *
 * \return PVector of every match in the given string or NULL in case of failure.
 *         One match with all its groups is again assembled in a pvector.
 */
RZ_API RZ_OWN RzPVector /*<RzVector<RzRegexMatch *> *>*/ *rz_regex_match_all_16(
	RZ_NONNULL const RzRegex16 *regex,
	RZ_NONNULL const ut16 *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags) {
	return match_all_internal_16(regex, text, text_size, text_offset, mflags, false, NULL);
}

/**
 * \brief Finds all matches in a text and returns them as vector of vector matches.
 *
 * NOTE: This matches against UTF-32 host's endianness strings.
 *
 * \param pattern The regex pattern to match.
 * \param text The text to search in. It should be UTF-32 host-endianness encoded.
 * \param text_size The length of the buffer pointed to by \p text in code units..
 *        Can be set to RZ_REGEX_ZERO_TERMINATED if the buffer is a zero terminated string.
 * \param text_offset The offset into \p text from where the search starts in code units..
 * \param mflags Match flags.
 * \param allow_overlap If true it will match also overlapping patterns.
 *
 * \return PVector of every match in the given string or NULL in case of failure.
 *         One match with all its groups is again assembled in a pvector.
 */
RZ_API RZ_OWN RzPVector /*<RzVector<RzRegexMatch *> *>*/ *rz_regex_match_all_overlap_32(
	RZ_NONNULL const RzRegex32 *regex,
	RZ_NONNULL const ut32 *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags) {
	return match_all_internal_32(regex, text, text_size, text_offset, mflags, true, NULL);
}

/**
 * \brief TODO: Note that size and offset are in bytes. Not code points.
 */
RZ_API RZ_OWN RzPVector /*<RzVector<RzRegexMatch *> *>*/ *rz_regex_match_all_overlap_multi(
	RZ_NONNULL const RzRegexMulti *regex,
	RZ_NONNULL const ut8 *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags) {
	switch (regex->re_type) {
	case RZ_REGEX_UTF8:
		return match_all_internal_8(regex->re8, (ut8 *)text, text_size, text_offset, mflags, true, regex->jit_stack);
	case RZ_REGEX_UTF16:
		return match_all_internal_16(regex->re16, (ut16 *)text, text_size / RZ_UTF16_CODE_POINT_WIDTH, text_offset / RZ_UTF16_CODE_POINT_WIDTH, mflags, true, regex->jit_stack);
	case RZ_REGEX_UTF32:
		return match_all_internal_32(regex->re32, (ut32 *)text, text_size / RZ_UTF32_CODE_POINT_WIDTH, text_offset / RZ_UTF32_CODE_POINT_WIDTH, mflags, true, regex->jit_stack);
	}
	rz_warn_if_reached();
	return NULL;
}

RZ_API RZ_OWN RzPVector /*<RzVector<RzRegexMatch *> *>*/ *rz_regex_match_all_multi(
	RZ_NONNULL const RzRegexMulti *regex,
	RZ_NONNULL const ut8 *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags) {
	switch (regex->re_type) {
	case RZ_REGEX_UTF8:
		return match_all_internal_8(regex->re8, (ut8 *)text, text_size, text_offset, mflags, false, regex->jit_stack);
	case RZ_REGEX_UTF16:
		return match_all_internal_16(regex->re16, (ut16 *)text, text_size / RZ_UTF16_CODE_POINT_WIDTH, text_offset / RZ_UTF16_CODE_POINT_WIDTH, mflags, false, regex->jit_stack);
	case RZ_REGEX_UTF32:
		return match_all_internal_32(regex->re32, (ut32 *)text, text_size / RZ_UTF32_CODE_POINT_WIDTH, text_offset / RZ_UTF32_CODE_POINT_WIDTH, mflags, false, regex->jit_stack);
	}
	rz_warn_if_reached();
	return NULL;
}

/**
 * \brief Finds all matches in a text and returns them as vector of vector matches.
 *
 * NOTE: This matches against UTF-32 host's endianness strings.
 *
 * \param pattern The regex pattern to match.
 * \param text The text to search in. It should be UTF-32 host-endianness encoded.
 * \param text_size The length of the buffer pointed to by \p text in code units..
 *        Can be set to RZ_REGEX_ZERO_TERMINATED if the buffer is a zero terminated string.
 * \param text_offset The offset into \p text from where the search starts in code units..
 * \param mflags Match flags.
 *
 * \return PVector of every match in the given string or NULL in case of failure.
 *         One match with all its groups is again assembled in a pvector.
 */
RZ_API RZ_OWN RzPVector /*<RzVector<RzRegexMatch *> *>*/ *rz_regex_match_all_32(
	RZ_NONNULL const RzRegex32 *regex,
	RZ_NONNULL const ut32 *text,
	RzRegexSize text_size,
	RzRegexSize text_offset,
	RzRegexFlags mflags) {
	return match_all_internal_32(regex, text, text_size, text_offset, mflags, false, NULL);
}

/**
 * \brief Checks if \p pattern can be found in \p text.
 *
 * \param pattern The regex pattern to match.
 * \param text The text to search in.
 * \param text_size The length of the buffer pointed to by \p text.
 *        Can be set to RZ_REGEX_ZERO_TERMINATED if the buffer is a zero terminated string.
 * \param text_offset The offset into \p text from where the search starts.
 * \param cflags Compile flags.
 * \param mflags Match flags.
 *
 * \return true if the text contains the patterns.
 * \return false Otherwise
 */
RZ_API bool rz_regex_contains(RZ_NONNULL const char *pattern, RZ_NONNULL const char *text,
	RzRegexSize text_size,
	RzRegexFlags cflags, RzRegexFlags mflags) {
	RzRegex *re = rz_regex_new(pattern, cflags, 0, NULL);
	if (!re) {
		return false;
	}
	RzPVector *matches = rz_regex_match_first(re, text, text_size, 0, mflags);
	bool found = matches != NULL && !rz_pvector_empty(matches);
	rz_pvector_free(matches);
	rz_regex_free(re);
	return found;
}

/**
 * \brief Searches for a \p pattern in \p text and returns all matches as concatenated string.
 * Only complete matches are concatenated. Sub-groups are skipped.
 *
 * \param pattern The regex pattern to match.
 * \param text The text to search in.
 * \param text_size The length of the buffer pointed to by \p text.
 *        Can be set to RZ_REGEX_ZERO_TERMINATED if the buffer is a zero terminated string.
 * \param cflags Compile flags.
 * \param mflags Match flags.
 * \param separator A string to separate the matches.
 *
 * \return A string with all matches concatenated or NULL in case of failure.
 */
RZ_API RZ_OWN RzStrBuf *rz_regex_full_match_str(RZ_NONNULL const char *pattern, RZ_NONNULL const char *text,
	RzRegexSize text_size,
	RzRegexFlags cflags, RzRegexFlags mflags, RZ_NONNULL const char *separator) {
	rz_return_val_if_fail(pattern && text && separator, NULL);

	RzRegex *re = rz_regex_new(pattern, cflags, 0, NULL);
	RzStrBuf *sbuf = rz_strbuf_new("");
	RzPVector *matches = rz_regex_match_all(re, text, text_size, 0, mflags);
	if (!matches || !sbuf) {
		goto fini;
	}

	size_t i = 1;
	void **m;
	rz_pvector_foreach (matches, m) {
		RzPVector *match_groups = *m;
		RzRegexMatch *match = rz_pvector_head(match_groups);
		const char *t = text + match->start;
		if (((int)match->len) < 0) {
			goto fini;
		}
		// No separator in case of only one match
		if (i == rz_pvector_len(matches)) {
			rz_strbuf_appendf(sbuf, "%-.*s", (int)match->len, t);
		} else if (!rz_strbuf_appendf(sbuf, "%-.*s%s", (int)match->len, t, separator)) {
			goto fini;
		}
		++i;
	}

fini:
	rz_regex_free(re);
	rz_pvector_free(matches);
	return sbuf;
}

/**
 * \brief Searches for the given \p pattern in \p text and
 * returns an byte offset into the string where the pattern was found.
 *
 * \param pattern The regex pattern to match.
 * \param text The text to search in.
 * \param text_size The length of the buffer pointed to by \p text.
 *        Can be set to RZ_REGEX_ZERO_TERMINATED if the buffer is a zero terminated string.
 * \param text_offset The offset into \p text from where the search starts.
 * \param cflags Compile flags.
 * \param mflags Match flags.
 *
 * \return Offset into the string, or SZT_MAX if pattern was not found.
 */
RZ_API RzRegexSize rz_regex_find(RZ_NONNULL const char *pattern, RZ_NONNULL RZ_BORROW char *text,
	RzRegexSize text_size, RzRegexSize text_offset,
	RzRegexFlags cflags, RzRegexFlags mflags) {
	rz_return_val_if_fail(pattern && text, SZT_MAX);
	RzRegex *regex = rz_regex_new(pattern, cflags, RZ_REGEX_DEFAULT, NULL);
	RzPVector *matches = rz_regex_match_first(regex, text, text_size, text_offset, mflags);
	if (rz_pvector_empty(matches)) {
		rz_pvector_free(matches);
		rz_regex_free(regex);
		return SZT_MAX;
	}
	RzRegexSize off = ((RzRegexMatch *)rz_pvector_head(matches))->start;
	rz_pvector_free(matches);
	rz_regex_free(regex);
	return off;
}

/**
 * \brief Returns a compile context.
 *
 * \return A PCRE2 compile context, or NULL in case of failure.
 */
RZ_API RZ_OWN RzRegexCompContext *rz_regex_compile_context_new() {
	return pcre2_compile_context_create_8(NULL);
}

/**
 * \brief Frees a compile context.
 *
 * \param A PCRE2 compile context.
 */
RZ_API void rz_regex_compile_context_free(RzRegexCompContext *ccontext) {
	pcre2_compile_context_free_8(ccontext);
}

/**
 * \brief Sets the newline convention of a compile context to the NUL character (\0).
 *
 * \param A PCRE2 compile context.
 */
RZ_API void rz_regex_set_nul_as_newline(RZ_NONNULL RzRegexCompContext *ccontext) {
	pcre2_set_newline_8(ccontext, PCRE2_NEWLINE_NUL);
}

/**
 * \brief Parses a string with regex flags characters and returns the numerical
 * value of it.
 *
 * - ''/NULL/'r' - Default: RZ_REGEX_DEFAULT
 * - 'l'         - RZ_REGEX_LITERAL
 * - 'i'         - RZ_REGEX_CASELESS
 * - 'e'         - RZ_REGEX_EXTENDED
 * - 'E'         - RZ_REGEX_EXTENDED_MORE
 * - 'm'         - RZ_REGEX_MULTILINE
 *
 * \param re_flags_desc The string containing several characters.
 *
 * \return The flags as numerical value. Or ~RZ_REGEX_DEFAULT if flags are invalid.
 *
 * Examples:
 *
 * - "ri"  => RZ_REGEX_DEFAULT | RZ_REGEX_CASELESS
 * - "li"  => RZ_REGEX_LITERAL | RZ_REGEX_CASELESS
 * - "Eim" => RZ_REGEX_EXTENDED | RZ_REGEX_CASELESS | RZ_REGEX_MULTILINE
 * - "rl"  => ~RZ_REGEX_DEFAULT => Error: Flag combination is invalid.
 * - "xX"  => ~RZ_REGEX_DEFAULT => Error: Flag combination is invalid.
 */
RZ_API RzRegexFlags rz_regex_parse_flag_desc(RZ_NULLABLE const char *re_flags_desc) {
	RzRegexFlags flags = RZ_REGEX_DEFAULT;
	if (RZ_STR_ISEMPTY(re_flags_desc)) {
		return flags;
	}
	size_t fcount = 0;
	if (strchr(re_flags_desc, 'i')) {
		fcount++;
		flags |= RZ_REGEX_CASELESS;
	}
	if (strchr(re_flags_desc, 'l')) {
		fcount++;
		flags |= RZ_REGEX_LITERAL;
		goto return_flags;
	}
	if (strchr(re_flags_desc, 'r')) {
		fcount++;
		goto return_flags;
	}
	if (strchr(re_flags_desc, 'e')) {
		fcount++;
		flags |= RZ_REGEX_EXTENDED;
	}
	if (strchr(re_flags_desc, 'E')) {
		fcount++;
		flags |= RZ_REGEX_EXTENDED_MORE;
	}
	if (strchr(re_flags_desc, 'm')) {
		fcount++;
		flags |= RZ_REGEX_MULTILINE;
	}
	if (strchr(re_flags_desc, 'd')) {
		fcount++;
		flags |= RZ_REGEX_DOTALL;
	}
return_flags:
	if (fcount != strlen(re_flags_desc)) {
		RZ_LOG_ERROR("Flag combination '%s' is invalid.\n", re_flags_desc);
		return ~RZ_REGEX_DEFAULT;
	}
	return flags;
}

/**
 * \brief The string characters in binary files.
 * The characters matched with this pattern are assumed to belong to
 * single string.
 * Any character not matching this pattern is assumed to end a string.
 * Note: A new line is a valid character within a string.
 */
#define RZ_REGEX_STR_WILDARD "[\\w\\e\\pS\\s\\n\\r\\pP]"

/**
 * \brief Returns a Regex pattern of the form "[\w\e\pS\s\n\r\pP]{min_len, max_len}".
 *
 * If min_len == max_len == 0, the function returns "[\w\e\pS\s\n\r\pP]*".
 * If min_len > max_len, the function returns "[\w\e\pS\s\n\r\pP]{min_len,}".
 *
 * \param min_len The minimum length of the wildcard regex pattern.
 * \param max_len The maximum length of the wildcard regex pattern.
 *
 * \return The pattern or NULL in case of failure.
 */
RZ_API RZ_OWN char *rz_regex_create_wildcard_pattern(size_t min_len, size_t max_len) {
	if (min_len == 0 && max_len == 0) {
		return rz_str_dup(RZ_REGEX_STR_WILDARD "*");
	} else if (min_len > max_len) {
		return rz_str_newf(RZ_REGEX_STR_WILDARD "{%" PFMTSZd ",}", min_len);
	}
	return rz_str_newf(RZ_REGEX_STR_WILDARD "{%" PFMTSZd ",%" PFMTSZd "}", min_len, max_len);
}
