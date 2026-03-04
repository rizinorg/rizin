// SPDX-FileCopyrightText: 2026 Ehab-24 <ehabs1775@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <wctype.h>
#include "i/private.h"

static bool is_word_constituent(RzCodePoint cp) {
	return iswalnum((wint_t)cp);
}

static char *unicode_mapping_append_to_buf(RZ_NONNULL const RzUnicodeCaseMapping *um, RZ_NONNULL char *p, RZ_NONNULL const char *end) {
	rz_return_val_if_fail(um && p && end, NULL);
	if (rz_unicode_case_mapping_is_empty(um)) {
		const size_t len = rz_utf8_encode((ut8 *)p, um->key);
		if (len > 0) {
			if ((size_t)(end - p) < len) {
				return NULL;
			}
			p += len;
		}
	} else {
		for (int j = 0; j < 3; ++j) {
			RzCodePoint v = um->val[j];
			if (v == 0) {
				continue;
			}
			const size_t len = rz_utf8_encode((ut8 *)p, v);
			if (len < 1) {
				continue;
			}
			if ((size_t)(end - p) < len) {
				return NULL;
			}
			p += len;
		}
	}
	return p;
}

/**
 * \brief Convert a vector of RzUnicodeCaseMapping to an encoded UTF-8 string.
 * NOTE: Empty mappings are encoded using their `key` insted of value(s).
 *
 * \param map RzVector <RzUnicodeCaseMapping>.
 * \param maxlen The length of encoded string in bytes.
 *
 * \return Encoded UTF-8 (null-terminated) string.
 */
static RZ_OWN RZ_NULLABLE char *unicode_mapping_to_str(RZ_NONNULL RzUnicodeCaseMappings *map, size_t utf8_len) {
	rz_return_val_if_fail(map, NULL);
	char *utf8_buf = RZ_NEWS0(char, utf8_len + 1);
	if (!utf8_buf) {
		return NULL;
	}

	void *it;
	char *ptr = utf8_buf;
	char *const endptr = utf8_buf + utf8_len;
	rz_vector_foreach (map, it) {
		const RzUnicodeCaseMapping *um = (RzUnicodeCaseMapping *)it;
		ptr = unicode_mapping_append_to_buf(um, ptr, endptr);
		if (!ptr) {
			RZ_FREE(utf8_buf);
			return NULL;
		}
	}
	return utf8_buf;
}

/**
 * \brief Find index of the first (unicode) character in the following word in \p buffer.
 */
static ssize_t emacs_mode_find_word_start(RZ_NONNULL const RzCodePoints *buffer, ssize_t start) {
	rz_return_val_if_fail(buffer && rz_vector_len(buffer), -1);
	while (start < rz_vector_len(buffer)) {
		const RzCodePoint *cp = rz_vector_index_ptr(buffer, start);
		if (is_word_constituent(*cp)) {
			break;
		}
		++start;
	}
	return start;
}

/**
 * \brief Find index of the last (unicode) character in the following word in \p buffer.
 */
static ssize_t emacs_mode_find_word_end(RZ_NONNULL const RzCodePoints *buffer, ssize_t start) {
	rz_return_val_if_fail(buffer && rz_vector_len(buffer), -1);
	ssize_t end = RZ_MIN(start + 1, rz_vector_len(buffer));
	while (end < rz_vector_len(buffer)) {
		const RzCodePoint *cp = rz_vector_index_ptr(buffer, end);
		if (!is_word_constituent(*cp)) {
			break;
		}
		++end;
	}
	return end;
}

/**
 * \brief Find the starting byte index of a unicode code point in \p buffer.
 *
 * \param buffer RzVector <RzUnicodePoint>.
 * \param cp_index Index of the unicode code point.
 *
 * \return ssize_t -1 in case of failure.
 */
static ssize_t emacs_mode_find_byte_index(RZ_NONNULL const RzCodePoints *buffer, size_t cp_index) {
	rz_return_val_if_fail(cp_index <= rz_vector_len(buffer), -1);
	ssize_t bytei = 0;
	for (size_t i = 0; i < cp_index; ++i) {
		const RzCodePoint *cp = rz_vector_index_ptr(buffer, i);
		const size_t len = rz_utf8_byte_length(*cp);
		bytei += len ? len : 1;
	}
	return bytei;
}

/**
 * \brief Capitalize the current or next word in \p buffer.
 *
 * \param buffer RzVector <RzCodePoint>.
 * \param start Starting index of the word in \p buffer.
 * \param end Ending index of the word in \p buffer.
 * \param utf8_len Number of bytes between \p start (inclusive) and \p end (exclusive) in \p buffer.
 *
 * \return Capitalized word as UTF-8 encoded (null-terminated) string.
 */
static RZ_OWN RZ_NULLABLE char *emacs_mode_capitalize(RZ_NONNULL const RzCodePoints *buffer, ssize_t start, ssize_t end, size_t utf8_len) {
	rz_return_val_if_fail(buffer && rz_vector_len(buffer) > 0 && utf8_len > 0 && start <= end && end <= rz_vector_len(buffer), NULL);

	RzUnicodeCaseMappings *map = rz_vector_new(sizeof(RzUnicodeCaseMapping), NULL, NULL);
	ssize_t i = start;
	for (; i < end; ++i) {
		const RzCodePoint *cp = rz_vector_index_ptr(buffer, i);
		if (iswalpha((wint_t)(*cp))) {
			RzUnicodeCaseMapping um = rz_unicode_code_point_find_upper(*cp);
			rz_vector_push(map, &um);
			break;
		} else {
			RzUnicodeCaseMapping um = rz_unicode_case_mapping_default(*cp);
			rz_vector_push(map, &um);
		}
	}
	for (++i; i < end; ++i) {
		const RzCodePoint *cp = rz_vector_index_ptr(buffer, i);
		RzUnicodeCaseMapping um = rz_unicode_code_point_find_lower(*cp);
		rz_vector_push(map, &um);
	}

	char *utf8_buf = unicode_mapping_to_str(map, utf8_len);
	rz_vector_free(map);
	return utf8_buf;
}

/**
 * \brief Lowercase the current or next word in \p buffer.
 *
 * \param buffer RzVector <RzCodePoint>.
 * \param start Starting index of the word in \p buffer.
 * \param end Ending index of the word in \p buffer.
 * \param utf8_len Number of bytes between \p start (inclusive) and \p end (exclusive) in \p buffer.
 *
 * \return Lowercase word as UTF-8 encoded (null-terminated) string.
 */
static char *emacs_mode_tolower(RZ_NONNULL const RzCodePoints *buffer, ssize_t start, ssize_t end, size_t utf8_len) {
	rz_return_val_if_fail(buffer && rz_vector_len(buffer) > 0 && utf8_len > 0 && start <= end && end <= rz_vector_len(buffer), NULL);

	RzVector *map = rz_vector_new(sizeof(RzUnicodeCaseMapping), NULL, NULL);
	for (ssize_t i = start; i < end; ++i) {
		const RzCodePoint *cp = rz_vector_index_ptr(buffer, i);
		RzUnicodeCaseMapping um = rz_unicode_code_point_find_lower(*cp);
		rz_vector_push(map, &um);
	}

	char *utf8_buf = unicode_mapping_to_str(map, utf8_len);
	rz_vector_free(map);
	return utf8_buf;
}

/**
 * \brief Uppercase the current or next word in \p buffer.
 *
 * \param buffer RzVector <RzCodePoint>.
 * \param start Starting index of the word in \p buffer.
 * \param end Ending index of the word in \p buffer.
 * \param utf8_len Number of bytes between \p start (inclusive) and \p end (exclusive) in \p buffer.
 *
 * \return Uppercase word as UTF-8 encoded (null-terminated) string.
 */
static RZ_OWN RZ_NULLABLE char *emacs_mode_toupper(RZ_NONNULL const RzCodePoints *buffer, ssize_t start, ssize_t end, size_t utf8_len) {
	rz_return_val_if_fail(buffer && rz_vector_len(buffer) > 0 && utf8_len > 0 && start <= end && end <= rz_vector_len(buffer), NULL);

	RzVector *map = rz_vector_new(sizeof(RzUnicodeCaseMapping), NULL, NULL);
	for (ssize_t i = start; i < end; ++i) {
		const RzCodePoint *cp = rz_vector_index_ptr(buffer, i);
		RzUnicodeCaseMapping um = rz_unicode_code_point_find_upper(*cp);
		rz_vector_push(map, &um);
	}

	char *utf8_buf = unicode_mapping_to_str(map, utf8_len);
	rz_vector_free(map);
	return utf8_buf;
}

/**
 * \brief Decode a UTF-8 encoded string as a vector of RzCodePoint into \p out.
 *
 * \param buf The UTF-8 encoded string.
 * \param buflen Length of \p buf.
 * \param out RzVector <RzCodePoint>.
 *
 * \return false on failure.
 */
static bool utf8_decode_buf(const ut8 *buf, size_t buflen, RZ_NONNULL RzCodePoints *out) {
	rz_return_val_if_fail(out, false);
	for (size_t i = 0; i < buflen;) {
		RzCodePoint cp;
		const size_t len = rz_utf8_decode(buf + i, buflen - i, &cp, false);
		void *elem = rz_vector_push(out, &cp);
		if (!elem) {
			return false;
		}
		i += len ? len : 1;
	}
	return true;
}

static bool emacs_mode_modify_one(RzEmacsModeModifyOp op, RZ_NONNULL RzLine *line, RZ_NONNULL const RzCodePoints *cpbuffer, ssize_t start, size_t end) {
	rz_return_val_if_fail(line && cpbuffer && start >= 0 && end >= 0, false);
	const ssize_t start_byte = emacs_mode_find_byte_index(cpbuffer, start);
	const ssize_t end_byte = emacs_mode_find_byte_index(cpbuffer, end);
	if (start_byte == -1 || end_byte == -1) {
		return false;
	}

	char *mword = NULL; ///< The modified word
	switch (op) {
	default:
		rz_return_val_if_reached(false);
	case EMACS_MODIFY_CAPITALIZE:
		mword = emacs_mode_capitalize(cpbuffer, start, end, end_byte - start_byte);
		break;
	case EMACS_MODIFY_TOLOWER:
		mword = emacs_mode_tolower(cpbuffer, start, end, end_byte - start_byte);
		break;
	case EMACS_MODIFY_TOUPPER:
		mword = emacs_mode_toupper(cpbuffer, start, end, end_byte - start_byte);
		break;
	}

	if (!mword) {
		return false;
	}
	char *p = line->buffer.data + start_byte;
	memcpy(p, mword, end_byte - start_byte);
	RZ_FREE(mword);
	return true;
}

/**
 * \brief Capitalizes/lowercases/uppercases the current or next word(s).
 * Note: Optionally sets the cursor position to the end of the last word.
 *
 * \param opts The modify options
 * \param line RzLine
 *
 * \return false on failure
 */
RZ_IPI bool rz_emacs_mode_modify(RZ_NONNULL RzEmacsModeModifyOpts *opts, RZ_NONNULL RzLine *line) {
	rz_return_val_if_fail(line && opts, false);
	if (line->buffer.length < 1) {
		return true;
	}

	RzCodePoints *cpbuffer = rz_vector_new(sizeof(RzCodePoint), NULL, NULL);
	const ut8 *line_buf = (ut8 *)line->buffer.data;
	const bool decoded = utf8_decode_buf(line_buf, line->buffer.length, cpbuffer);
	if (!decoded || rz_vector_len(cpbuffer) < 1) {
		goto cleanup_and_exit;
	}

	const size_t word_count = opts->word_count_provided ? opts->word_count : 1;
	const size_t utf8_index = rz_utf8_strnlen(line_buf, line->buffer.index);

	ssize_t start = 0, end = 0; ///< index of first/last unicode code point in the current word
	start = emacs_mode_find_word_start(cpbuffer, utf8_index);
	end = emacs_mode_find_word_end(cpbuffer, start);
	for (size_t wi = 0; wi < word_count && start < end; ++wi) {
		if (start == -1 || end == -1) {
			goto cleanup_and_exit;
		}
		const bool failed = !emacs_mode_modify_one(opts->op, line, cpbuffer, start, end);
		if (failed) {
			goto cleanup_and_exit;
		}
		if (opts->move_cursor) {
			line->buffer.index = emacs_mode_find_byte_index(cpbuffer, end);
		}
		start = emacs_mode_find_word_start(cpbuffer, end);
		end = emacs_mode_find_word_end(cpbuffer, start);
	}
	rz_vector_free(cpbuffer);
	return true;

cleanup_and_exit:
	rz_vector_free(cpbuffer);
	return false;
}

/**
 * \brief Reset \p opts to their default state.
 *
 * \param opts The modify options.
 */
RZ_IPI void rz_emacs_mode_modify_opts_reset(RZ_NONNULL RzEmacsModeModifyOpts *opts) {
	rz_return_if_fail(opts);
	opts->move_cursor = true;
	opts->word_count_provided = false;
	opts->word_count = 0;
}
