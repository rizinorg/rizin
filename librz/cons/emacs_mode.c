// SPDX-FileCopyrightText: 2026 Ehab-24 <ehabs1775@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <wctype.h>
#include "i/private.h"

static bool is_word_constituent(RzCodePoint cp) {
	return iswalnum((wint_t)cp);
}

static bool is_word_constituent_index(const RzCodePoints *buffer, size_t index) {
	if (index >= rz_vector_len(buffer)) {
		return false;
	}
	RzCodePoint *cp = rz_vector_index_ptr(buffer, index);
	return is_word_constituent(*cp);
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
static size_t emacs_mode_find_word_start(RZ_NONNULL const RzCodePoints *buffer, size_t start) {
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
static size_t emacs_mode_find_word_end(RZ_NONNULL const RzCodePoints *buffer, size_t start) {
	size_t end = RZ_MIN(start + 1, rz_vector_len(buffer));
	while (end < rz_vector_len(buffer)) {
		const RzCodePoint *cp = rz_vector_index_ptr(buffer, end);
		if (!is_word_constituent(*cp)) {
			break;
		}
		++end;
	}
	return end;
}

static size_t emacs_mode_find_prev_word_start(const RzCodePoints *buffer, size_t index) {
	while (index > 0) {
		const RzCodePoint *cp = rz_vector_index_ptr(buffer, index - 1);
		if (!is_word_constituent(*cp)) {
			break;
		}
		--index;
	}
	return index;
}

static size_t emacs_mode_find_prev_word_end(const RzCodePoints *buffer, size_t index) {
	while (index > 0) {
		const RzCodePoint *cp = rz_vector_index_ptr(buffer, index);
		if (is_word_constituent(*cp)) {
			break;
		}
		--index;
	}
	return index;
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

static void line_delete_range(RzLine *line, size_t start, size_t end) {
	if (start >= end || end > line->buffer.length) {
		return;
	}
	char *line_buf = line->buffer.data;
	memmove(line_buf + start, line_buf + end, line->buffer.length - end);
	line->buffer.length -= end - start;
	line->buffer.data[line->buffer.length] = '\0';
}

static bool emacs_mode_modify_kill(RzLine *line, const RzCodePoints *buffer, size_t word_count, size_t end) {
	for (size_t i = 0; i < word_count && end < rz_vector_len(buffer); ++i) {
		const size_t start = emacs_mode_find_word_start(buffer, end);
		end = emacs_mode_find_word_end(buffer, start);
	}
	const ssize_t end_byte = emacs_mode_find_byte_index(buffer, end);
	if (end_byte < 0) {
		return false;
	}
	line_delete_range(line, line->buffer.index, end_byte);
	return true;
}

static bool emacs_mode_modify_kill_backward(RzLine *line, const RzCodePoints *buffer, size_t word_count, size_t utf8_index) {
	if (utf8_index < 1) {
		return true;
	}
	size_t start = RZ_MIN(utf8_index, rz_vector_len(buffer) - 1);
	if (start < utf8_index && is_word_constituent_index(buffer, start)) {
		--word_count;
	}

	for (size_t wi = 0; wi < word_count && start > 0; ++wi) {
		size_t end = emacs_mode_find_prev_word_end(buffer, start - 1);
		start = emacs_mode_find_prev_word_start(buffer, end);
	}

	const ssize_t start_byte = emacs_mode_find_byte_index(buffer, start);
	if (start_byte < 0) {
		return false;
	}
	line_delete_range(line, start_byte, line->buffer.index);
	line->buffer.index = start_byte;
	return true;
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
static RZ_OWN RZ_NULLABLE char *emacs_mode_capitalize(RZ_NONNULL const RzCodePoints *buffer, size_t start, size_t end, size_t utf8_len) {
	rz_return_val_if_fail(buffer && rz_vector_len(buffer) > 0 && utf8_len > 0 && start <= end && end <= rz_vector_len(buffer), NULL);

	RzUnicodeCaseMappings *map = rz_vector_new(sizeof(RzUnicodeCaseMapping), NULL, NULL);
	size_t i = start;
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
static char *emacs_mode_tolower(RZ_NONNULL const RzCodePoints *buffer, size_t start, size_t end, size_t utf8_len) {
	rz_return_val_if_fail(buffer && rz_vector_len(buffer) > 0 && utf8_len > 0 && start <= end && end <= rz_vector_len(buffer), NULL);

	RzVector *map = rz_vector_new(sizeof(RzUnicodeCaseMapping), NULL, NULL);
	for (size_t i = start; i < end; ++i) {
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
static RZ_OWN RZ_NULLABLE char *emacs_mode_toupper(RZ_NONNULL const RzCodePoints *buffer, size_t start, size_t end, size_t utf8_len) {
	rz_return_val_if_fail(buffer && rz_vector_len(buffer) > 0 && utf8_len > 0 && start <= end && end <= rz_vector_len(buffer), NULL);

	RzVector *map = rz_vector_new(sizeof(RzUnicodeCaseMapping), NULL, NULL);
	for (size_t i = start; i < end; ++i) {
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

static bool emacs_mode_modify_case_single(RzEmacsModeOp op, RZ_NONNULL RzLine *line, RZ_NONNULL const RzCodePoints *cpbuffer, size_t start, size_t end) {
	rz_return_val_if_fail(line && cpbuffer, false);
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

static bool emacs_mode_modify_case(RZ_NONNULL const RzEmacsModeOpts *opts, RZ_NONNULL RzLine *line, RZ_NONNULL const RzCodePoints *buffer, size_t word_count, size_t utf8_index) {
	size_t start = 0, end = 0; ///< index of first/last unicode code point in the current word
	start = emacs_mode_find_word_start(buffer, utf8_index);
	end = emacs_mode_find_word_end(buffer, start);
	for (size_t wi = 0; wi < word_count && start < end; ++wi) {
		const bool failed = !emacs_mode_modify_case_single(opts->op, line, buffer, start, end);
		if (failed) {
			return false;
		}
		if (opts->move_cursor) {
			line->buffer.index = emacs_mode_find_byte_index(buffer, end);
		}
		start = emacs_mode_find_word_start(buffer, end);
		end = emacs_mode_find_word_end(buffer, start);
	}
	return true;
}

static bool emacs_mode_move_forward(RzLine *line, const RzCodePoints *buffer, size_t word_count, size_t utf8_index) {
	size_t start = emacs_mode_find_word_start(buffer, utf8_index);
	size_t end = emacs_mode_find_word_end(buffer, start);
	ssize_t new_index = line->buffer.index;

	RzCodePoint *curr_ch = rz_vector_index_ptr(buffer, utf8_index);
	if (!is_word_constituent(*curr_ch)) {
		new_index = emacs_mode_find_byte_index(buffer, start);
		--word_count;
	}

	for (size_t wi = 0; wi < word_count && start < end; ++wi) {
		start = emacs_mode_find_word_start(buffer, end);
		end = emacs_mode_find_word_end(buffer, start);
		new_index = emacs_mode_find_byte_index(buffer, start);
		if (new_index < 0) {
			return false;
		}
	}
	line->buffer.index = new_index;
	return true;
}

static bool emacs_mode_move_backward(RzLine *line, const RzCodePoints *buffer, size_t word_count, size_t utf8_index) {
	size_t start = utf8_index;
	if (start < 1) {
		return true;
	}
	size_t end = emacs_mode_find_prev_word_end(buffer, start - 1);
	ssize_t new_index = line->buffer.index;
	for (size_t wi = 0; wi < word_count && end >= 0; ++wi) {
		start = emacs_mode_find_prev_word_start(buffer, end);
		new_index = emacs_mode_find_byte_index(buffer, start);
		if (new_index < 0) {
			return false;
		}
		if (start < 1) {
			break;
		}
		end = emacs_mode_find_prev_word_end(buffer, start - 1);
	}
	line->buffer.index = new_index;
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
RZ_IPI bool rz_emacs_mode_action(RZ_NONNULL RZ_BORROW const RzEmacsModeOpts *opts, RZ_NONNULL RZ_BORROW RzLine *line) {
	rz_return_val_if_fail(line && opts, false);
	if (line->buffer.length < 1) {
		return true;
	}

	RzCodePoints cpbuffer;
	rz_vector_init(&cpbuffer, sizeof(RzCodePoint), NULL, NULL);
	const ut8 *line_buf = (ut8 *)line->buffer.data;
	const bool decoded = utf8_decode_buf(line_buf, line->buffer.length, &cpbuffer);
	if (!decoded || rz_vector_len(&cpbuffer) < 1) {
		rz_vector_fini(&cpbuffer);
		return false;
	}

	const size_t word_count = opts->word_count_provided ? opts->word_count : 1;
	const size_t utf8_index = rz_utf8_strnlen(line_buf, line->buffer.index);

	bool ret = true;
	switch (opts->op) {
	default:
		rz_return_val_if_reached(false);
	case EMACS_MODIFY_CAPITALIZE:
	case EMACS_MODIFY_TOLOWER:
	case EMACS_MODIFY_TOUPPER:
		ret = emacs_mode_modify_case(opts, line, &cpbuffer, word_count, utf8_index);
		break;
	case EMACS_MODIFY_KILL_WORD:
		ret = emacs_mode_modify_kill(line, &cpbuffer, word_count, utf8_index);
		break;
	case EMACS_MODIFY_KILL_WORD_BACKWARD:
		ret = emacs_mode_modify_kill_backward(line, &cpbuffer, word_count, utf8_index);
		break;
	case EMACS_MOVE_FORWARD:
		ret = emacs_mode_move_forward(line, &cpbuffer, word_count, utf8_index);
		break;
	case EMACS_MOVE_BACKWARD:
		ret = emacs_mode_move_backward(line, &cpbuffer, word_count, utf8_index);
		break;
	}

	rz_vector_fini(&cpbuffer);
	return ret;
}

/**
 * \brief Reset \p opts to their default state.
 *
 * \param opts The modify options.
 */
RZ_IPI void rz_emacs_mode_opts_reset(RZ_NONNULL RZ_BORROW RzEmacsModeOpts *opts) {
	rz_return_if_fail(opts);
	opts->move_cursor = true;
	opts->word_count_provided = false;
	opts->word_count = 0;
}
