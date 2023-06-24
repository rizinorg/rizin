// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2010-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2010-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

static inline ut64 read_uleb128(ut8 **p, ut8 *end) {
	const char *error = NULL;
	ut64 v;
	*p = (ut8 *)rz_uleb128(*p, end - *p, &v, &error);
	if (error) {
		RZ_LOG_ERROR("%s", error);
		RZ_FREE(error);
		return UT64_MAX;
	}
	return v;
}

static inline size_t get_word_size(struct MACH0_(obj_t) * bin) {
	const size_t word_size = MACH0_(get_bits)(bin) / 8;
	return RZ_MAX(word_size, 4);
}
