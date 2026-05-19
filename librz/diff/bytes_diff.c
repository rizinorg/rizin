// SPDX-FileCopyrightText: 2021-2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021-2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

/* Helpers for handling bytes */
#define DIFF_IS_BYTES_METHOD(x) (x.elem_at == methods_bytes.elem_at)
#define IS_PTR_ALIGNED(x, y)    ((((uintptr_t)(x)) & (sizeof(y) - 1)) == 0)
#define DIFF_BYTE_REALIGN_SIZE  32

static const void *byte_elem_at(const ut8 *array, ut32 index) {
	return array + index;
}

static void byte_stringify(const ut8 *bytes, RzStrBuf *sb) {
	char buf[4] = { 0 };
	rz_hex_bin2str(bytes, 1, buf);
	rz_strbuf_set(sb, buf);
}

static bool byte_small_block_compare(const ut8 *a, ut32 a_left, const ut8 *b, ut32 b_left, ut32 *inc) {
#define SMALL_CMP(bits) \
	if (a_left > sizeof(ut##bits) && IS_PTR_ALIGNED(a, ut##bits) && IS_PTR_ALIGNED(b, ut##bits)) { \
		ut##bits *a_##bits = (ut##bits *)a; \
		ut##bits *b_##bits = (ut##bits *)b; \
		*inc = sizeof(ut##bits); \
		if (*a_##bits == *b_##bits) { \
			return true; \
		} \
	}

	SMALL_CMP(64)
	SMALL_CMP(32)
	SMALL_CMP(16)

	*inc = 1;
	return *a == *b;
}

static size_t byte_try_to_realign_buffer(const ut8 *a, ut32 a_size, const ut8 *b, ut32 b_size) {
	const size_t max_size = RZ_MIN(a_size, b_size);
	const size_t min_block = RZ_MIN(8, max_size);

	for (size_t align = 0; align < DIFF_BYTE_REALIGN_SIZE && max_size <= (b_size - align); align++) {
		size_t leftover = RZ_MIN(b_size - align, min_block);
		if (!memcmp(a, b + align, leftover)) {
			return align;
		}
	}
	return 0;
}

static ut32 byte_longest_match_in_buffer(const ut8 *a, ut32 a_size, const ut8 *b, ut32 b_size, ut32 *hit_a, ut32 *hit_b) {
	size_t begin_a = 0, begin_b = 0;
	size_t size = 0;
	size_t i, j, count;

	ut32 inc = 1;
	for (i = 0, j = 0, count = 0; i < a_size && j < b_size; i += inc, j += inc) {
		if (byte_small_block_compare(a + i, a_size - i, b + j, b_size - j, &inc)) {
			count += inc;
			continue;
		} else if (count < 1) {
			size_t aligned_at = byte_try_to_realign_buffer(a + i, a_size - i, b + j, b_size - j);
			if (aligned_at > 0) {
				j += aligned_at;
				inc = 0;
			}
			continue;
		}

		if (count > size) {
			begin_a = i - count;
			begin_b = j - count;
			size = count;

			if (size >= (a_size - i) || size >= (b_size - i)) {
				// the leftovers are always smaller than the current match
				break;
			}
		}
		count = 0;
	}

	if (count > size) {
		begin_a = i - count;
		begin_b = j - count;
		size = count;
	}

	*hit_a = begin_a;
	*hit_b = begin_b;
	return size;
}

static RzDiffMatch *byte_find_longest_match(RzDiff *diff, Block *block) {
	rz_return_val_if_fail(diff, NULL);
	const ut8 *a = ((const ut8 *)diff->a) + block->a_low;
	const ut8 *b = ((const ut8 *)diff->b) + block->b_low;
	size_t a_size = block->a_hi - block->a_low;
	size_t b_size = block->b_hi - block->b_low;

	ut32 hit_a = 0;
	ut32 hit_b = 0;
	ut32 match_size = byte_longest_match_in_buffer(a, a_size, b, b_size, &hit_a, &hit_b);

	if (match_size < 1) {
		return NULL;
	}

	hit_a += block->a_low;
	hit_b += block->b_low;

	RzDiffMatch *match = match_new(hit_a, hit_b, match_size);
	if (match) {
		return match;
	}

	RZ_LOG_ERROR("byte_find_longest_match: cannot allocate RzDiffMatch\n");
	return NULL;
}

static const MethodsInternal methods_bytes = {
	.elem_at /*      */ = (RzDiffMethodElemAt)byte_elem_at,
	.elem_hash /*    */ = NULL,
	.compare /*      */ = NULL,
	.stringify /*    */ = (RzDiffMethodStringify)byte_stringify,
	.ignore /*       */ = fake_ignore,
	.free /*         */ = NULL,
	.find_longest_match = byte_find_longest_match,
};
