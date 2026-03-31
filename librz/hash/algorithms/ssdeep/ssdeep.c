// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "ssdeep.h"
#include <rz_types.h>
#include <rz_endian.h>
#include <rz_util.h>
#include <rz_diff.h>

#include "fnv_hash.h"

#define SSDEEP_BASE64_CHARSET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

#define SSDEEP_ROLL_SLIDE_WINDOW_SIZE 7u
#define SSDEEP_BLOCK_HASHES_SIZE      31u
#define SSDEEP_SPAMSUM_LENGTH         64u
#define SSDEEP_SPAMSUM_HALF_LENGTH    (SSDEEP_SPAMSUM_LENGTH / 2)
#define SSDEEP_MIN_BLOCK_SIZE         3ull
#define SSDEEP_N_BLOCK_HASHES         31u
#define SSDEEP_BLOCK_SIZE(i)          (SSDEEP_MIN_BLOCK_SIZE << (i))
#define SSDEEP_TOTAL_SIZE(i)          (SSDEEP_BLOCK_SIZE(i) * SSDEEP_SPAMSUM_LENGTH)
#define SSDEEP_LIMIT_SIZE_INIT        SSDEEP_TOTAL_SIZE(0)
#define SSDEEP_LIMIT_MAX_SIZE         SSDEEP_TOTAL_SIZE(SSDEEP_N_BLOCK_HASHES - 1)
#define SSDEEP_DIGEST_SIZE            (SSDEEP_SPAMSUM_LENGTH + 2)
#define SSDEEP_ROLL_HASHES_SIZE       (SSDEEP_SPAMSUM_LENGTH - (SSDEEP_ROLL_SLIDE_WINDOW_SIZE - 1))
#define SSDEEP_SMALL_BLOCK_LIMIT      ((((99 + SSDEEP_ROLL_SLIDE_WINDOW_SIZE) / (SSDEEP_ROLL_SLIDE_WINDOW_SIZE)) * SSDEEP_MIN_BLOCK_SIZE))

typedef struct roll_hash_t {
	ut8 window[SSDEEP_ROLL_SLIDE_WINDOW_SIZE];
	ut32 current;
	ut32 state[3];
} RollHash;

typedef ut8 SumHash;

typedef struct digest_block_t {
	ut32 length; // digest length
	char digest[SSDEEP_DIGEST_SIZE];
	char prev_half;
	SumHash complete;
	SumHash half;
} DigestBlock;

struct rz_ssdeep_t {
	RollHash roll;
	DigestBlock blocks[SSDEEP_N_BLOCK_HASHES];
	SumHash lasth;
	bool last_iteration;

	ut64 block_limit;
	ut64 total_size;

	ut32 start;
	ut32 end;
	ut32 roll_mask;
};

static const char *base64_charset = SSDEEP_BASE64_CHARSET;
static const char fnv_b64_table[64][64] = {
	FNV_B64_00, FNV_B64_01, FNV_B64_02, FNV_B64_03, FNV_B64_04, FNV_B64_05, FNV_B64_06, FNV_B64_07,
	FNV_B64_08, FNV_B64_09, FNV_B64_0A, FNV_B64_0B, FNV_B64_0C, FNV_B64_0D, FNV_B64_0E, FNV_B64_0F,
	FNV_B64_10, FNV_B64_11, FNV_B64_12, FNV_B64_13, FNV_B64_14, FNV_B64_15, FNV_B64_16, FNV_B64_17,
	FNV_B64_18, FNV_B64_19, FNV_B64_1A, FNV_B64_1B, FNV_B64_1C, FNV_B64_1D, FNV_B64_1E, FNV_B64_1F,
	FNV_B64_20, FNV_B64_21, FNV_B64_22, FNV_B64_23, FNV_B64_24, FNV_B64_25, FNV_B64_26, FNV_B64_27,
	FNV_B64_28, FNV_B64_29, FNV_B64_2A, FNV_B64_2B, FNV_B64_2C, FNV_B64_2D, FNV_B64_2E, FNV_B64_2F,
	FNV_B64_30, FNV_B64_31, FNV_B64_32, FNV_B64_33, FNV_B64_34, FNV_B64_35, FNV_B64_36, FNV_B64_37,
	FNV_B64_38, FNV_B64_39, FNV_B64_3A, FNV_B64_3B, FNV_B64_3C, FNV_B64_3D, FNV_B64_3E, FNV_B64_3F
};

#define sum_hash_reset(state) \
	(state = FNV_INIT);

#define sum_hash_update(state, value) \
	(state = fnv_b64_table[state][value & 0x3f]);

#define roll_hash_reset(hash) \
	memset(hash, 0, sizeof(RollHash))

static void roll_hash_update(RollHash *hash, ut8 value8) {
	ut32 value32 = value8;
	ut32 current = hash->window[hash->current];

	hash->state[1] = hash->state[1] - hash->state[0] + (SSDEEP_ROLL_SLIDE_WINDOW_SIZE * value32);
	hash->state[0] = hash->state[0] + value32 - current;
	hash->state[2] = (hash->state[2] << 5) ^ value32;

	hash->window[hash->current] = value8;
	hash->current++;
	if (hash->current >= SSDEEP_ROLL_SLIDE_WINDOW_SIZE) {
		hash->current = 0;
	}
}

static ut32 roll_hash_sum(RollHash *hash) {
	return hash->state[0] + hash->state[1] + hash->state[2];
}

static void block_hash_reset(DigestBlock *block) {
	sum_hash_reset(block->complete);
	sum_hash_reset(block->half);
	memset(block->digest, 0, SSDEEP_DIGEST_SIZE);
	block->prev_half = 0;
	block->length = 0;
}

static void block_hash_update(DigestBlock *block) {
	block->length++;
	block->digest[block->length] = 0;
	sum_hash_reset(block->complete);
	if (block->length >= SSDEEP_SPAMSUM_HALF_LENGTH) {
		return;
	}

	sum_hash_reset(block->half);
	block->prev_half = 0;
}

static void ssdeep_update_next_block(RzSSDeep *context) {
	DigestBlock *last = &context->blocks[context->end - 1];
	if (context->end <= (SSDEEP_N_BLOCK_HASHES - 1)) {
		DigestBlock *next = &last[1]; // get the next block
		block_hash_reset(next);
		next->complete = last->complete;
		next->half = last->half;
		context->end++;
	} else if (context->end == SSDEEP_N_BLOCK_HASHES && !context->last_iteration) {
		context->last_iteration = true;
		context->lasth = last->complete;
	}
}

static void ssdeep_update_start_block(RzSSDeep *context) {
	if ((context->end - context->start) < 2 ||
		context->total_size < context->block_limit ||
		context->blocks[context->start + 1].length < SSDEEP_SPAMSUM_HALF_LENGTH) {
		return;
	}

	context->start++;
	context->block_limit <<= 1;
	context->roll_mask <<= 1;
	context->roll_mask |= 1;
}

static void ssdeep_update(RzSSDeep *context, ut8 c) {
	roll_hash_update(&context->roll, c);

	ut32 hash = roll_hash_sum(&context->roll) + 1;
	ut32 roll_size = hash / (ut32)SSDEEP_MIN_BLOCK_SIZE;

	for (ut32 i = context->start; i < context->end; ++i) {
		sum_hash_update(context->blocks[i].complete, c);
		sum_hash_update(context->blocks[i].half, c);
	}

	if (context->last_iteration) {
		sum_hash_update(context->lasth, c);
	}

	if (!hash ||
		(roll_size & context->roll_mask) ||
		(hash % (ut32)SSDEEP_MIN_BLOCK_SIZE)) {
		return;
	}

	roll_size >>= context->start;

	for (ut32 i = context->start; i < context->end; i++) {
		DigestBlock *block = &context->blocks[i];
		if (!block->length) {
			ssdeep_update_next_block(context);
		}

		block->digest[block->length] = base64_charset[block->complete];
		block->prev_half = base64_charset[block->half];

		if (block->length < (SSDEEP_SPAMSUM_LENGTH - 1)) {
			block_hash_update(block);
		} else {
			ssdeep_update_start_block(context);
		}
		if (roll_size & 1) {
			break;
		}
		roll_size >>= 1;
	};
}

RzSSDeep *rz_ssdeep_new(void) {
	RzSSDeep *context = RZ_NEW0(RzSSDeep);
	if (context) {
		rz_ssdeep_init(context);
	}
	return context;
}

void rz_ssdeep_init(RzSSDeep *context) {
	rz_return_if_fail(context);
	roll_hash_reset(&context->roll);
	block_hash_reset(&context->blocks[0]);
	context->total_size = 0;
	context->block_limit = SSDEEP_LIMIT_SIZE_INIT;
	context->last_iteration = false;
	context->start = 0;
	context->end = 1;
	context->roll_mask = 0;
}

bool rz_ssdeep_update(RzSSDeep *context, const ut8 *buf, ut64 len) {
	rz_return_val_if_fail(context && buf, false);
	context->total_size += len;

	for (ut64 i = 0; i < len; i++) {
		ssdeep_update(context, buf[i]);
	}
	return true;
}

void rz_ssdeep_fini(RzSSDeep *context, char *result) {
	rz_return_if_fail(context && result);

	memset(result, 0, RZ_HASH_SSDEEP_DIGEST_SIZE);

	DigestBlock tmp = { 0 };
	DigestBlock *block_0 = NULL, *block_1 = NULL;
	ut32 start = context->start;
	ut32 roll_hash = roll_hash_sum(&context->roll);

	if (context->total_size > SSDEEP_LIMIT_MAX_SIZE) {
		RZ_LOG_ERROR("ssdeep: total size exceeds max size\n");
		return;
	}

	while (SSDEEP_TOTAL_SIZE(start) < context->total_size) {
		++start;
	}

	if (start >= context->end) {
		start = context->end - 1;
	}

	while (start > context->start && context->blocks[start].length < SSDEEP_SPAMSUM_HALF_LENGTH) {
		--start;
	}

	ut64 block_size = SSDEEP_BLOCK_SIZE(start);
	block_0 = &context->blocks[start];
	block_1 = &context->blocks[start + 1];

	if (roll_hash) {
		block_0->digest[block_0->length++] = base64_charset[block_0->complete];
	} else if (block_0->digest[block_0->length]) {
		// has a tail char, we must include it
		block_0->length++;
	}

	// ensure the last char is always the delimiter
	block_0->digest[block_0->length] = 0;

	if (start < context->end - 1) {
		if (block_1->length > SSDEEP_SPAMSUM_HALF_LENGTH - 1) {
			block_1->length = SSDEEP_SPAMSUM_HALF_LENGTH - 1;
		}
		if (roll_hash) {
			block_1->digest[block_1->length++] = base64_charset[block_1->half];
		} else if (block_1->prev_half) {
			block_1->digest[block_1->length++] = block_1->prev_half;
		}
	} else if (roll_hash) {
		tmp.length++;
		tmp.digest[0] = start ? base64_charset[context->lasth] : base64_charset[block_0->complete];
		block_1 = &tmp;
	}

	// ensure the last char is always the delimiter
	block_1->digest[block_1->length] = 0;

	snprintf(result, RZ_HASH_SSDEEP_DIGEST_SIZE, "%" PFMT64u ":%s:%s", block_size, block_0->digest, block_1->digest);
}

// removes char sequences longer than 3.
static char *remove_triplets(const char *old) {
	size_t len = strlen(old);
	char *new_str = RZ_NEWS0(char, len + 1);
	if (len < 3 || !new_str) {
		free(new_str);
		return NULL;
	}

	new_str[0] = old[0];
	new_str[1] = old[1];
	new_str[2] = old[2];

	for (size_t i = 3, j = 3; i < len; ++i) {
		if (old[i] == old[i - 1] && old[i] == old[i - 2] && old[i] == old[i - 3]) {
			continue;
		}
		new_str[j++] = old[i];
	}
	return new_str;
}

static bool has_same_roll_hashes(const char *hash_a, size_t len_a, const char *hash_b, size_t len_b) {
	RollHash hash = { 0 };
	ut32 hashes[SSDEEP_ROLL_HASHES_SIZE] = { 0 };

	const ut32 window_end = SSDEEP_ROLL_SLIDE_WINDOW_SIZE - 1;

	for (ut32 i = 0; i < window_end; i++) {
		roll_hash_update(&hash, hash_a[i]);
	}
	for (ut32 i = window_end; i < len_a; i++) {
		roll_hash_update(&hash, hash_a[i]);
		hashes[i - window_end] = roll_hash_sum(&hash);
	}
	len_a -= window_end;

	roll_hash_reset(&hash);

	for (ut32 i = 0; i < window_end; i++) {
		roll_hash_update(&hash, hash_b[i]);
	}
	len_b -= window_end;

	for (ut32 j = 0; j < len_b; j++) {
		roll_hash_update(&hash, hash_b[j + window_end]);
		ut32 sum = roll_hash_sum(&hash);
		for (ut32 i = 0; i < len_a; i++) {
			if (sum != hashes[i] || memcmp(hash_a + i, hash_b + j, SSDEEP_ROLL_SLIDE_WINDOW_SIZE)) {
				continue;
			}
			return true;
		}
	}
	return false;
}

double calculate_hashes_distance(const char *hash_a, size_t len_a, const char *hash_b, size_t len_b) {
	size_t max_len = RZ_MAX(len_a, len_b) + 1;
	float *dist1 = RZ_NEWS0(float, max_len);
	float *dist2 = RZ_NEWS0(float, max_len);

	if (!dist1 || !dist2) {
		RZ_LOG_ERROR("ssdeep: failed to allocate buffer for distance calculation\n");
		free(dist1);
		free(dist2);
		return 0;
	}

	for (size_t i = 0; i <= len_b; i++) {
		dist1[i] = (float)i;
	}

	for (size_t i = 0; i < len_a; i++) {
		dist2[0] = 1.0f + i;
		for (size_t j = 0; j < len_b; j++) {
			float rpl_cost = dist1[j];
			if (hash_a[i] != hash_b[j]) {
				// replace 2 chars
				rpl_cost += 2.0f;
			}
			float rem_cost = dist2[j] + 1.0f; // remove 1 char
			float add_cost = dist1[j + 1] + 1.0f; // add 1 char
			dist2[j + 1] = RZ_MIN(RZ_MIN(rem_cost, rpl_cost), add_cost);
		}

		// swap the two distances
		float *tmp = dist1;
		dist1 = dist2;
		dist2 = tmp;
	}

	double result = (double)dist1[len_b];
	free(dist1);
	free(dist2);

	result /= (double)(len_a + len_b);
	return 1.0 - result;
}

static double calculate_similarity(const char *hash_a, const char *hash_b, ut32 block_size) {
	size_t len_a = strlen(hash_a);
	size_t len_b = strlen(hash_b);
	if (len_a < SSDEEP_ROLL_SLIDE_WINDOW_SIZE || len_b < SSDEEP_ROLL_SLIDE_WINDOW_SIZE) {
		return 0.0;
	}

	if (!has_same_roll_hashes(hash_a, len_a, hash_b, len_b)) {
		return 0.0;
	}

	double similarity = calculate_hashes_distance(hash_a, len_a, hash_b, len_b);

	if (block_size < SSDEEP_SMALL_BLOCK_LIMIT) {
		double max_score = block_size;
		max_score /= (double)SSDEEP_MIN_BLOCK_SIZE;
		max_score *= (double)RZ_MIN(len_a, len_b);
		if ((similarity * 100.0) > max_score) {
			similarity = max_score / 100.0;
		}
	}

	return similarity;
}

double rz_ssdeep_compare(const char *hash_a, const char *hash_b) {
	double similarity = 0.0;
	ut32 block_a, block_b;
	char *digest_a0 = NULL, *digest_a1 = NULL;
	char *digest_b0 = NULL, *digest_b1 = NULL;
	RzList *token_a = rz_str_split_duplist(hash_a, ":", true);
	RzList *token_b = rz_str_split_duplist(hash_b, ":", true);

	if (rz_list_length(token_a) != 3 || rz_list_length(token_b) != 3) {
		RZ_LOG_ERROR("diff: the expected hashes are not in ssdeep format\n");
		similarity = -1.0;
		goto end;
	}

	block_a = strtol(rz_list_first_val(token_a), NULL, 10);
	digest_a0 = remove_triplets(rz_list_get_n(token_a, 1));
	digest_a1 = remove_triplets(rz_list_last_val(token_a));

	block_b = strtol(rz_list_first_val(token_b), NULL, 10);
	digest_b0 = remove_triplets(rz_list_get_n(token_b, 1));
	digest_b1 = remove_triplets(rz_list_last_val(token_b));

	if (!block_a || !block_b || !digest_a0 || !digest_a1 || !digest_b0 || !digest_b1) {
		RZ_LOG_ERROR("diff: the expected hashes are not in ssdeep format\n");
		similarity = -1.0;
		goto end;
	}

	if (block_a != block_b && block_a != (block_b << 1) && block_b != (block_a << 1)) {
		similarity = 0.0;
	} else if (block_a == block_b && !strcmp(digest_a1, digest_b1)) {
		similarity = 1.0;
	} else if (block_a == block_b) {
		double score1 = calculate_similarity(digest_a0, digest_b0, block_a);
		double score2 = calculate_similarity(digest_a1, digest_b1, block_a << 1);
		similarity = RZ_MAX(score1, score2);
	} else if (block_a == (block_b << 1)) {
		similarity = calculate_similarity(digest_a0, digest_b1, block_a);
	} else /* if (block_b == (block_a << 1)) */ {
		similarity = calculate_similarity(digest_a1, digest_b0, block_b);
	}

end:
	free(digest_a0);
	free(digest_a1);
	free(digest_b0);
	free(digest_b1);
	rz_list_free(token_a);
	rz_list_free(token_b);
	return similarity;
}
