// SPDX-FileCopyrightText: 2026 Anton Angelov <anton.angelov@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "bench_utils.h"
#include <rz_util/ht_pu.h>
#include <rz_util/ht_su.h>
#include <rz_util/ht_uu.h>

/**
 * \file bench_ht.c
 * \brief Benchmark for hash table functions (`ht_*`)
 */

#define ITERATION_COUNT    2000000
#define SHUFFLE_MULTIPLIER 1037

static bool ht_pu_foreach_cb(RZ_UNUSED ut64 *i, RZ_UNUSED const void *key, RZ_UNUSED const ut64 value) {
	return true;
}

/**
 * Used for generating a pseudo-random value based on iteration number (for randomizing HtUU keys)
 */
static inline ut64 splitmix64(ut64 v) {
	uint64_t z = (v + 0x9E3779B97F4A7C15ULL);
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
	return z ^ (z >> 31);
}

/**
 * A sample object to be used as a key for a HtPU hash table
 */
typedef struct {
	ut32 a;
	ut32 b;
} PUKey;

static inline PUKey make_pu_key(ut64 iteration) {
	PUKey result;
	result.a = iteration * 1000;
	result.b = splitmix64(iteration);
	return result;
}

/**
 * Reshuffles a key in order to do the following (in a deterministic way):
 *	- avoid sequential key insert/lookup
 *	- create 87.5% chance of lookup hit vs 12.5% chance of miss
 *	- make 10% of the elements (hot zone) to be requested 75.5% of the time
 */
static ut64 reshuffle_key(ut64 index, ut64 max_value, ut64 unexistent_key) {
	const ut64 hot_zone_denom = 10; // 10% of the hash table elements are considered in the hot zone
	ut64 hot_zone_size = max_value / hot_zone_denom;

	switch (index % 8) {
	case 0:
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
		// 75.5% hot zone (6/8)
		return (index * SHUFFLE_MULTIPLIER) % hot_zone_size * hot_zone_denom;
	case 6:
		// 12.5% cold zone (1/8)
		return (index * SHUFFLE_MULTIPLIER) % max_value;
	case 7:
		// 12.5% miss rate (1/8)
		return unexistent_key;
	default:
		rz_warn_if_reached();
		return 0;
	}
}

static ut32 pu_key_hash(void *p) {
	PUKey *key = p;
	return key->a ^ key->b;
}

static int pu_key_cmp(void *p1, void *p2) {
	PUKey *key1 = p1;
	PUKey *key2 = p2;

	if (key1->a < key2->a) {
		return -1;
	}
	if (key1->a > key2->a) {
		return 1;
	}
	if (key1->b < key2->b) {
		return -1;
	}
	if (key1->b > key2->b) {
		return 1;
	}
	return 0;
}

static void bench_rz_ht_pu_combined(RzTable *t_out) {
	ut64 temp = 0;
	HtPUOptions pu_opt = { 0 };
	pu_opt.hashfn = (HtPUHashFunction)pu_key_hash;
	pu_opt.cmp = (HtPUComparator)pu_key_cmp;
	PUKey *keys = malloc(sizeof(PUKey) * ITERATION_COUNT);

	// Generate keys
	for (ut64 i = 0; i < ITERATION_COUNT; i++) {
		keys[i] = make_pu_key(i);
	}

	// Insert
	{
		HtPU *ht = ht_pu_new_opt(&pu_opt);
		RZ_BENCH_RUN_I("[HtPU] insert", i, t_out, ITERATION_COUNT, {
			ht_pu_insert(ht, &keys[i], i);
		});
		RZ_BENCH_RUN_I("[HtPU] delete", i, t_out, ITERATION_COUNT, {
			ht_pu_delete(ht, &keys[i]);
		});
		ht_pu_free(ht);
	}

	// Lookup (small, medium, large hash tables) and iterate
	{
		HtPU *ht_100 = ht_pu_new_opt(&pu_opt);
		HtPU *ht_1k = ht_pu_new_opt(&pu_opt);
		HtPU *ht_10k = ht_pu_new_opt(&pu_opt);
		HtPU *ht_100k = ht_pu_new_opt(&pu_opt);
		HtPU *ht_1m = ht_pu_new_opt(&pu_opt);

		for (ut64 i = 0; i < 1000000; i++) {
			PUKey *key = &keys[i];
			if (i < 100) {
				ht_pu_insert(ht_100, key, i);
			}
			if (i < 1000) {
				ht_pu_insert(ht_1k, key, i);
			}
			if (i < 10000) {
				ht_pu_insert(ht_10k, key, i);
			}
			if (i < 100000) {
				ht_pu_insert(ht_100k, key, i);
			}
			ht_pu_insert(ht_1m, key, i);
		}

		RZ_BENCH_RUN("[HtPU] iterate (100 elements)", t_out, ITERATION_COUNT, {
			ht_pu_foreach(ht_100, (HtPUForeachCallback)ht_pu_foreach_cb, &temp);
		});
		RZ_BENCH_RUN_I("[HtPU] lookup (100 elements)", i, t_out, ITERATION_COUNT, {
			PUKey temp_key = make_pu_key(reshuffle_key(i, 100, UT64_MAX));
			RZ_DONT_OPTIMIZE(ut64, ht_pu_find(ht_100, &temp_key, NULL));
		});
		RZ_BENCH_RUN_I("[HtPU] lookup (1k elements)", i, t_out, ITERATION_COUNT, {
			PUKey temp_key = make_pu_key(reshuffle_key(i, 1000, UT64_MAX));
			RZ_DONT_OPTIMIZE(ut64, ht_pu_find(ht_1k, &temp_key, NULL));
		});
		RZ_BENCH_RUN_I("[HtPU] lookup (10k elements)", i, t_out, ITERATION_COUNT, {
			PUKey temp_key = make_pu_key(reshuffle_key(i, 10000, UT64_MAX));
			RZ_DONT_OPTIMIZE(ut64, ht_pu_find(ht_10k, &temp_key, NULL));
		});
		RZ_BENCH_RUN_I("[HtPU] lookup (100k elements)", i, t_out, ITERATION_COUNT, {
			PUKey temp_key = make_pu_key(reshuffle_key(i, 100000, UT64_MAX));
			RZ_DONT_OPTIMIZE(ut64, ht_pu_find(ht_100k, &temp_key, NULL));
		});
		RZ_BENCH_RUN_I("[HtPU] lookup (1M elements)", i, t_out, ITERATION_COUNT, {
			PUKey temp_key = make_pu_key(reshuffle_key(i, 1000000, UT64_MAX));
			RZ_DONT_OPTIMIZE(ut64, ht_pu_find(ht_1m, &temp_key, NULL));
		});

		ht_pu_free(ht_100);
		ht_pu_free(ht_1k);
		ht_pu_free(ht_10k);
		ht_pu_free(ht_100k);
		ht_pu_free(ht_1m);
	}

	free(keys);
}

static char *generate_su_key(ut64 i) {
	char buffer[UT8_MAX];

	// cast to uint64_t to avoid format specifier (PRIx64) mismatch
	uint64_t index = (uint64_t)i;

	// Try to mimic real world string keys
	switch (index % 8) {
	case 0:
		snprintf(buffer, UT8_MAX, "user_%" PRIx64, index); // user id
		break;
	case 1:
		snprintf(buffer, UT8_MAX, "session_%" PRIx64 "%" PRIx64, index, index * 7919); // session token
		break;
	case 2: {
		const char *sections[] = { "analysis", "asm", "scr", "graph", "str" };
		const char *keys[] = { "flags", "prefix", "editor", "times", "server" };
		snprintf(buffer, UT8_MAX, "config.%s.%s", sections[index % 5], keys[(index / 5) % 5]); // config keys
		break;
	}
	case 3: {
		const char *headers[] = { "content-type", "content-length", "authorization", "user-agent", "accept", "accept-encoding",
			"cache-control", "connection", "host", "cookie", "referer", "accept-language",
			"x-forwarded-for", "x-request-id", "etag" };
		snprintf(buffer, UT8_MAX, "%s-%" PRIx64, headers[index % 15], index / 15); // http header
		break;
	}
	case 4: {
		const char *dirs[] = { "/home/user/documents", "/var/log", "/etc/config", "/usr/local/bin", "/tmp/cache" };
		snprintf(buffer, UT8_MAX, "%s/file %" PRIx64 ".txt", dirs[index % 5], index);
		break;
	}
	case 5: {
		const char *domains[] = { "example.com", "test.org", "mail.net", "company.io" };
		snprintf(buffer, UT8_MAX, "user%" PRIx64 "@%s", index, domains[index % 4]); // email
		break;
	}
	case 6: {
		snprintf(buffer, UT8_MAX, "%08" PRIx64 "-%04" PRIx64 "-%04" PRIx64 "-%04" PRIx64 "-%012" PRIx64,
			index,
			(index >> 16) & 0xFFFF,
			(index >> 8) & 0xFFFF,
			(index >> 4) & 0xFFFF,
			(index * 2654435761u)); // GUID
		break;
	}
	case 7: {
		// alphanumeric code with length of 2 to 64 characters
		const char chars[] = "abcdefghijklmnopqrstuvwxyz0123456789";
		int len = 2 + (index % 62);

		for (ut64 i = 0; i < len && i < UT8_MAX - 1; i++) {
			buffer[i] = chars[(index + i * 7) % 36];
		}
		buffer[len] = '\0';
		break;
	}
	default:
		rz_warn_if_reached();
	}

	return strdup(buffer);
}

static bool ht_su_foreach_cb(RZ_UNUSED ut64 *i, RZ_UNUSED const char *key, RZ_UNUSED const ut64 value) {
	return true;
}

static void bench_rz_ht_su_combined(RzTable *t_out) {
	char **precomputed_keys = malloc((ITERATION_COUNT + 1) * sizeof(char *));

	// Generate test keys
	for (ut64 i = 0; i < ITERATION_COUNT; i++) {
		precomputed_keys[i] = generate_su_key(i);
	}
	precomputed_keys[ITERATION_COUNT] = "non-existent";

	// Insert
	{
		HtSU *ht = ht_su_new(HT_STR_CONST);
		RZ_BENCH_RUN_I("[HtSU] insert", i, t_out, ITERATION_COUNT, {
			ht_su_insert(ht, precomputed_keys[i], i);
		});
		RZ_BENCH_RUN_I("[HtSU] delete", i, t_out, ITERATION_COUNT, {
			ht_su_delete(ht, precomputed_keys[i]);
		});
		ht_su_free(ht);
	}

	// Lookup (small, medium, large hash tables) and iterate
	{
		HtSU *ht_100 = ht_su_new(HT_STR_CONST);
		HtSU *ht_1k = ht_su_new(HT_STR_CONST);
		HtSU *ht_10k = ht_su_new(HT_STR_CONST);
		HtSU *ht_100k = ht_su_new(HT_STR_CONST);
		HtSU *ht_1m = ht_su_new(HT_STR_CONST);

		for (ut64 i = 0; i < 1000000; i++) {
			if (i < 100) {
				ht_su_insert(ht_100, precomputed_keys[i], i);
			}
			if (i < 1000) {
				ht_su_insert(ht_1k, precomputed_keys[i], i);
			}
			if (i < 10000) {
				ht_su_insert(ht_10k, precomputed_keys[i], i);
			}
			if (i < 100000) {
				ht_su_insert(ht_100k, precomputed_keys[i], i);
			}
			ht_su_insert(ht_1m, precomputed_keys[i], i);
		}

		RZ_BENCH_RUN("[HtSU] iterate (100 elements)", t_out, ITERATION_COUNT, {
			ht_su_foreach(ht_100, (HtSUForeachCallback)ht_su_foreach_cb, NULL);
		});
		RZ_BENCH_RUN_I("[HtSU] lookup (100 elements)", i, t_out, ITERATION_COUNT, {
			const char *key = precomputed_keys[reshuffle_key(i, 100, ITERATION_COUNT)];
			RZ_DONT_OPTIMIZE(ut64, ht_su_find(ht_100, key, NULL));
		});
		RZ_BENCH_RUN_I("[HtSU] lookup (1k elements)", i, t_out, ITERATION_COUNT, {
			const char *key = precomputed_keys[reshuffle_key(i, 1000, ITERATION_COUNT)];
			RZ_DONT_OPTIMIZE(ut64, ht_su_find(ht_1k, key, NULL));
		});
		RZ_BENCH_RUN_I("[HtSU] lookup (10k elements)", i, t_out, ITERATION_COUNT, {
			const char *key = precomputed_keys[reshuffle_key(i, 10000, ITERATION_COUNT)];
			RZ_DONT_OPTIMIZE(ut64, ht_su_find(ht_10k, key, NULL));
		});
		RZ_BENCH_RUN_I("[HtSU] lookup (100k elements)", i, t_out, ITERATION_COUNT, {
			const char *key = precomputed_keys[reshuffle_key(i, 100000, ITERATION_COUNT)];
			RZ_DONT_OPTIMIZE(ut64, ht_su_find(ht_100k, key, NULL));
		});
		RZ_BENCH_RUN_I("[HtSU] lookup (1M elements)", i, t_out, ITERATION_COUNT, {
			const char *key = precomputed_keys[reshuffle_key(i, 1000000, ITERATION_COUNT)];
			RZ_DONT_OPTIMIZE(ut64, ht_su_find(ht_1m, key, NULL));
		});

		ht_su_free(ht_100);
		ht_su_free(ht_1k);
		ht_su_free(ht_10k);
		ht_su_free(ht_100k);
		ht_su_free(ht_1m);
	}

	// Free precomputed keys
	for (ut64 i = 0; i < ITERATION_COUNT; i++) {
		free(precomputed_keys[i]);
	}
	free(precomputed_keys);
}

static bool ht_uu_foreach_cb(RZ_UNUSED ut64 *i, RZ_UNUSED const ut64 key, RZ_UNUSED const ut64 value) {
	return true;
}

static void bench_rz_ht_uu_combined(RzTable *t_out) {
	HtUU *ht = NULL;

	// Insert
	{
		ht = ht_uu_new();
		RZ_BENCH_RUN_I("[HtUU] insert", i, t_out, ITERATION_COUNT, {
			ht_uu_insert(ht, splitmix64(i), i);
		});
		RZ_BENCH_RUN_I("[HtUU] delete", i, t_out, ITERATION_COUNT, {
			ht_uu_delete(ht, splitmix64(i)); // reshuffle keys
		});
		ht_uu_free(ht);
	}

	// Lookup 100 elements (and iterate)
	{
		const ut64 size = 100;
		ht = ht_uu_new();
		for (ut64 i = 0; i < size; i++) {
			ht_uu_insert(ht, splitmix64(i), i);
		}

		RZ_BENCH_RUN("[HtUU] iterate (100 elements)", t_out, ITERATION_COUNT, {
			ht_uu_foreach(ht, (HtUUForeachCallback)ht_uu_foreach_cb, NULL);
		});

		RZ_BENCH_RUN_I("[HtUU] lookup (100 elements)", i, t_out, ITERATION_COUNT, {
			ht_uu_find(ht, splitmix64(reshuffle_key(i, size, size)), NULL);
		});

		ht_uu_free(ht);
	}

	// Lookup 1k
	{
		const ut64 size = 1000;
		ht = ht_uu_new();
		for (ut64 i = 0; i < size; i++) {
			ht_uu_insert(ht, splitmix64(i), i);
		}

		RZ_BENCH_RUN_I("[HtUU] lookup (1k elements)", i, t_out, ITERATION_COUNT, {
			ht_uu_find(ht, splitmix64(reshuffle_key(i, size, size)), NULL);
		});

		ht_uu_free(ht);
	}

	// Lookup 10k
	{
		const ut64 size = 10000;
		ht = ht_uu_new();
		for (ut64 i = 0; i < size; i++) {
			ht_uu_insert(ht, splitmix64(i), i);
		}

		RZ_BENCH_RUN_I("[HtUU] lookup (10k elements)", i, t_out, ITERATION_COUNT, {
			ht_uu_find(ht, splitmix64(reshuffle_key(i, size, size)), NULL);
		});

		ht_uu_free(ht);
	}

	// Lookup 100k
	{
		const ut64 size = 100000;
		ht = ht_uu_new();
		for (ut64 i = 0; i < size; i++) {
			ht_uu_insert(ht, splitmix64(i), i);
		}

		RZ_BENCH_RUN_I("[HtUU] lookup (100k elements)", i, t_out, ITERATION_COUNT, {
			ht_uu_find(ht, splitmix64(reshuffle_key(i, size, size)), NULL);
		});

		ht_uu_free(ht);
	}

	// Lookup large
	{
		const ut64 size = 1000000;
		ht = ht_uu_new();
		for (ut64 i = 0; i < size; i++) {
			ht_uu_insert(ht, splitmix64(i), i);
		}

		RZ_BENCH_RUN_I("[HtUU] lookup (1M elements)", i, t_out, ITERATION_COUNT, {
			ht_uu_find(ht, splitmix64(reshuffle_key(i, size, size)), NULL);
		});

		ht_uu_free(ht);
	}
}

int main() {
	RzTable *t = rz_table_new();
	RZ_BENCH_TABLE_INIT(t);

	// Micro benchmarks
	bench_rz_ht_pu_combined(t);
	bench_rz_ht_su_combined(t);
	bench_rz_ht_uu_combined(t);

	// Print results
	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	return 0;
}
