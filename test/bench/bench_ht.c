// SPDX-FileCopyrightText: 2026 Anton Angelov <anton.angelov@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "bench_utils.h"
#include <rz_util/ht_pu.h>
#include <rz_util/ht_su.h>
#include <rz_util/ht_uu.h>

/**
 * \file bench_mem.c
 * \brief Benchmark for hash table functions (`ht_*`)
 */

#define ITERATION_COUNT 2000000

static bool ht_pu_foreach_cb(RZ_UNUSED ut64 *i, RZ_UNUSED const void *key, RZ_UNUSED const ut64 value) {
	return true;
}

static inline void *generate_pu_key(ut64 index) {
	// Try to mimic real world pointer paterns
	switch (index % 5) {
	case 0:
		return (void *)(0x100000000ull + index * 8); // base pointer + array index (8 byte elements)
	case 1:
		return (void *)(0x100001000ull + index * 64); // base pointer + array index (64 byte elements)
	case 2:
		return (void *)(0x100050000ull + index * 4096); // base pointer + array index (4096 pages)
	case 3:
		return (void *)(0x7fffffffe000ull - index * 8); // stack pointers
	case 4:
		return (void *)(0x1000 + index * 2); // pointer 16-bit elements in a 16-bit arch
	}

	rz_warn_if_reached();
	return NULL;
}

static void bench_rz_ht_pu_combined(RzTable *t_out) {
	ut64 i = 0;
	ut64 temp = 0;
	HtPUOptions pu_opt = { 0 };

	// Insert
	{
		HtPU *ht = ht_pu_new_opt(&pu_opt);
		RZ_BENCH_RUN("[HtPU] insert", t_out, ITERATION_COUNT, {
			ht_pu_insert(ht, generate_pu_key(i), i);
			i++;
		});
		ht_pu_free(ht);
	}

	// Lookup (small, medium, large hash tables) and iterate
	{
		const ut64 size_small = 100;
		const ut64 size_medium = 1000;
		const ut64 size_large = 1000000;
		HtPU *ht_small = ht_pu_new_opt(&pu_opt);
		HtPU *ht_medium = ht_pu_new_opt(&pu_opt);
		HtPU *ht_large = ht_pu_new_opt(&pu_opt);

		for (i = 0; i < size_large; i++) {
			if (i < size_small) {
				ht_pu_insert(ht_small, generate_pu_key(i), i);
			}
			if (i < size_medium) {
				ht_pu_insert(ht_medium, generate_pu_key(i), i);
			}
			ht_pu_insert(ht_large, generate_pu_key(i), i);
		}

		RZ_BENCH_RUN("[HtPU] iterate (100 elements)", t_out, ITERATION_COUNT, {
			ht_pu_foreach(ht_small, (HtPUForeachCallback)ht_pu_foreach_cb, &temp);
		});
		i = 0;
		RZ_BENCH_RUN("[HtPU] lookup (100 elements)", t_out, ITERATION_COUNT, {
			ut64 result = ht_pu_find(ht_small, generate_pu_key(i % (size_small * 2)), NULL); // 50% hit vs 50% miss
			i++;
		});
		i = 0;
		RZ_BENCH_RUN("[HtPU] lookup (1000 elements)", t_out, ITERATION_COUNT, {
			ut64 result = ht_pu_find(ht_medium, generate_pu_key(i % (size_medium * 2)), NULL); // 50% hit vs 50% miss
			i++;
		});
		i = 0;
		RZ_BENCH_RUN("[HtPU] lookup (1000000 elements)", t_out, ITERATION_COUNT, {
			ut64 result = ht_pu_find(ht_large, generate_pu_key(i % (size_large * 2)), NULL); // 50% hit vs 50% miss
			i++;
		});

		ht_pu_free(ht_small);
		ht_pu_free(ht_medium);
		ht_pu_free(ht_large);
	}
}

static char *generate_su_key(ut64 index) {
	char buffer[UT8_MAX];

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

		for (ut32 i = 0; i < len && i < UT8_MAX - 1; i++) {
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
	ut64 i = 0;
	char **precomputed_keys = malloc(ITERATION_COUNT * sizeof(char *));

	// Generate test keys
	for (i = 0; i < ITERATION_COUNT; i++) {
		precomputed_keys[i] = generate_su_key(i);
	}

	// Insert
	{
		HtSU *ht = ht_su_new(HT_STR_CONST);
		RZ_BENCH_RUN("[HtSU] insert", t_out, ITERATION_COUNT, {
			ht_su_insert(ht, precomputed_keys[i], i);
			i++;
		});
		ht_su_free(ht);
	}

	// Lookup (small, medium, large hash tables) and iterate
	{
		const ut64 size_small = 100;
		const ut64 size_medium = 1000;
		const ut64 size_large = 1000000;
		HtSU *ht_small = ht_su_new(HT_STR_CONST);
		HtSU *ht_medium = ht_su_new(HT_STR_CONST);
		HtSU *ht_large = ht_su_new(HT_STR_CONST);

		for (i = 0; i < size_large; i++) {
			if (i < size_small) {
				ht_su_insert(ht_small, precomputed_keys[i], i);
			}
			if (i < size_medium) {
				ht_su_insert(ht_medium, precomputed_keys[i], i);
			}
			ht_su_insert(ht_large, precomputed_keys[i], i);
		}

		RZ_BENCH_RUN("[HtSU] iterate (100 elements)", t_out, ITERATION_COUNT, {
			ht_su_foreach(ht_small, (HtSUForeachCallback)ht_su_foreach_cb, NULL);
		});
		i = 0;
		RZ_BENCH_RUN("[HtSU] lookup (100 elements)", t_out, ITERATION_COUNT, {
			const char *key = i % 2 ? precomputed_keys[i / 2] : "non-existent-key";
			ut64 result = ht_su_find(ht_small, key, NULL); // 50% hit vs 50% miss
			i++;
		});
		i = 0;
		RZ_BENCH_RUN("[HtSU] lookup (1000 elements)", t_out, ITERATION_COUNT, {
			const char *key = i % 2 ? precomputed_keys[i / 2] : "non-existent-key";
			ut64 result = ht_su_find(ht_medium, key, NULL); // 50% hit vs 50% miss
			i++;
		});
		i = 0;
		RZ_BENCH_RUN("[HtSU] lookup (1000000 elements)", t_out, ITERATION_COUNT, {
			const char *key = i % 2 ? precomputed_keys[i / 2] : "non-existent-key";
			ut64 result = ht_su_find(ht_large, key, NULL); // 50% hit vs 50% miss
			i++;
		});

		ht_su_free(ht_small);
		ht_su_free(ht_medium);
		ht_su_free(ht_large);
	}

	// Free precomputed keys
	for (i = 0; i < ITERATION_COUNT; i++) {
		free(precomputed_keys[i]);
	}
	free(precomputed_keys);
}

static bool ht_uu_foreach_cb(RZ_UNUSED ut64 *i, RZ_UNUSED const ut64 key, RZ_UNUSED const ut64 value) {
	return true;
}

static void bench_rz_ht_uu_combined(RzTable *t_out) {
	HtUU *ht = NULL;
	ut64 i = 0;

	// Insert
	{
		ht = ht_uu_new();
		RZ_BENCH_RUN("[HtUU] insert", t_out, ITERATION_COUNT, {
			ht_uu_insert(ht, i, i);
			i++;
		});
		ht_uu_free(ht);
	}

	// Lookup small (and iterate)
	{
		const ut64 size = 100;
		ht = ht_uu_new();
		for (i = 0; i < size; i++) {
			ht_uu_insert(ht, i, i);
		}

		RZ_BENCH_RUN("[HtUU] iterate (100) elements", t_out, ITERATION_COUNT, {
			ht_uu_foreach(ht, (HtUUForeachCallback)ht_uu_foreach_cb, NULL);
		});

		i = 0;
		RZ_BENCH_RUN("[HtUU] lookup (100 elements)", t_out, ITERATION_COUNT, {
			ht_uu_find(ht, i % (size * 2), NULL); // 50% hit vs 50% miss
			i++;
		});

		ht_uu_free(ht);
	}

	// Lookup medium
	{
		const ut64 size = 1000;
		ht = ht_uu_new();
		for (i = 0; i < size; i++) {
			ht_uu_insert(ht, i, i);
		}

		i = 0;
		RZ_BENCH_RUN("[HtUU] lookup (1000 elements)", t_out, ITERATION_COUNT, {
			ht_uu_find(ht, i % (size * 2), NULL); // 50% hit vs 50% miss
			i++;
		});

		ht_uu_free(ht);
	}

	// Lookup large
	{
		const ut64 size = 1000000;
		ht = ht_uu_new();
		for (i = 0; i < size; i++) {
			ht_uu_insert(ht, i, i);
		}

		i = 0;
		RZ_BENCH_RUN("[HtUU] lookup (1000000 elements)", t_out, ITERATION_COUNT, {
			ht_uu_find(ht, i % (size * 2), NULL); // 50% hit vs 50% miss
			i++;
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
