// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "bench_utils.h"
#include <rz_diff.h>
#include <rz_util.h>

/**
 * \file bench_diff.c
 * \brief Micro-benchmarks for the RzDiff subsystem (librz/diff)
 *
 * The benchmarks fall into several groups:
 *
 *   1. Construction:           rz_diff_bytes_new / rz_diff_lines_new
 *                              These populate the internal `b_hits` hashmap
 *                              and dominate setup cost.
 *
 *   2. Core diffing:           rz_diff_matches_new / rz_diff_opcodes_new /
 *                              rz_diff_opcodes_grouped_new -- the
 *                              Ratcliff/Obershelp inner loop.
 *
 *   3. End-to-end output:      rz_diff_unified_text -- everything above
 *                              plus formatting cost.
 *
 *   4. Similarity:             rz_diff_ratio / rz_diff_sizes_ratio.
 *
 *   5. Distance algorithms:    rz_diff_myers_distance /
 *                              rz_diff_levenshtein_distance.
 *
 * For each, we cover both "similar" (mostly equal) and "divergent" (largely
 * different) inputs because the two cases have very different behavior in
 * the hit-map / longest-match search.
 */

#define BUF_SMALL  256
#define BUF_MEDIUM 4096
#define BUF_LARGE  32768

#define ITER_HEAVY  64
#define ITER_MEDIUM 1024
#define ITER_LIGHT  8192
#define ITER_TINY   200000

// ------------------------------------------------------------
// Input generators
// ------------------------------------------------------------

/* Deterministic, fast LCG so benchmarks are reproducible across runs and
 * platforms without depending on libc rand() quality. */
static ut32 lcg_state;

static void lcg_seed(ut32 s) {
	lcg_state = s ? s : 0xdeadbeefu;
}

static ut32 lcg_next(void) {
	lcg_state = lcg_state * 1103515245u + 12345u;
	return lcg_state;
}

/* Fill `buf` with `size` pseudo-random bytes (printable, so the same buffer
 * doubles as a string for line-diff benchmarks if needed). */
static void fill_random(ut8 *buf, ut32 size, ut32 seed) {
	lcg_seed(seed);
	for (ut32 i = 0; i < size; i++) {
		/* keep it printable so line/byte diff trees behave similarly */
		buf[i] = 0x20 + (lcg_next() % (0x7f - 0x20));
	}
}

/* Build two buffers `a` and `b` that share most content but differ in a few
 * scattered windows. `divergence_pct` is the approximate percentage of bytes
 * in `b` that are mutated relative to `a`. */
static void make_pair_similar(ut8 *a, ut8 *b, ut32 size, ut32 divergence_pct) {
	fill_random(a, size, 0xc0ffee);
	memcpy(b, a, size);
	lcg_seed(0xfeedface);
	ut32 changes = (size * divergence_pct) / 100;
	for (ut32 i = 0; i < changes; i++) {
		ut32 idx = lcg_next() % size;
		b[idx] ^= (ut8)(lcg_next() | 1);
	}
}

/* Build two completely unrelated buffers (worst-case for the longest-match
 * search). */
static void make_pair_divergent(ut8 *a, ut8 *b, ut32 size) {
	fill_random(a, size, 0xa5a5a5a5u);
	fill_random(b, size, 0x5a5a5a5au);
}

/* Build a multi-line string of `n_lines` lines, each ~`line_len` bytes,
 * pseudo-random within an alphabet that produces realistic line diversity. */
static char *make_lines(ut32 n_lines, ut32 line_len, ut32 seed) {
	ut32 total = n_lines * (line_len + 1) + 1;
	char *out = malloc(total);
	if (!out) {
		return NULL;
	}
	lcg_seed(seed);
	ut32 pos = 0;
	for (ut32 i = 0; i < n_lines; i++) {
		for (ut32 j = 0; j < line_len; j++) {
			out[pos++] = 'a' + (lcg_next() % 26);
		}
		out[pos++] = '\n';
	}
	out[pos] = '\0';
	return out;
}

/* Build a "modified" version of `src` where roughly `mod_pct` % of lines are
 * altered. Lines are simply replaced with a fresh random line of the same
 * length, so byte-for-byte similarity is preserved at the structural level. */
static char *make_lines_modified(const char *src, ut32 mod_pct, ut32 seed) {
	size_t len = strlen(src);
	char *out = malloc(len + 1);
	if (!out) {
		return NULL;
	}
	memcpy(out, src, len + 1);
	lcg_seed(seed);
	/* Walk lines and rewrite some of them in place */
	size_t i = 0;
	while (i < len) {
		size_t j = i;
		while (j < len && out[j] != '\n') {
			j++;
		}
		if ((lcg_next() % 100) < mod_pct) {
			for (size_t k = i; k < j; k++) {
				out[k] = 'a' + (lcg_next() % 26);
			}
		}
		i = j + 1;
	}
	return out;
}

// ------------------------------------------------------------
// Bytes-diff benchmarks
// ------------------------------------------------------------

static void bench_bytes_new_similar_medium(RzTable *t_out) {
	ut8 *a = malloc(BUF_MEDIUM);
	ut8 *b = malloc(BUF_MEDIUM);
	make_pair_similar(a, b, BUF_MEDIUM, 5);

	RZ_BENCH_RUN("[RzDiff] rz_diff_bytes_new (similar, 4KB)", t_out, ITER_MEDIUM, {
		RzDiff *d = rz_diff_bytes_new(a, BUF_MEDIUM, b, BUF_MEDIUM);
		rz_diff_free(d);
	});

	free(a);
	free(b);
}

static void bench_bytes_new_divergent_medium(RzTable *t_out) {
	ut8 *a = malloc(BUF_MEDIUM);
	ut8 *b = malloc(BUF_MEDIUM);
	make_pair_divergent(a, b, BUF_MEDIUM);

	RZ_BENCH_RUN("[RzDiff] rz_diff_bytes_new (divergent, 4KB)", t_out, ITER_MEDIUM, {
		RzDiff *d = rz_diff_bytes_new(a, BUF_MEDIUM, b, BUF_MEDIUM);
		rz_diff_free(d);
	});

	free(a);
	free(b);
}

static void bench_bytes_matches_similar_small(RzTable *t_out) {
	ut8 *a = malloc(BUF_SMALL);
	ut8 *b = malloc(BUF_SMALL);
	make_pair_similar(a, b, BUF_SMALL, 5);

	RZ_BENCH_RUN("[RzDiff] rz_diff_matches_new (similar, 256B)", t_out, ITER_LIGHT, {
		RzDiff *d = rz_diff_bytes_new(a, BUF_SMALL, b, BUF_SMALL);
		RzList *m = rz_diff_matches_new(d);
		rz_list_free(m);
		rz_diff_free(d);
	});

	free(a);
	free(b);
}

static void bench_bytes_matches_similar_medium(RzTable *t_out) {
	ut8 *a = malloc(BUF_MEDIUM);
	ut8 *b = malloc(BUF_MEDIUM);
	make_pair_similar(a, b, BUF_MEDIUM, 5);

	RZ_BENCH_RUN("[RzDiff] rz_diff_matches_new (similar, 4KB)", t_out, ITER_HEAVY, {
		RzDiff *d = rz_diff_bytes_new(a, BUF_MEDIUM, b, BUF_MEDIUM);
		RzList *m = rz_diff_matches_new(d);
		rz_list_free(m);
		rz_diff_free(d);
	});

	free(a);
	free(b);
}

static void bench_bytes_matches_divergent_medium(RzTable *t_out) {
	ut8 *a = malloc(BUF_MEDIUM);
	ut8 *b = malloc(BUF_MEDIUM);
	make_pair_divergent(a, b, BUF_MEDIUM);

	/* Divergent case is the pathological one for the inner loop; keep iter
	 * count modest. */
	RZ_BENCH_RUN("[RzDiff] rz_diff_matches_new (divergent, 4KB)", t_out, ITER_HEAVY, {
		RzDiff *d = rz_diff_bytes_new(a, BUF_MEDIUM, b, BUF_MEDIUM);
		RzList *m = rz_diff_matches_new(d);
		rz_list_free(m);
		rz_diff_free(d);
	});

	free(a);
	free(b);
}

static void bench_bytes_opcodes_similar_medium(RzTable *t_out) {
	ut8 *a = malloc(BUF_MEDIUM);
	ut8 *b = malloc(BUF_MEDIUM);
	make_pair_similar(a, b, BUF_MEDIUM, 5);

	RZ_BENCH_RUN("[RzDiff] rz_diff_opcodes_new (similar, 4KB)", t_out, ITER_HEAVY, {
		RzDiff *d = rz_diff_bytes_new(a, BUF_MEDIUM, b, BUF_MEDIUM);
		RzList *ops = rz_diff_opcodes_new(d);
		rz_list_free(ops);
		rz_diff_free(d);
	});

	free(a);
	free(b);
}

static void bench_bytes_opcodes_grouped_similar_medium(RzTable *t_out) {
	ut8 *a = malloc(BUF_MEDIUM);
	ut8 *b = malloc(BUF_MEDIUM);
	make_pair_similar(a, b, BUF_MEDIUM, 5);

	RZ_BENCH_RUN("[RzDiff] rz_diff_opcodes_grouped_new (similar, 4KB)", t_out, ITER_HEAVY, {
		RzDiff *d = rz_diff_bytes_new(a, BUF_MEDIUM, b, BUF_MEDIUM);
		RzList *g = rz_diff_opcodes_grouped_new(d, RZ_DIFF_DEFAULT_N_GROUPS);
		rz_list_free(g);
		rz_diff_free(d);
	});

	free(a);
	free(b);
}

static void bench_bytes_ratio_similar_medium(RzTable *t_out) {
	ut8 *a = malloc(BUF_MEDIUM);
	ut8 *b = malloc(BUF_MEDIUM);
	make_pair_similar(a, b, BUF_MEDIUM, 5);

	RZ_BENCH_RUN("[RzDiff] rz_diff_ratio (similar, 4KB)", t_out, ITER_HEAVY, {
		RzDiff *d = rz_diff_bytes_new(a, BUF_MEDIUM, b, BUF_MEDIUM);
		double r = 0.0;
		rz_diff_ratio(d, &r);
		rz_diff_free(d);
	});

	free(a);
	free(b);
}

static void bench_bytes_unified_similar_medium(RzTable *t_out) {
	ut8 *a = malloc(BUF_MEDIUM);
	ut8 *b = malloc(BUF_MEDIUM);
	make_pair_similar(a, b, BUF_MEDIUM, 5);

	RZ_BENCH_RUN("[RzDiff] rz_diff_unified_text bytes (similar, 4KB)", t_out, ITER_HEAVY, {
		RzDiff *d = rz_diff_bytes_new(a, BUF_MEDIUM, b, BUF_MEDIUM);
		char *s = rz_diff_unified_text(d, NULL, NULL, false, false);
		free(s);
		rz_diff_free(d);
	});

	free(a);
	free(b);
}

// ------------------------------------------------------------
// Lines-diff benchmarks
// ------------------------------------------------------------

static void bench_lines_matches_similar(RzTable *t_out) {
	char *a = make_lines(200, 40, 0x1111);
	char *b = make_lines_modified(a, 10, 0x2222);

	RZ_BENCH_RUN("[RzDiff] rz_diff_matches_new lines (~200 lines, 10% changed)", t_out, ITER_HEAVY, {
		RzDiff *d = rz_diff_lines_new(a, b, NULL);
		RzList *m = rz_diff_matches_new(d);
		rz_list_free(m);
		rz_diff_free(d);
	});

	free(a);
	free(b);
}

static void bench_lines_unified_similar(RzTable *t_out) {
	char *a = make_lines(200, 40, 0x1111);
	char *b = make_lines_modified(a, 10, 0x2222);

	RZ_BENCH_RUN("[RzDiff] rz_diff_unified_text lines (~200 lines, 10% changed)", t_out, ITER_HEAVY, {
		RzDiff *d = rz_diff_lines_new(a, b, NULL);
		char *s = rz_diff_unified_text(d, NULL, NULL, false, false);
		free(s);
		rz_diff_free(d);
	});

	free(a);
	free(b);
}

// ------------------------------------------------------------
// Distance benchmarks
// ------------------------------------------------------------

static void bench_myers_distance_similar(RzTable *t_out) {
	ut8 *a = malloc(BUF_SMALL);
	ut8 *b = malloc(BUF_SMALL);
	make_pair_similar(a, b, BUF_SMALL, 5);

	RZ_BENCH_RUN("[RzDiff] rz_diff_myers_distance (similar, 256B)", t_out, ITER_MEDIUM, {
		ut32 dist = 0;
		rz_diff_myers_distance(a, BUF_SMALL, b, BUF_SMALL, &dist, NULL);
	});

	free(a);
	free(b);
}

static void bench_myers_distance_divergent(RzTable *t_out) {
	ut8 *a = malloc(BUF_SMALL);
	ut8 *b = malloc(BUF_SMALL);
	make_pair_divergent(a, b, BUF_SMALL);

	/* O(ND) blows up when D ~ N; keep iter count modest. */
	RZ_BENCH_RUN("[RzDiff] rz_diff_myers_distance (divergent, 256B)", t_out, ITER_HEAVY, {
		ut32 dist = 0;
		rz_diff_myers_distance(a, BUF_SMALL, b, BUF_SMALL, &dist, NULL);
	});

	free(a);
	free(b);
}

static void bench_levenshtein_distance_similar(RzTable *t_out) {
	ut8 *a = malloc(BUF_SMALL);
	ut8 *b = malloc(BUF_SMALL);
	make_pair_similar(a, b, BUF_SMALL, 5);

	RZ_BENCH_RUN("[RzDiff] rz_diff_levenshtein_distance (similar, 256B)", t_out, ITER_MEDIUM, {
		ut32 dist = 0;
		rz_diff_levenshtein_distance(a, BUF_SMALL, b, BUF_SMALL, &dist, NULL);
	});

	free(a);
	free(b);
}

static void bench_levenshtein_distance_divergent(RzTable *t_out) {
	ut8 *a = malloc(BUF_SMALL);
	ut8 *b = malloc(BUF_SMALL);
	make_pair_divergent(a, b, BUF_SMALL);

	/* Levenshtein is O(N*M) regardless of similarity, so size is the only
	 * knob. */
	RZ_BENCH_RUN("[RzDiff] rz_diff_levenshtein_distance (divergent, 256B)", t_out, ITER_HEAVY, {
		ut32 dist = 0;
		rz_diff_levenshtein_distance(a, BUF_SMALL, b, BUF_SMALL, &dist, NULL);
	});

	free(a);
	free(b);
}

// ------------------------------------------------------------
// Hash helper benchmark (the building block used by elem_hash)
// ------------------------------------------------------------

static void bench_hash_data_64B(RzTable *t_out) {
	ut8 *a = malloc(64);
	fill_random(a, 64, 0xbadc0de);

	RZ_BENCH_RUN("[RzDiff] rz_diff_hash_data (64B)", t_out, ITER_TINY, {
		ut32 h = rz_diff_hash_data(a, 64);
		RZ_DONT_OPTIMIZE(ut32, h);
	});

	free(a);
}

static void bench_hash_data_1KB(RzTable *t_out) {
	ut8 *a = malloc(1024);
	fill_random(a, 1024, 0xbadc0de);

	RZ_BENCH_RUN("[RzDiff] rz_diff_hash_data (1KB)", t_out, ITER_TINY, {
		ut32 h = rz_diff_hash_data(a, 1024);
		RZ_DONT_OPTIMIZE(ut32, h);
	});

	free(a);
}

// ------------------------------------------------------------
// Larger end-to-end scenario (gated to a small iter count)
// ------------------------------------------------------------

static void bench_bytes_unified_large_similar(RzTable *t_out) {
	ut8 *a = malloc(BUF_LARGE);
	ut8 *b = malloc(BUF_LARGE);
	make_pair_similar(a, b, BUF_LARGE, 2);

	/* 32KB end-to-end is the heaviest non-torture scenario. Iteration count
	 * is kept low so the whole bench suite still fits comfortably inside the
	 * `benchmark()` timeout configured in test/bench/meson.build. */
	RZ_BENCH_RUN("[RzDiff] rz_diff_unified_text bytes (similar, 32KB)", t_out, 8, {
		RzDiff *d = rz_diff_bytes_new(a, BUF_LARGE, b, BUF_LARGE);
		char *s = rz_diff_unified_text(d, NULL, NULL, false, false);
		free(s);
		rz_diff_free(d);
	});

	free(a);
	free(b);
}

// ------------------------------------------------------------
// Real-world "torture" scenarios
//
// These reproduce, on small (~16-128 KB) buffers, the structural patterns
// the algorithm sees on real binaries. They are kept compact -- each one
// runs only a handful of iterations -- but their *shape* matches what users
// actually hit when they `rz-diff` two firmware images or two builds of the
// same executable.
//
// Buffer sizes were chosen so the suite still finishes comfortably inside
// the meson `benchmark()` timeout, even on the worst-case scenarios
// where Ratcliff/Obershelp degrades.
// ------------------------------------------------------------

/* "Firmware" image generator.
 *
 * Real firmware images for the same device differ in characteristic ways:
 *   - a fixed bootloader region that almost never changes,
 *   - a vector / interrupt table (small, occasional pointer changes),
 *   - a large code region with a handful of changed functions,
 *   - a constant / string pool that grows or shrinks slightly,
 *   - large stretches of 0xFF erased flash padding.
 *
 * We synthesize both versions in a single pass so they share the structure
 * by construction. `delta_seed` controls how V2 diverges from V1. */
static void make_firmware_pair(ut8 *v1, ut8 *v2, ut32 size, ut32 delta_seed) {
	/* Layout, scaled to `size`:
	 *   [0, 1/16)        bootloader  -- byte-identical between v1 and v2
	 *   [1/16, 2/16)     vector table -- a few 4-byte slots differ
	 *   [2/16, 12/16)    code region  -- handful of small "patched functions"
	 *   [12/16, 14/16)   const pool   -- minor edits, plus 16-byte shift
	 *   [14/16, 16/16)   0xFF erase padding -- identical
	 */
	ut32 s1 = size / 16;
	ut32 s2 = size * 2 / 16;
	ut32 s12 = size * 12 / 16;
	ut32 s14 = size * 14 / 16;

	/* Common substrate -- realistic-ish ARM-like instruction byte
	 * distribution: mostly low entropy, lots of recurring opcodes. */
	lcg_seed(0xb0071ea0u);
	for (ut32 i = 0; i < size; i++) {
		ut32 r = lcg_next();
		/* 70% "common opcode" bytes in {0x00, 0x01, 0x20, 0x46, 0x47, 0x68,
		 * 0xB5, 0xBD, 0xE7, 0xF0}, 30% noisy. This produces realistic
		 * collision rates in the elem_hash map. */
		static const ut8 common[] = { 0x00, 0x01, 0x20, 0x46, 0x47, 0x68, 0xB5, 0xBD, 0xE7, 0xF0 };
		v1[i] = (r % 100) < 70 ? common[(r >> 8) % sizeof(common)] : (ut8)(r >> 16);
	}
	/* 0xFF flash erase region. */
	memset(v1 + s14, 0xff, size - s14);

	/* v2 starts as a byte-identical copy. */
	memcpy(v2, v1, size);

	lcg_seed(delta_seed);

	/* Vector table: change ~6 four-byte pointers. */
	for (int i = 0; i < 6; i++) {
		ut32 off = s1 + (lcg_next() % ((s2 - s1) / 4)) * 4;
		ut32 patch = lcg_next();
		memcpy(v2 + off, &patch, 4);
	}

	/* Code region: 8 "patched functions", each a 16-64 byte rewrite at a
	 * random aligned offset. */
	for (int i = 0; i < 8; i++) {
		ut32 off = s2 + ((lcg_next() % ((s12 - s2) / 16)) * 16);
		ut32 patch_len = 16 + (lcg_next() % 49);
		if (off + patch_len > s12) {
			patch_len = s12 - off;
		}
		for (ut32 k = 0; k < patch_len; k++) {
			v2[off + k] = (ut8)lcg_next();
		}
	}

	/* Const pool: shift everything after a midpoint by 16 bytes (simulates
	 * a string being lengthened). This is the slide pattern that defeats
	 * naive byte-wise comparisons. */
	ut32 slide_at = s12 + (s14 - s12) / 2;
	if (slide_at + 16 < s14) {
		memmove(v2 + slide_at + 16, v2 + slide_at, s14 - slide_at - 16);
		for (ut32 k = 0; k < 16; k++) {
			v2[slide_at + k] = (ut8)('A' + (lcg_next() % 26));
		}
	}
}

/* "Big executable" generator (think mid-size ELF / PE / Mach-O):
 *   - identical headers,
 *   - large .text region heavily churned (every ~64 bytes a small patch),
 *   - identical .rodata,
 *   - .bss is all zeros in both.
 *
 * Stresses the hit-map traversal because the .bss zeros all hash to the
 * same value (every elem_hash collision in B gets visited per byte of A). */
static void make_big_exec_pair(ut8 *a, ut8 *b, ut32 size, ut32 delta_seed) {
	ut32 hdr = 1024;
	ut32 text = (size - hdr) * 6 / 10;
	ut32 rodata = (size - hdr) * 2 / 10;
	/* tail (after hdr+text+rodata) is .bss */

	/* Header: small, identical. */
	lcg_seed(0xe1f00000u);
	for (ut32 i = 0; i < hdr; i++) {
		a[i] = (ut8)lcg_next();
	}
	/* Text: dense pseudo-instructions. */
	lcg_seed(0x7e71u);
	for (ut32 i = 0; i < text; i++) {
		a[hdr + i] = (ut8)lcg_next();
	}
	/* Rodata: ASCII strings mostly. */
	lcg_seed(0x0d0d04u);
	for (ut32 i = 0; i < rodata; i++) {
		a[hdr + text + i] = (ut8)(0x20 + (lcg_next() % 0x60));
	}
	/* Bss: zeros. */
	memset(a + hdr + text + rodata, 0, size - hdr - text - rodata);

	memcpy(b, a, size);

	/* Heavily churn .text: ~20% of 16-byte basic-block-sized windows are
	 * fully rewritten in B. */
	lcg_seed(delta_seed);
	for (ut32 off = hdr; off + 16 < hdr + text; off += 16) {
		if ((lcg_next() % 100) < 20) {
			for (ut32 k = 0; k < 16; k++) {
				b[off + k] = (ut8)lcg_next();
			}
		}
	}
}

/* "Memory dump / disk image" generator (think 64+ MB blob, but synthesized
 * at 64-128 KB so the suite stays fast):
 *
 *   - 80% zero-filled (sparse regions, free pages, etc.),
 *   - 15% structured data (page-aligned 4 KB blocks with low-entropy headers),
 *   - 5% high-entropy data (compressed / encrypted regions).
 *
 * The diff between v1 and v2 only touches a handful of 4 KB pages -- the
 * realistic "snapshot N vs snapshot N+1" case. The pathology here is that
 * the zero pages make every zero byte a hash collision in B. */
static void make_memdump_pair(ut8 *a, ut8 *b, ut32 size, ut32 delta_seed) {
	memset(a, 0, size);

	/* Drop in a few structured 4 KB pages at random aligned offsets. */
	lcg_seed(0x9a9eu);
	ut32 n_pages = size / 4096;
	for (ut32 i = 0; i < n_pages; i++) {
		ut32 r = lcg_next() % 100;
		ut32 page = i * 4096;
		if (r < 15) {
			/* Structured page: low-entropy header + body. */
			ut32 hdr_seed = lcg_next();
			for (ut32 k = 0; k < 64; k++) {
				a[page + k] = (ut8)(hdr_seed >> ((k & 3) * 8));
			}
			for (ut32 k = 64; k < 4096 && page + k < size; k++) {
				/* Repeating pattern: lots of intra-page redundancy. */
				a[page + k] = (ut8)('A' + ((k - 64) % 26));
			}
		} else if (r < 20) {
			/* High-entropy page. */
			for (ut32 k = 0; k < 4096 && page + k < size; k++) {
				a[page + k] = (ut8)lcg_next();
			}
		}
		/* else: stays zero */
	}

	memcpy(b, a, size);

	/* Modify a handful of pages in B -- the realistic snapshot diff case. */
	lcg_seed(delta_seed);
	int n_modified = 4;
	for (int i = 0; i < n_modified; i++) {
		ut32 page = ((lcg_next() % n_pages)) * 4096;
		if (page + 4096 > size) {
			continue;
		}
		/* Replace the page body. */
		for (ut32 k = 0; k < 4096; k++) {
			b[page + k] = (ut8)lcg_next();
		}
	}
}

/* Adversarial: every byte in B hashes to the same bucket (all 0x00). This
 * is the pathological input for the longest-match search, since every
 * position in A finds a hit list of length B_size in the hit map. */
static void make_all_zeros_pair(ut8 *a, ut8 *b, ut32 size) {
	memset(a, 0, size);
	memset(b, 0, size);
	/* Tiny perturbation so the diff isn't trivially identical: flip one
	 * byte in the middle of B. */
	if (size > 1) {
		b[size / 2] = 0x01;
	}
}

/* Adversarial: short repeating pattern. Every elem_hash bucket collects
 * size/period entries, and many overlapping matches are found and rejected. */
static void make_repeating_pattern_pair(ut8 *a, ut8 *b, ut32 size) {
	for (ut32 i = 0; i < size; i++) {
		a[i] = (ut8)('A' + (i & 3));
	}
	memcpy(b, a, size);
	/* Inject a couple of small disturbances so we don't trivially match. */
	if (size > 100) {
		b[size / 4] = 'Z';
		b[size / 2] = 'Z';
		b[size * 3 / 4] = 'Z';
	}
}

/* "Block shift" -- A and B are byte-identical except a 1 KB block is moved
 * from one position to another. This is the classic case where a chunked /
 * hashed comparison should still detect both halves of the shift as matches,
 * but a naive byte-by-byte loop has to rediscover them. */
static void make_block_shift_pair(ut8 *a, ut8 *b, ut32 size) {
	lcg_seed(0xb10cu);
	for (ut32 i = 0; i < size; i++) {
		a[i] = (ut8)('a' + (lcg_next() % 26));
	}
	memcpy(b, a, size);
	if (size > 4096) {
		ut32 src = size / 4;
		ut32 dst = size * 3 / 4;
		ut32 blk = 1024;
		ut8 tmp[1024];
		memcpy(tmp, a + src, blk);
		/* Slide the region between src+blk and dst left by blk, then place
		 * tmp at dst-blk. */
		memmove(b + src, a + src + blk, dst - src - blk);
		memcpy(b + dst - blk, tmp, blk);
	}
}

// ------------------------------------------------------------
// Torture benchmarks
//
// Each one runs few iterations -- these are the heavyweight cases. They
// exercise the full pipeline (matches + opcodes + unified_text), since
// that's what real users invoke and that's where regressions are visible.
// ------------------------------------------------------------

/* NOTE: Ratcliff/Obershelp scales worse than quadratic in practice on
 * "similar" inputs because every common byte's hit-list grows with the
 * buffer size and is walked for every position in A. Measured on the
 * current `dev` (May 2026): firmware-like 4 KB ~0.7 s/iter, 8 KB ~3.5 s/iter,
 * 16 KB ~13 s/iter, 32 KB > 60 s/iter. Sizes here are picked so each
 * scenario finishes in a few seconds per iteration -- enough to make the
 * std. deviation meaningful while keeping the whole bench suite under the
 * meson `benchmark()` timeout (120 s). Once PR #6385's chunked
 * comparison lands, these can be cranked back up.
 */
#define TORTURE_FW_SIZE      (8 * 1024) /* synthesized firmware              */
#define TORTURE_EXEC_SIZE    (8 * 1024) /* synthesized executable             */
#define TORTURE_MEMDUMP_SIZE (8 * 1024) /* synthesized memdump-shape blob     */
#define TORTURE_BLOCKSHIFT   (16 * 1024) /* block-shift -- few matches, fast   */
#define TORTURE_ADVERSARY    (2 * 1024) /* pathological hash distributions    */
#define ITER_TORTURE         3 /* must be >= 3 for useful stddev     */
#define ITER_TORTURE_LIGHT   8

static void bench_torture_firmware_pair(RzTable *t_out) {
	ut8 *v1 = malloc(TORTURE_FW_SIZE);
	ut8 *v2 = malloc(TORTURE_FW_SIZE);
	make_firmware_pair(v1, v2, TORTURE_FW_SIZE, 0xa11dau);

	RZ_BENCH_RUN("[RzDiff] torture: firmware v1 vs v2 (8KB, mostly identical)", t_out, ITER_TORTURE, {
		RzDiff *d = rz_diff_bytes_new(v1, TORTURE_FW_SIZE, v2, TORTURE_FW_SIZE);
		char *s = rz_diff_unified_text(d, NULL, NULL, false, false);
		free(s);
		rz_diff_free(d);
	});

	/* Also measure the matches phase in isolation -- the place chunked /
	 * hashed byte comparison primarily speeds up. */
	RZ_BENCH_RUN("[RzDiff] torture: firmware v1 vs v2 (8KB, matches only)", t_out, ITER_TORTURE, {
		RzDiff *d = rz_diff_bytes_new(v1, TORTURE_FW_SIZE, v2, TORTURE_FW_SIZE);
		RzList *m = rz_diff_matches_new(d);
		rz_list_free(m);
		rz_diff_free(d);
	});

	free(v1);
	free(v2);
}

static void bench_torture_big_exec(RzTable *t_out) {
	ut8 *a = malloc(TORTURE_EXEC_SIZE);
	ut8 *b = malloc(TORTURE_EXEC_SIZE);
	make_big_exec_pair(a, b, TORTURE_EXEC_SIZE, 0xbabeu);

	/* With the new stddev / geometric-mean reporting introduced by
	 * rizinorg/rizin#6390 and #6403, we need at least 3 iterations for
	 * those statistics to be meaningful. */
	RZ_BENCH_RUN("[RzDiff] torture: big exec (8KB, .text churn)", t_out, ITER_TORTURE, {
		RzDiff *d = rz_diff_bytes_new(a, TORTURE_EXEC_SIZE, b, TORTURE_EXEC_SIZE);
		RzList *ops = rz_diff_opcodes_new(d);
		rz_list_free(ops);
		rz_diff_free(d);
	});

	/* Ratio-only is significantly cheaper than full unified, and is what
	 * binary-similarity tooling typically wants. */
	RZ_BENCH_RUN("[RzDiff] torture: big exec ratio (8KB)", t_out, ITER_TORTURE, {
		RzDiff *d = rz_diff_bytes_new(a, TORTURE_EXEC_SIZE, b, TORTURE_EXEC_SIZE);
		double r = 0.0;
		rz_diff_ratio(d, &r);
		rz_diff_free(d);
	});

	free(a);
	free(b);
}

static void bench_torture_memdump(RzTable *t_out) {
	ut8 *a = malloc(TORTURE_MEMDUMP_SIZE);
	ut8 *b = malloc(TORTURE_MEMDUMP_SIZE);
	make_memdump_pair(a, b, TORTURE_MEMDUMP_SIZE, 0xd09e7u);

	/* Memdumps are dominated by huge zero regions, which create a single
	 * giant hit list in b_hits and stress the longest-match search far more
	 * than a uniformly-random buffer of the same size. */
	RZ_BENCH_RUN("[RzDiff] torture: memdump (8KB, sparse, few pages changed)", t_out, ITER_TORTURE, {
		RzDiff *d = rz_diff_bytes_new(a, TORTURE_MEMDUMP_SIZE, b, TORTURE_MEMDUMP_SIZE);
		RzList *ops = rz_diff_opcodes_new(d);
		rz_list_free(ops);
		rz_diff_free(d);
	});

	free(a);
	free(b);
}

static void bench_torture_all_zeros(RzTable *t_out) {
	/* Pathological: every byte of A hits a hit-list of length |B| in the
	 * b_hits map. This is the case where any chunked / hashed comparison
	 * scheme has to be careful not to lose to the original on small N. */
	ut8 *a = malloc(TORTURE_ADVERSARY);
	ut8 *b = malloc(TORTURE_ADVERSARY);
	make_all_zeros_pair(a, b, TORTURE_ADVERSARY);

	RZ_BENCH_RUN("[RzDiff] torture: all-zeros adversary (2KB)", t_out, ITER_TORTURE, {
		RzDiff *d = rz_diff_bytes_new(a, TORTURE_ADVERSARY, b, TORTURE_ADVERSARY);
		RzList *m = rz_diff_matches_new(d);
		rz_list_free(m);
		rz_diff_free(d);
	});

	free(a);
	free(b);
}

static void bench_torture_repeating_pattern(RzTable *t_out) {
	/* Short repeating alphabet -> dense hit map, many overlapping matches. */
	ut8 *a = malloc(TORTURE_ADVERSARY);
	ut8 *b = malloc(TORTURE_ADVERSARY);
	make_repeating_pattern_pair(a, b, TORTURE_ADVERSARY);

	RZ_BENCH_RUN("[RzDiff] torture: short repeating pattern (2KB)", t_out, ITER_TORTURE_LIGHT, {
		RzDiff *d = rz_diff_bytes_new(a, TORTURE_ADVERSARY, b, TORTURE_ADVERSARY);
		RzList *m = rz_diff_matches_new(d);
		rz_list_free(m);
		rz_diff_free(d);
	});

	free(a);
	free(b);
}

static void bench_torture_block_shift(RzTable *t_out) {
	/* Two large equal halves separated by a 1 KB block-shift. The matcher
	 * has to find both halves separately. Block-shift is the fastest of the
	 * torture scenarios per byte (very few but very long matches), so we
	 * keep it larger than the other scenarios. */
	ut8 *a = malloc(TORTURE_BLOCKSHIFT);
	ut8 *b = malloc(TORTURE_BLOCKSHIFT);
	make_block_shift_pair(a, b, TORTURE_BLOCKSHIFT);

	RZ_BENCH_RUN("[RzDiff] torture: block shift (16KB, 1KB moved)", t_out, ITER_TORTURE, {
		RzDiff *d = rz_diff_bytes_new(a, TORTURE_BLOCKSHIFT, b, TORTURE_BLOCKSHIFT);
		RzList *ops = rz_diff_opcodes_new(d);
		rz_list_free(ops);
		rz_diff_free(d);
	});

	free(a);
	free(b);
}

/* Distance-only torture for the same firmware shape. Distance algorithms
 * are O(N*D) / O(N*M), so they're the limiting factor on bigger inputs and
 * they live in a totally different code path from matches/opcodes. */
static void bench_torture_distances_firmware(RzTable *t_out) {
	const ut32 size = 8 * 1024;
	ut8 *v1 = malloc(size);
	ut8 *v2 = malloc(size);
	make_firmware_pair(v1, v2, size, 0xd157u);

	RZ_BENCH_RUN("[RzDiff] torture: myers distance firmware-like (4KB)", t_out, ITER_TORTURE, {
		ut32 dist = 0;
		rz_diff_myers_distance(v1, size, v2, size, &dist, NULL);
	});
	RZ_BENCH_RUN("[RzDiff] torture: levenshtein distance firmware-like (4KB)", t_out, ITER_TORTURE, {
		ut32 dist = 0;
		rz_diff_levenshtein_distance(v1, size, v2, size, &dist, NULL);
	});

	free(v1);
	free(v2);
}

// ------------------------------------------------------------
// Main
// ------------------------------------------------------------

int main(void) {
	RzTable *t = rz_table_new();
	RZ_BENCH_TABLE_INIT(t);

	/* Construction-only -- isolates set_b() + b_hits build cost. */
	bench_bytes_new_similar_medium(t);
	bench_bytes_new_divergent_medium(t);

	/* Core diffing pipeline. */
	bench_bytes_matches_similar_small(t);
	bench_bytes_matches_similar_medium(t);
	bench_bytes_matches_divergent_medium(t);
	bench_bytes_opcodes_similar_medium(t);
	bench_bytes_opcodes_grouped_similar_medium(t);

	/* Ratio. */
	bench_bytes_ratio_similar_medium(t);

	/* End-to-end with formatting. */
	bench_bytes_unified_similar_medium(t);
	bench_bytes_unified_large_similar(t);

	/* Line-diff variants. */
	bench_lines_matches_similar(t);
	bench_lines_unified_similar(t);

	/* Distance algorithms. */
	bench_myers_distance_similar(t);
	bench_myers_distance_divergent(t);
	bench_levenshtein_distance_similar(t);
	bench_levenshtein_distance_divergent(t);

	/* Internal helpers. */
	bench_hash_data_64B(t);
	bench_hash_data_1KB(t);

	/* Real-world torture scenarios. */
	bench_torture_firmware_pair(t);
	bench_torture_big_exec(t);
	bench_torture_memdump(t);
	bench_torture_block_shift(t);
	bench_torture_repeating_pattern(t);
	bench_torture_all_zeros(t);
	bench_torture_distances_firmware(t);

	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	return 0;
}
