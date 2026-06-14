// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_DIFF_INTERNAL_H
#define RZ_DIFF_INTERNAL_H

#include <rz_util.h>
#include <rz_diff.h>

#define FASTCDC_MINSIZE          64
#define FASTCDC_MAXSIZE          (1 << 30) // 1GiB
#define FASTCDC_NORM_LVL_DEFAULT FASTCDC_NORM_LVL_2
#define FASTCDC_AVG_SIZE_DEFAULT (1024 * 1024) // 1miB
#define FASTCDC_SEED_DEFAULT     0

typedef enum {
	FASTCDC_NORM_DISABLED = 0,
	FASTCDC_NORM_LVL_1,
	FASTCDC_NORM_LVL_2,
	FASTCDC_NORM_LVL_3,
	// enum size
	FASTCDC_NORM_LVL_ENUM_SIZE,
} NormLvl;

typedef struct fastcdc_options_t {
	ut64 average_size; ///< A power of 2 and must be within [64B, 1GiB].
	ut64 min_size; ///< The minimum allowed chunk size.
	ut64 max_size; ///< The maximum allowed chunk size.
	ut32 norm_level; ///< The chunk normalization level (see NormLvl).
	ut64 chunk_size; ///< Chunk size.
	ut64 seed; ///< When non-zero is used to randomize the gear table.
} FastCDCOptions;

typedef struct fastcdc_t {
	size_t fp_norm_size; ///< Fingerprint normalized buffer size
	size_t fp_min_size; ///< Fingerprint min buffer size
	size_t fp_max_size; ///< Fingerprint max buffer size

	const ut64 *table; ///< Gear table generated via seed option
	ut64 mask_s; ///< Stricter mask, used in [min_size, avg_size)
	ut64 mask_l; ///< Looser mask, used in [avg_size, max_size)
} FastCDC;

typedef struct fastcdc_chunk_t {
	const ut8 *data; ///< Chunk data
	size_t length; ///< length of the chunk data in bytes
	ut64 offset; ///< offset location of this chunk from the beginning.
	ut64 fingerprint; ///< rolling hash for the chunk data.
} FastCDCChunk;

typedef struct fastcdc_reader_t {
	const ut8 *bytes; ///< Bytes pointer
	size_t leftovers; ///< Number of bytes left
} FastCDCReader;

typedef struct fastcdc_chunker_t {
	ut8 *buf; ///< Buffer containing chunk data
	size_t buf_size; ///< Buffer size
	size_t position; ///< Current location on the buffer
	size_t n_read; ///< Total number of bytes read till now.
	bool eof; ///< When true stops calculating the fingerprint
	FastCDCReader reader; ///< Buffer to read from
	FastCDC state; ///< Internal state of FastCDC
} FastCDCChunker;

RZ_IPI void rz_fastcdc_opts_defaults(RZ_NONNULL FastCDCOptions *opts, ut64 avg_size, NormLvl norm, ut64 seed);
RZ_IPI bool rz_fastcdc_init(RZ_NONNULL FastCDC *state, RZ_NONNULL const FastCDCOptions *opts);
RZ_IPI bool rz_fastcdc_init2(RZ_NONNULL FastCDC *state, ut64 avg_size);
RZ_IPI void rz_fastcdc_fini(RZ_NULLABLE FastCDC *state);
RZ_IPI size_t rz_fastcdc_fingerprint(RZ_NONNULL const FastCDC *state, RZ_NONNULL const ut8 *data, size_t data_size, RZ_NONNULL ut64 *fingerprint);

RZ_IPI bool rz_fastcdc_chunker_init(RZ_NONNULL FastCDCChunker *chunker, RZ_NONNULL const FastCDCOptions *opts, RZ_NONNULL const ut8 *bytes, size_t size);
RZ_IPI bool rz_fastcdc_chunker_init2(RZ_NONNULL FastCDCChunker *chunker, ut64 avg_size, RZ_NONNULL const ut8 *bytes, size_t size);
RZ_IPI void rz_fastcdc_chunker_fini(RZ_NULLABLE FastCDCChunker *chunker);
RZ_IPI bool rz_fastcdc_chunker_next_chunk(RZ_NONNULL FastCDCChunker *chunker, RZ_NONNULL RZ_OUT FastCDCChunk *chunk);

#endif /* RZ_DIFF_INTERNAL_H */
