// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include "diff_internal.h"

// 2048 random bytes (in blocks of 64 bits) for the rolling hash function
static const ut64 random_table[256] = {
	// clang-format off
	0xa7bdc50f69cf0b07, 0xc8cfc0b8f8ab08ce, 0x4b87bc1d5786a71d, 0xdaa0876d9c63ea1e,
	0xe4eb3800a86857dd, 0x610ee07eb44e3f99, 0x15d03de39cfd2df4, 0x3b7d82bc31977de2,
	0xc21d5d0a8609ddd3, 0x4f30f537408575fd, 0x8606427cd861e46c, 0x5e38dd4c35d4a5f6,
	0x311c06f570b21f8e, 0xaf508a0752dc848c, 0x05117ea02963c770, 0x13b394f77a0be9a2,
	0xf8153d1e21e50676, 0xd1a379f10d965099, 0x9d63e99c7e721fd9, 0x853c45f5f070d198,
	0x9644897f957d628a, 0x7728ab0239e43162, 0xe084c2043be723f4, 0x40d1f4a3e27a2454,
	0x2c0e1cbff5c1ea67, 0x5bad5ff676d1804d, 0x31b97a272cbbb99e, 0x1cf8fa72ba3ea3d1,
	0x246102033f517740, 0xac4e6b31fd3d0cfd, 0xd9c17f6f1b79a073, 0xa3ef35d32a01bac6,
	0x0c8b93dda27cafec, 0xa8095ded6bc1cfb0, 0xa43faa7a70e6ad3e, 0x3a3f71434b7bac9e,
	0xa54c6c9a90b1b2fd, 0x64001f19e386d88e, 0xe041e9569ff6be5f, 0x9f4d87f1269dd452,
	0x908df5dd442689da, 0x46e10f40cbd3cb3d, 0xe1577f6fa682ff21, 0x01837bfaedf4aa6f,
	0x373a491c6c696be2, 0xf280da91f12d9c9d, 0x976acfb67285ef4c, 0xc84404ea9a167cdb,
	0xa48ad6037911bfcc, 0x7a6217dfa15ed0ad, 0x1ae7c7341d9dc6f0, 0x366c3d4eea9de53c,
	0x96f50c069a67387a, 0xc1ea576f6d704b80, 0x654292fd45e3a950, 0xabc6eed45a573fe2,
	0xff1815232b3d96dd, 0xd6296cbd494c9ccd, 0x59c7c7324ee08a52, 0x3d70366519260b12,
	0x8025997db91bffb7, 0xa872fd22e06bdd0b, 0x49b7234294c1b6d2, 0x12d7a036bdcad010,
	0x30bf2e84e3e65159, 0x7f8965124e635f16, 0xee5f5584c24a2ab0, 0xe2de05824a1fd22f,
	0x49e3ab20e7766d82, 0x84404f379c4a2edc, 0x8933d690727dfb60, 0xac465341b1fc1219,
	0x23df731c1db539c3, 0x293d9b574772030a, 0x805da867b9672e0d, 0xb37d808d39f8c3fe,
	0x8c40f87cae187050, 0x00c1bb0e5af5ab8a, 0xdc71048b268d38da, 0x06195743331c607a,
	0x6c47149b8ab7fd76, 0x50c77edc02a7de25, 0x4664f60a01e40a8e, 0xb87e7171e7ae32a0,
	0x1477973d2b316c40, 0x8a04bf956dd6781a, 0x5cde37eeec06b358, 0x1670da9adae373d8,
	0xb74169c437f526ea, 0xf049364843138606, 0xe3f0d970f68e5eb6, 0xb011b65cbb01c463,
	0x32f1be2d0f37c413, 0xd82764d085273e80, 0xc96eb3b5a2aa51ad, 0x60c2762149e2f20b,
	0xef1131ce68ea765b, 0x105733dd5dc6a7a4, 0xd1b7b34461cd8c4f, 0xcd2f678bb2773aa8,
	0x054fec9b26362c2c, 0x6dc9f53696043143, 0x4e55297177d74c64, 0x85ce751edf1703db,
	0x4292228124a3af30, 0x58f69783caeb5341, 0x847ff4bffdd61243, 0xc91aca999e9f099f,
	0x0b8788e4012cde0d, 0xe23c13739c9e3c95, 0xb8ae41e92552bc2a, 0x9b493b00486f459f,
	0xa2a4c82a05707181, 0x16119959d27c65bc, 0xa88a98134d3ea18f, 0xa603be4fbf6f0941,
	0x7835a10764a322a4, 0xf7625cfee6bc9007, 0xce83982ff05ca58d, 0x099c5c034b458baa,
	0xa92f2727605f7d54, 0x2db1e88dcb4acf3a, 0x695d777fd8b679d8, 0x25d16746f080f390,
	0x8063a4d40c3ac4c4, 0x53a4c92ebaf00209, 0x7e189ad4bd66c9cf, 0x7fdd547d4e4177aa,
	0x8259ba24e6900bb6, 0x313967125e76a24a, 0x1209c7d076d8dc8e, 0xa4cce6e130bb00d1,
	0xa4c7d3e425a825fc, 0xbe64c22e1e04e5d9, 0xe8a854813b70fa39, 0x047484e20f1ac73d,
	0x8b5d13ee73957bb1, 0x682841a2e767f130, 0x1ef527464f634b66, 0x8297b6c8e61b6f1c,
	0x745d5aca0cdec668, 0x332776d11116f033, 0x69e9ac11c9024577, 0x87b9cd5984695874,
	0x73eef22636b6f6b9, 0x4e81bd9cd69bbc4d, 0x28f5d68b4293dd4f, 0x036b53c0777dd1ac,
	0x8be44387921795c0, 0xa4fe431a4345c51d, 0xeda9862e1177b050, 0xc14d30ed068c3b08,
	0xc3a3ac941fe6da99, 0x54dc2b93cf0028e8, 0xadbf86a3b1c05829, 0x326a82e63a3d7e6b,
	0x96d487bc8c9f62c4, 0xc61dedfe09cc7d9d, 0x2cab308f349fe2b5, 0x9ffc6f56212f3804,
	0x4895e7a10c2d2435, 0x678db61a044f7ac8, 0x1ce84453201683a5, 0x80827f93ecb08696,
	0xaae21c46a32dd4e5, 0xf34a90ee786ca2df, 0xc3fea7ba7100135c, 0xc733d390b84b8ebe,
	0xdb6de57979a4a9f6, 0xc40e611525194a7a, 0x5ca0ba5daed30882, 0x7de89bf0ec3a5408,
	0xa4984bb41755518d, 0x82c9dda1a9fde9a9, 0xd2539ddc4ce55df2, 0xf89b9478617b5a36,
	0x1fa878b20f20d322, 0xfcdda7d5c3f3e3cc, 0x11bb8cb0e80b621c, 0xf70ca11b5d521fe9,
	0x1cea9b012d53bfdd, 0x4030feed87c68187, 0xbbfca4caecb0efa1, 0x9899988a97382900,
	0xf817557dd0b90a2a, 0x2aeb5123bcc26b98, 0x0af4ce4abd2338ee, 0xf427f1ee9d3e3dc7,
	0x9c369f3aef55e205, 0x6cb1d938274d3ec7, 0x04ef6f3854925851, 0xb8ff781f9eb193ae,
	0xbc816c42588c9ccf, 0x1fb5e4025af6755e, 0xde631b9d570a6399, 0x734d2cfec10f2099,
	0xda0f53c4bca3ece6, 0xc550a57b5a9a00b1, 0xa0ffd4405fbde53d, 0x231a0163de7d1328,
	0xb6bf4b2f6aec3ffe, 0x8e09c149fbc3f5db, 0xa5d25284ab6842be, 0xec77fcc384989927,
	0xb88ab7fdf39780e5, 0x1831dd9f7bd73e72, 0x97ea230f6099505c, 0xb3b7986689a907f7,
	0x273be14ba0c475ba, 0xb511e2b4f03f3b5b, 0xf1ea636663459cf3, 0x16016291c3f47ad6,
	0x4232b457036eba3f, 0xc712345bec1df3e6, 0x5001350f623d5f9e, 0x1332757509bf1bfd,
	0x05266240892f23c1, 0xf40b5c36a53c787a, 0x2e04054e8dc24b72, 0x28629062c0f38866,
	0xa4c6d5125e07a9c3, 0x74a6abf83045b7f8, 0xbc3dc0777c574be5, 0x7c0bdd32c444c8ba,
	0xcc265f6115b439c5, 0x58c4e18bf3a9b732, 0x992e6cfdb44a176e, 0x928be5bd0ec86ed9,
	0x0a255ac4548d14e1, 0x7a6e9ad6a4669f60, 0xbbb2ed6436a07d3a, 0x0d435065481aa98f,
	0x561fb4bab6e65293, 0xe15864b47f960f60, 0x0109a1d5d0dcb3c7, 0x23cc53c6a89bbd1e,
	0xa3756b5fa84fac6b, 0x215ac2717ebfe574, 0x2b44f7b31fd245c8, 0xefe7345c410b0af2,
	0x545964387fb5c958, 0x2c13e6e70242d9fe, 0xdfb3cfaa3525951a, 0xe2147cc2d11229e9,
	0xdf48025b1ec8fe1d, 0xdefbc923ed269044, 0x1bbfce855d32e696, 0x8e1df2acf5b28361,
	0x5e03f19e91ba7510, 0x080403eba2ac0ed9, 0xda661c998509e5c0, 0xb4cf6eecf4a4560e,
	0x0100f393105d9268, 0xc463e510f1c9b186, 0xd12aede58d0f8321, 0x78d0600590ef5b82,
	// clang-format on
};

/**
 * \brief      Initializes the FastCDCOptions with a given avg_size
 *
 * \param      opts      The options to initialize
 * \param[in]  avg_size  The average size
 * \param[in]  norm      The normalize level (see NormLvl)
 * \param[in]  seed      The seed to use
 */
RZ_IPI void rz_fastcdc_opts_defaults(RZ_NONNULL FastCDCOptions *opts, ut64 avg_size, NormLvl norm, ut64 seed) {
	rz_return_if_fail(opts);
	if (avg_size < 1) {
		avg_size = FASTCDC_AVG_SIZE_DEFAULT;
	}

	opts->average_size = avg_size;
	if (opts->min_size < 1) {
		opts->min_size = (avg_size / 4);
		if (opts->min_size < FASTCDC_MINSIZE) {
			opts->min_size = FASTCDC_MINSIZE;
		}
	}
	if (opts->max_size < 1) {
		opts->max_size = (avg_size * 4);
		if (opts->max_size > FASTCDC_MAXSIZE) {
			opts->max_size = FASTCDC_MAXSIZE;
		}
	}
	if (opts->chunk_size < 1) {
		opts->chunk_size = opts->max_size * 2;
	}
	opts->norm_level = norm;
	opts->seed = seed;
}

static bool fastcdc_opts_validate(const FastCDCOptions *opts) {
	if (opts->average_size < 1) {
		RZ_LOG_ERROR("fastcdc: `average_size` is required to be > 0\n");
		return false;
	} else if (opts->min_size < FASTCDC_MINSIZE || opts->min_size > FASTCDC_MAXSIZE) {
		RZ_LOG_ERROR("fastcdc: `min_size` must between [64B, 1GiB] in size\n");
		return false;
	} else if (opts->max_size < FASTCDC_MINSIZE || opts->max_size > FASTCDC_MAXSIZE) {
		RZ_LOG_ERROR("fastcdc: `max_size` must between [64B, 1GiB] in size\n");
		return false;
	} else if (opts->max_size <= opts->min_size) {
		RZ_LOG_ERROR("fastcdc: `min_size` must be less than max_size\n");
		return false;
	} else if (opts->average_size > opts->max_size || opts->average_size < opts->min_size) {
		RZ_LOG_ERROR("fastcdc: `average_size` must be betweeen (min_size, max_size)\n");
		return false;
	} else if (opts->norm_level < FASTCDC_NORM_DISABLED || opts->norm_level >= FASTCDC_NORM_LVL_ENUM_SIZE) {
		RZ_LOG_ERROR("fastcdc: `norm_level` must be 0, 1, 2 or 3\n");
		return false;
	} else if (opts->chunk_size <= opts->max_size) {
		RZ_LOG_ERROR("fastcdc: `chunk_size`, must be at least max_size\n");
		return false;
	}
	return true;
}

static bool fastcdc_init_table(FastCDC *state, ut64 seed) {
	if (!seed) {
		// no seed, so we use the random table as is.
		state->table = &random_table[0];
		return true;
	}

	ut64 *table = (ut64 *)malloc(sizeof(random_table));
	if (!table) {
		return false;
	}

	for (size_t i = 0; i < RZ_ARRAY_SIZE(random_table); ++i) {
		table[i] = random_table[i] ^ seed;
	}
	state->table = table;

	return true;
}

/**
 * \brief      Initializes the FastCDC state structure using a given configuration.
 *
 * \param      state  The state to initialize
 * \param[in]  opts   The configuration to use
 *
 * \return     On success returns true.
 */
RZ_IPI bool rz_fastcdc_init(RZ_NONNULL FastCDC *state, RZ_NONNULL const FastCDCOptions *opts) {
	rz_return_val_if_fail(state && opts, false);

	if (!fastcdc_opts_validate(opts) ||
		!fastcdc_init_table(state, opts->seed)) {
		return false;
	}

	ut64 bits = round(log2(opts->average_size));
	ut64 small_bits = bits + opts->norm_level;
	ut64 large_bits = bits - opts->norm_level;

	state->fp_min_size = opts->min_size;
	state->fp_max_size = opts->max_size;
	state->fp_norm_size = opts->average_size;
	state->mask_s = (1 << small_bits) - 1;
	state->mask_l = (1 << large_bits) - 1;

	return true;
}

/**
 * \brief      Initializes the FastCDC state structure using the avg size
 *
 * \param      state     The state to initialize
 * \param[in]  avg_size  The average size to use
 *
 * \return     On success returns true.
 */
RZ_IPI bool rz_fastcdc_init2(RZ_NONNULL FastCDC *state, ut64 avg_size) {
	rz_return_val_if_fail(state, false);

	FastCDCOptions opts = { 0 };
	rz_fastcdc_opts_defaults(&opts, avg_size, FASTCDC_NORM_LVL_DEFAULT, FASTCDC_SEED_DEFAULT);
	return rz_fastcdc_init(state, &opts);
}

/**
 * \brief      Finalize the FastCDC state structure
 *
 * \param      state  The state structure to finalize
 */
RZ_IPI void rz_fastcdc_fini(RZ_NULLABLE FastCDC *state) {
	if (!state) {
		return;
	}
	if (state->table != random_table) {
		free((void *)state->table);
	}
}

/**
 * \brief      Initializes the FastCDC state structure using a given configuration.
 *
 * \param      chunker  The chunker to initialize
 * \param[in]  opts     The configuration to use
 * \param      bytes    The buffer to read from
 * \param      size     The size of the buffer to read from
 */
RZ_IPI bool rz_fastcdc_chunker_init(RZ_NONNULL FastCDCChunker *chunker, RZ_NONNULL const FastCDCOptions *opts, RZ_NONNULL const ut8 *bytes, size_t size) {
	rz_return_val_if_fail(chunker && opts && bytes, false);

	if (!rz_fastcdc_init(&chunker->state, opts)) {
		return false;
	}

	// initial status is always an empty buffer.
	chunker->buf_size = opts->chunk_size;
	chunker->position = opts->chunk_size;
	chunker->buf = malloc(opts->chunk_size);
	chunker->reader.bytes = bytes;
	chunker->reader.leftovers = size;

	return chunker->buf != NULL;
}

/**
 * \brief      Initializes the FastCDC state structure using the avg size
 *
 * \param      chunker   The chunker to initialize
 * \param[in]  avg_size  The average size to use
 * \param      bytes     The buffer to read from
 * \param      size      The size of the buffer to read from
 */
RZ_IPI bool rz_fastcdc_chunker_init2(RZ_NONNULL FastCDCChunker *chunker, ut64 avg_size, RZ_NONNULL const ut8 *bytes, size_t size) {
	rz_return_val_if_fail(chunker && bytes, false);

	FastCDCOptions opts = { 0 };
	rz_fastcdc_opts_defaults(&opts, avg_size, FASTCDC_NORM_LVL_DEFAULT, FASTCDC_SEED_DEFAULT);
	return rz_fastcdc_chunker_init(chunker, &opts, bytes, size);
}

/**
 * \brief      Finalize the FastCDC chunker structure
 *
 * \param      chunker  The chunker structure to finalize
 */
RZ_IPI void rz_fastcdc_chunker_fini(RZ_NULLABLE FastCDCChunker *chunker) {
	if (!chunker) {
		return;
	}
	free(chunker->buf);
	rz_fastcdc_fini(&chunker->state);
}

/**
 * \brief      Returns the fingerprint of the fastcdc algo
 *
 * \param      state        The FastCDC state to use
 * \param[in]  data         The data to fingerprint
 * \param[in]  data_size    The data size
 * \param      fingerprint  The fingerprint output
 *
 * \return     Returns the number of bytes fingerprinted
 */
RZ_IPI size_t rz_fastcdc_fingerprint(RZ_NONNULL const FastCDC *state, RZ_NONNULL const ut8 *data, size_t data_size, RZ_NONNULL ut64 *fingerprint) {
	rz_return_val_if_fail(state && data && fingerprint, 0);

	if (data_size <= state->fp_min_size) {
		// when the data is less than min, we always return 0
		*fingerprint = 0;
		return data_size;
	}

	size_t n = RZ_MIN(data_size, state->fp_max_size);
	size_t min_norm = RZ_MIN(n, state->fp_norm_size);

	ut64 fp = 0;
	ut64 i = state->fp_min_size;
	for (; i < min_norm; i++) {
		fp = (fp << 1) + state->table[data[i]];
		if ((fp & state->mask_s) == 0) {
			*fingerprint = fp;
			return i + 1;
		}
	}

	for (; i < n; i++) {
		fp = (fp << 1) + state->table[data[i]];
		if ((fp & state->mask_l) == 0) {
			*fingerprint = fp;
			return i + 1;
		}
	}

	*fingerprint = fp;
	return i;
}

static size_t fastcdc_reader_copy(FastCDCReader *reader, ut8 *output, size_t out_size, bool *eof) {
	if (reader->leftovers < out_size) {
		*eof = true;
		out_size = reader->leftovers;
	}

	memcpy(output, reader->bytes, out_size);

	reader->bytes += out_size;
	reader->leftovers -= out_size;

	return out_size;
}

static void fastcdc_chunker_read_buffer(FastCDCChunker *chunker) {
	size_t n = chunker->buf_size - chunker->position;
	if (n >= chunker->state.fp_max_size) {
		return;
	}

	if (n > 0) {
		memmove(chunker->buf, &chunker->buf[chunker->position], n);
	}
	chunker->position = 0;

	if (chunker->eof) {
		chunker->buf_size = n;
		return;
	}

	size_t n_copied = fastcdc_reader_copy(&chunker->reader, &chunker->buf[n], chunker->state.fp_max_size - n, &chunker->eof);
	chunker->buf_size = n + n_copied;
}

/**
 * \brief      Calculates the next chunk, when false notifies the EOF.
 *
 * \param      chunker  The FastCDC chunker to use
 * \param      chunk    The FastCDC chunk to write to
 *
 * \return     When false notifies that this is the last chunk.
 */
RZ_IPI bool rz_fastcdc_chunker_next_chunk(RZ_NONNULL FastCDCChunker *chunker, RZ_NONNULL FastCDCChunk *chunk) {
	rz_return_val_if_fail(chunker && chunk, false);

	chunk->offset = chunker->n_read;
	chunk->length = 0;
	chunk->data = NULL;
	chunk->fingerprint = 0;

	fastcdc_chunker_read_buffer(chunker);
	if (chunker->buf_size < 1) {
		// eof.
		return false;
	}

	const size_t leftovers = chunker->buf_size - chunker->position;

	chunk->length = rz_fastcdc_fingerprint(&chunker->state, &chunker->buf[chunker->position], leftovers, &chunk->fingerprint);
	chunk->data = &chunker->buf[chunker->position];

	if (chunk->length < 1) {
		// eof.
		return false;
	}

	chunker->position += chunk->length;
	chunker->n_read += chunk->length;

	return true;
}
