// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include <rz_magic.h>
#include <string.h>

#include "rz_util/rz_buf.h"
#include "search_internal.h"

static RzMagic *setup_magic_instance(const char *magic_dir) {
	RzMagic *magic = rz_magic_new();
	if (!magic) {
		RZ_LOG_ERROR("search: cannot initialize RzMagic.\n");
		return NULL;
	}
	if (!rz_magic_load(magic, magic_dir)) {
		RZ_LOG_ERROR("search: failed to load from '%s'.\n", magic_dir);
		rz_magic_free(magic);
		return NULL;
	}
	return magic;
}

static bool magic_is_empty(void *user) {
	// Always return false.
	return false;
}

static bool magic_find(RzSearchFindOpt *fopt, void *user, ut64 address, const RzBuffer *buffer,
	RZ_OUT RzThreadQueue *hits, RZ_OUT size_t *n_hits) {
	const char *magic_dir = user;
	RzMagic *magic = setup_magic_instance(magic_dir);
	if (!magic) {
		return false;
	}

	ut64 size;
	const ut8 *raw_buf = rz_buf_get_whole_hot_paths((RzBuffer *)buffer, &size);
	// There are no single-byte signatures.
	for (size_t i = 0; i < size; i += 2) {
		RAW_BUF_ITER_ALIGN(fopt, address, i);
		size_t leftovers = size - i;
		char *match = rz_magic_buffer(magic, raw_buf + i, leftovers);
		if (!match) {
			continue;
		}

		RzSearchHitDetail *detail = rz_search_hit_detail_string_new(match);
		free(match);
		if (!detail) {
			RZ_LOG_ERROR("search: failed to allocate magic hit detail.\n");
			return false;
		}
		RzSearchHit *hit = rz_search_hit_new("magic", address + i, 0, detail);
		if (!hit || !rz_th_queue_push(hits, hit, true)) {
			rz_search_hit_free(hit);
			rz_magic_free(magic);
			return false;
		}
	}
	rz_magic_free(magic);
	return true;
}

/**
 * \brief      Allocates and initialize a magic RzSearchCollection.
 *
 * \param[in]  magic_dir  The magic directory to use for loading the signatures.
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_API RZ_OWN RzSearchCollection *rz_search_collection_magic(RZ_NONNULL const char *magic_dir) {
	rz_return_val_if_fail(magic_dir, NULL);
	if (!(rz_file_is_directory(magic_dir) || rz_file_exists(magic_dir))) {
		RZ_LOG_ERROR("The magic file/directory '%s' does not exist.\n", magic_dir);
		return NULL;
	}

	// Test if RzMagic can be setup successfully.
	// Otherwise fail early.
	RzMagic *magic = setup_magic_instance(magic_dir);
	if (!magic) {
		return NULL;
	}
	// RzMagic is not thread save. So each find() worker gets its own.
	rz_magic_free(magic);

	return rz_search_collection_new_bytes_space(magic_find, magic_is_empty, free, strdup(magic_dir));
}
