// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include <rz_magic.h>

#include "search_internal.h"

static char *magic_metadata_new(const char *match) {
	char *meta = rz_str_newf("magic.%s", match);
	if (!meta) {
		return NULL;
	}

	// filter any non-alphanum
	for (size_t i = 0; meta[i]; i++) {
		if (!IS_ALPHANUM(meta[i])) {
			meta[i] = '.';
		}
	}
	return meta;
}

static bool search_over_magic(RzPVector /*<char *>*/ *collection, ut64 address, const ut8 *buffer, size_t size, RzThreadQueue *hits) {
	void **it = NULL;
	RzMagic *magic = rz_magic_new(0);
	if (!magic) {
		RZ_LOG_ERROR("search: cannot initialize RzMagic\n");
		return false;
	}

	rz_pvector_foreach (collection, it) {
		const char *magic_dir = (const char *)*it;
		rz_magic_load(magic, magic_dir);
	}

	// there are no-single byte signatures
	for (size_t i = 0; i < size; i += 2) {
		const char *match = rz_magic_buffer(magic, buffer + i, size - i);
		if (!match) {
			continue;
		}
		char *meta = magic_metadata_new(match);
		if (!meta) {
			RZ_LOG_ERROR("search: cannot allocate magic metadata string for %s\n", match);
			rz_magic_free(magic);
			return false;
		}
		RzSearchHit *hit = rz_search_hit_new(meta, address + i, RZ_SEARCH_MAGIC_BLOCK_ALIGN);
		free(meta);
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
 * \brief      Allocates and initialize a magic RzSearchCollection
 *
 * \param[in]  magic_dir  The magic directory to use for loading the signatures
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzSearchCollection *rz_search_collection_magic(RZ_NONNULL const char *magic_dir) {
	RzSearchCollection *sc = rz_search_collection_new(search_over_magic, free);
	if (!sc) {
		return NULL;
	}
	char *copy = rz_str_dup(magic_dir);
	if (!copy || !rz_pvector_push(sc->collection, copy)) {
		RZ_LOG_ERROR("search: failed to initialize magic search collection\n");
		free(copy);
		rz_search_collection_free(sc);
		return NULL;
	}
	return sc;
}
