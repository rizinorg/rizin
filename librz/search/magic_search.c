// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include <rz_magic.h>

#include "search_internal.h"

static bool magic_is_empty(void *user) {
	// always return false.
	return false;
}

static bool magic_find(void *user, ut64 address, const ut8 *buffer, size_t size, RzThreadQueue *hits) {
	RzMagic *magic = (RzMagic *)user;

	// there are no single-byte signatures
	for (size_t i = 0; i < size; i += 2) {
		const char *match = rz_magic_buffer(magic, buffer + i, size - i);
		if (!match) {
			continue;
		}

		RzSearchHit *hit = rz_search_hit_new("magic", address + i, 0);
		if (!hit || !rz_th_queue_push(hits, hit, true)) {
			rz_search_hit_free(hit);
			return false;
		}
	}
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
	if (RZ_STR_ISEMPTY(magic_dir)) {
		RZ_LOG_ERROR("search: cannot initialize RzMagic without a valid magic dir\n");
		return NULL;
	}

	RzMagic *magic = rz_magic_new(0);
	if (!magic || !rz_magic_load(magic, magic_dir)) {
		RZ_LOG_ERROR("search: cannot initialize RzMagic\n");
		rz_magic_free(magic);
		return NULL;
	}

	return rz_search_collection_new(magic_find, magic_is_empty, (RzSearchFreeCallback)rz_magic_free, magic);
}
