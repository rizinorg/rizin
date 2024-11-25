// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include <rz_util/rz_regex.h>

#include "search_internal.h"

static bool search_over_regex(RzPVector /*<RzRegex *>*/ *collection, ut64 address, const ut8 *buffer, size_t size, RzThreadQueue *hits) {
	void **it_c = NULL;
	RzPVector *matches = NULL;
	RzRegex *compiled = NULL;

	rz_pvector_foreach (collection, it_c) {
		compiled = (RzRegex *)*it_c;
		matches = rz_regex_match_all_not_grouped(compiled, (char *)buffer, size, 0, RZ_REGEX_DEFAULT);
		void **it_m = NULL;
		rz_pvector_foreach (matches, it_m) {
			RzRegexMatch *m = *it_m;
			RzSearchHit *hit = rz_search_hit_new("regex", address + m->start, m->len);
			if (!hit || !rz_th_queue_push(hits, hit, true)) {
				rz_search_hit_free(hit);
				rz_pvector_free(matches);
				return false;
			}
		}
		rz_pvector_free(matches);
	}
	return true;
}

/**
 * \brief      Allocates and initialize a regex RzSearchCollection
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzSearchCollection *rz_search_collection_regex() {
	return rz_search_collection_new(search_over_regex, rz_regex_free);
}

/**
 * \brief      Adds a new regex into a regex RzSearchCollection
 *
 * \param[in]  col       The RzSearchCollection to use
 * \param[in]  regex     The regular expression to add
 * \param[in]  caseless  The caseless
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_search_collection_regex_add(RZ_NONNULL RzSearchCollection *col, RZ_NONNULL const char *regex, bool caseless) {
	rz_return_val_if_fail(col && regex, false);

	if (!rz_search_collection_has_callback(col, search_over_regex)) {
		RZ_LOG_ERROR("search: cannot add regex to non-regex collection\n");
		return false;
	} else if (RZ_STR_ISEMPTY(regex)) {
		RZ_LOG_ERROR("search: cannot add an empty string to a regex collection\n");
		return false;
	}

	RzRegexFlags cflags = RZ_REGEX_EXTENDED;
	if (caseless) {
		cflags |= RZ_REGEX_CASELESS;
	}

	RzRegex *compiled = rz_regex_new(regex, cflags, 0);
	if (!compiled) {
		RZ_LOG_ERROR("search: cannot compile '%s' regexp.\n", regex);
		return false;
	} else if (!rz_pvector_push(col->collection, compiled)) {
		RZ_LOG_ERROR("search: cannot add '%s' regexp.\n", regex);
		rz_regex_free(compiled);
		return false;
	}
	return true;
}
