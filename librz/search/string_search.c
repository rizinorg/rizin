// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include <rz_util.h>

#include "search_internal.h"

typedef struct string_search {
	RzUtilStrScanOptions options; ///< String scan options
	RzStrEnc expected; ///< Expected encoding
	bool caseless;
	RzPVector /*<RzDetectedString *>*/ *strings; ///< UTF-8 strings to search
} StringSearch;

static bool string_find(void *user, ut64 address, const ut8 *buffer, size_t size, RzThreadQueue *hits) {
	StringSearch *ss = (StringSearch *)user;
	RzDetectedString *detected = NULL;
	RzListIter *it_s = NULL;

	RzList *found = rz_list_newf((RzListFree)rz_detected_string_free);
	if (!found) {
		RZ_LOG_ERROR("search: failed to allocate found list for strings collection\n");
		return false;
	}

	const ut64 end = address + size;
	if (rz_scan_strings_raw(buffer, found, &ss->options, address, end, ss->expected) <= 0) {
		rz_list_free(found);
		return true;
	}

	rz_list_foreach (found, it_s, detected) {
		void **it_m = NULL;
		rz_pvector_foreach (ss->strings, it_m) {
			RzDetectedString *find = *it_m;
			if (detected->length < find->length) {
				// ignore strings that are smaller than the one we are looking for.
				continue;
			}
			size_t len = RZ_MIN(detected->length, find->length);
			if ((ss->caseless && rz_str_ncasecmp(detected->string, find->string, len)) ||
				(!ss->caseless && strncmp(detected->string, find->string, len))) {
				// ignore strings that are not matching till len.
				continue;
			}

			RzSearchHit *hit = rz_search_hit_new("string", detected->addr, detected->size);
			if (!hit || !rz_th_queue_push(hits, hit, true)) {
				rz_search_hit_free(hit);
				rz_list_free(found);
				return false;
			}
		}
	}

	rz_list_free(found);
	return true;
}

static bool string_is_empty(void *user) {
	StringSearch *ss = (StringSearch *)user;
	return rz_pvector_empty(ss->strings);
}

static void string_free(void *user) {
	if (!user) {
		return;
	}
	StringSearch *ss = (StringSearch *)user;
	rz_pvector_free(ss->strings);
	free(ss);
}

/**
 * \brief      Allocates and initialize a string RzSearchCollection
 *
 * \param      opts      The RzUtilStrScanOptions options to use
 * \param[in]  expected  The expected encoding
 * \param[in]  caseless  When true performs a caseless compare
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzSearchCollection *rz_search_collection_strings(RZ_NONNULL RzUtilStrScanOptions *opts, RzStrEnc expected, bool caseless) {
	rz_return_val_if_fail(opts, NULL);

	StringSearch *ss = RZ_NEW0(StringSearch);
	if (!ss) {
		RZ_LOG_ERROR("search: failed to allocate StringSearch\n");
		return NULL;
	}

	ss->strings = rz_pvector_new((RzPVectorFree)rz_detected_string_free);
	if (!ss->strings) {
		RZ_LOG_ERROR("search: failed to initialize string collection\n");
		string_free(ss);
		return NULL;
	}

	ss->options = *opts; // copy the values
	ss->expected = expected;
	ss->caseless = caseless;

	return rz_search_collection_new(string_find, string_is_empty, string_free, ss);
}

static RzDetectedString *string_copy(const char *string) {
	char *copy = rz_str_dup(string);
	if (!copy) {
		return NULL;
	}
	RzDetectedString *ds = RZ_NEW0(RzDetectedString);
	if (!ds) {
		free(copy);
		return NULL;
	}
	ds->length = strlen(copy);
	return ds;
}

/**
 * \brief      Adds a new string into a string RzSearchCollection
 *
 * \param[in]  col     The RzSearchCollection to use
 * \param[in]  string  The regular expression to add
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_search_collection_string_add(RZ_NONNULL RzSearchCollection *col, RZ_NONNULL const char *string) {
	rz_return_val_if_fail(col && string, false);

	if (!rz_search_collection_has_find_callback(col, string_find)) {
		RZ_LOG_ERROR("search: cannot add string to non-string collection\n");
		return false;
	} else if (RZ_STR_ISEMPTY(string)) {
		RZ_LOG_ERROR("search: cannot add an empty string to a string collection\n");
		return false;
	}
	StringSearch *ss = (StringSearch *)col->user;

	RzDetectedString *s = string_copy(string);
	if (!s || !rz_pvector_push(ss->strings, s)) {
		RZ_LOG_ERROR("search: cannot add the string '%s'.\n", string);
		rz_detected_string_free(s);
		return false;
	}
	return true;
}
