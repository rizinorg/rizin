// SPDX-FileCopyrightText: 2025 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file Implements integration tests for the string search.
 * The code here can also serve as example how to use the search API
 * with minimal dependencies.
 *
 * For a general overview how the search is implemented see
 * librz/search/README.md
 */

#include "../unit/minunit.h"
#include "rz_list.h"
#include "rz_search.h"
#include "rz_util/rz_buf.h"
#include "rz_util/rz_str.h"

// The files to search in.
static const char *files[] = {
	"./bins/cmd/search/string_encodings/Hindi-Lipsum.utf8",
	"./bins/cmd/search/string_encodings/Hindi-Lipsum.utf16be",
	"./bins/cmd/search/string_encodings/regex_search.russian.utf8.utf32le.utf16be",
	"./bins/cmd/search/string_encodings/Japanese-Katakana-Lipsum.ibm290",

	// Big binaries
	//
	// A very big file (1.1GB) with mixed data and Chinese characters.
	// Code points are aligned to code point width (4 bytes).
	// File is not in our rizin-testbin repo due to size.
	// But useful for performance testing.
	//
	// sha256: dc365472d8bbfdc3a3d47b5a0d8061c7d18233b131b0ed12fe599b53248629b2
	// "test/bins/test/bins/test_strings_zh.utf-32-le",
	//
	// Big endian strings to search. Search will significantly slower on little endian machines.
	// sha256: 315e96099d4c0ad7501e47f28a7781b8ed9fef0902bce5e962276a285362a684
	// "test/bins/test/bins/test_strings_zh.utf-16-be",
};

// Patterns/strings to search in the files from above.
static const char *patterns[][3] = {
	// Same Hindi strings but one is shorter.
	{ "पहोचने वैश्विक एसलिये पुस्तक हुआआदी", "प.+चने वैश्विक एसलिये .+आ", NULL },
	{ "पहोचने वैश्विक एसलिये पुस्तक हुआआदी", "प.+चने वैश्विक एसलिये .+आ", NULL },
	{ "ипсум", "и.{3}м", NULL },
	{ "!¥*);¬アイウエオカキクケコ", "¥.+ケコ", NULL },

	// Big binaries' strings
	//
	// First is an actual sub string in the binary.
	// Second pattern as well, but only if interpreted in UTF-8 strings (file was generated as UTF32-le).
	// { "些 公司 任何....可", ":.{13,}", NULL },
};

// One element is a single string in this context.
// This one is the element size in bytes.
// It should be at least as large as the maximum string length (in bytes) you expect.
// Mind though, found strings are allowed to be larger than this.
// Always check RzSearchHit->size for the real byte length of a string.
#define ELEMENT_SIZE 50

/**
 * \brief Do a simple literal and regex search for strings in Hindi.
 */
int test_rz_str_search_single_simple(void) {
	// Open file as RzBuffer
	RzBuffer *file_buffer = rz_buf_new_file(files[0], O_RDONLY, 0);
	mu_assert_notnull(file_buffer, "Failed to open file");

	// Setup search options. These are _not_ specific for the string search.
	// They are applicable to the whole search module, independently what
	// is searched (bytes, strings, cryptographic material, values...).
	// Configuring specific values is optional.
	RzSearchOpt *search_opts = rz_search_opt_new();
	mu_assert_notnull(search_opts, "NULL check failed");
	rz_search_opt_set_max_threads(search_opts, 4);
	rz_search_opt_set_max_hits(search_opts, 10);
	rz_search_opt_set_show_progress_from_str(search_opts, "no");
	rz_search_opt_set_chunk_size(search_opts, ELEMENT_SIZE);

	// The find options allow to configure string specific settings.
	RzSearchFindOpt *find_opts = rz_search_find_opt_new();
	mu_assert_notnull(find_opts, "NULL check failed");

	// Set alignment to 1, because we search UTF-8 and its code points are aligned to 1.
	size_t match_alignment = 1;
	rz_search_find_opt_set_alignment(find_opts, match_alignment);
	rz_search_find_opt_set_overlap_match(find_opts, false);

	// Assign find options to the search options.
	rz_search_opt_set_find_options(search_opts, find_opts);

	// Initialize the collection to search for.
	// We can pass NULL here to the RzUtilStrScanOptions parameter,
	// because UTF-8 is endianness independent and can directly match the buffer with PCRE2.
	// No scanning for strings is required. Hence we don't need the options for it.
	RzSearchCollection *collection = rz_search_collection_strings(NULL, RZ_STRING_ENC_UTF8, match_alignment);
	mu_assert_notnull(collection, "NULL check failed");

	// Now add the two patterns we search for
	rz_search_collection_string_add(collection, patterns[0][0], RZ_REGEX_LITERAL, match_alignment);
	rz_search_collection_string_add(collection, patterns[0][1], RZ_REGEX_EXTENDED, match_alignment);

	RzList *hits = rz_search_on_buffer(search_opts, collection, file_buffer);
	mu_assert_eq(rz_list_length(hits), 2, "Incorrect number of strings.");
	RzListIter *it;
	const RzSearchHit *hit;
	rz_list_foreach (hits, it, hit) {
		mu_assert_true(hit->size == 97 || hit->size == 91, "Incorrect size");
		mu_assert_eq(hit->address, 0x00000086, "Incorrect address");

		ut8 *hit_str = RZ_NEWS0(ut8, hit->size + 1);
		mu_assert_notnull(hit_str, "NULL check failed");
		rz_buf_read_at(file_buffer, hit->address, hit_str, hit->size);
		printf("Hit 0x%" PFMT64x ", size %" PFMTSZd ": '%s'\n", hit->address, hit->size, hit_str);
		free(hit_str);
	}

	// mu_assert_notnull(result, "valid callback (false)");
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_str_search_single_simple);
	return tests_passed != tests_run;
}

mu_main(all_tests)
