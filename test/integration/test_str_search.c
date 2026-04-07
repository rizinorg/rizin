// SPDX-FileCopyrightText: 2025 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file Implements integration tests for the string search.
 * The code here can also serve as example how to use the search API
 * with minimal dependencies.
 *
 * NOTE: These tests must be run from `<repo_root>/test/` and
 * `git clone https://github.com/rizinorg/rizin-testbins/ <repo_root>/test/bins`
 * must have been executed before.
 *
 * For a general overview how the search is implemented see
 * librz/search/README.md
 */

#include "../unit/minunit.h"
#include <rz_core.h>
#include "rz_list.h"
#include "rz_search.h"
#include "rz_util/rz_buf.h"
#include "rz_util/rz_str.h"

// The files to search in.
static const char *files[] = {
	"./bins/cmd/search/string_encodings/Hindi-Lipsum.utf8",
	"./bins/elf/analysis/hello-utf-16",
	// This file has the same lorem ipsum string in three different encodings:
	// "Лорем ипсум долор сит амет\x00\x00\x00\x00\x00\x00\x00ЛОРЕМ ИПСУМ ДОЛОР СИТ АМЕТ"
	"./bins/cmd/search/string_encodings/regex_search.russian.utf8.utf32le.utf16be",

	// Big binaries
	//
	// A very big file (1.1GB) with mixed data and Chinese characters.
	// Code points are aligned to code point width (4 bytes).
	// File is not in our rizin-testbin repo due to size.
	// But useful for performance testing.
	//
	// sha256: dc365472d8bbfdc3a3d47b5a0d8061c7d18233b131b0ed12fe599b53248629b2
	// "test/bins/test/bins/test_strings_zh.utf-32-le",
};

// Patterns/strings to search in the files from above.
static const char *patterns[][3] = {
	// Same Hindi strings but one is shorter.
	{ "पहोचने वैश्विक एसलिये पुस्तक हुआआदी", "प.+चने वैश्विक एसलिये .+आ", NULL },
	{ "heLLo woRlD", NULL, NULL },
	{ "и.{3}м", NULL, NULL },
	{ "Æ}º}Æ}µ", NULL, NULL }, // These are IBM037 characters decoding to: \x9e\xd0\x9b\xd0\x9e\xd0\xa0

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

#define N_THREADS 4

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
	rz_search_opt_set_max_threads(search_opts, N_THREADS);
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
	RzSearchCollection *collection = rz_search_collection_strings(NULL, N_THREADS);
	mu_assert_notnull(collection, "NULL check failed");

	// Now add the two patterns we search for
	mu_assert_true(rz_search_collection_string_add(collection, patterns[0][0], RZ_REGEX_LITERAL, match_alignment, RZ_STRING_ENC_UTF8), "Failed to add job");
	mu_assert_true(rz_search_collection_string_add(collection, patterns[0][1], RZ_REGEX_EXTENDED, match_alignment, RZ_STRING_ENC_UTF8), "Failed to add job");

	RzList *hits = rz_search_on_buffer(search_opts, collection, file_buffer, NULL);
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

	rz_search_collection_free(collection);
	rz_list_free(hits);
	mu_end;
}

/**
 * \brief Do a string search in a binary file.
 * The file is opened with as an RzIO instance. Not just as simple buffer.
 * Useful if the binary has to be analyzed beyond searching strings in it.
 */
int test_rz_str_search_io_simple(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "NULL check failed");
	mu_assert_true(rz_core_file_open_load(core, files[1], 0, RZ_PERM_R, false), "Loading file failed");

	// Setup search options. These are _not_ specific for the string search.
	// They are applicable to the whole search module, independently what
	// is searched (bytes, strings, cryptographic material, values...).
	// Configuring specific values is optional.
	RzSearchOpt *search_opts = rz_search_opt_new();
	mu_assert_notnull(search_opts, "NULL check failed");
	rz_search_opt_set_max_threads(search_opts, N_THREADS);
	rz_search_opt_set_max_hits(search_opts, 10);
	rz_search_opt_set_show_progress_from_str(search_opts, "no");
	rz_search_opt_set_chunk_size(search_opts, ELEMENT_SIZE);

	// The find options allow to configure string specific settings.
	RzSearchFindOpt *find_opts = rz_search_find_opt_new();
	mu_assert_notnull(find_opts, "NULL check failed");

	// Set alignment to 2, because we search UTF-16 and its code points are aligned to 2.
	// It is possible to also set it to any other value of course.
	// For details see librz/search/README.md
	size_t match_alignment = 2;
	rz_search_find_opt_set_alignment(find_opts, match_alignment);
	rz_search_find_opt_set_overlap_match(find_opts, false);

	// Assign find options to the search options.
	rz_search_opt_set_find_options(search_opts, find_opts);

	RzSearchCollection *collection = rz_search_collection_strings(NULL, N_THREADS);
	mu_assert_notnull(collection, "NULL check failed");

	// Now add the pattern we search for.
	mu_assert_true(rz_search_collection_string_add(collection, patterns[1][0], RZ_REGEX_CASELESS, match_alignment, RZ_STRING_ENC_UTF16LE), "Failed to add job");

	// Get the boundaries the strings are searched in.
	// The default address ranges are in the main config under `search.from`, `search.to`.
	// The maps to search in are in the config under `search.in`.
	RzList *boundaries = rz_core_get_boundaries_select(core, "search.from", "search.to", "search.in");
	mu_assert_notnull(boundaries, "NULL check failed");
	mu_assert_true(rz_list_length(boundaries) != 0, "The search boundaries are emtpy");

	RzList *hits = rz_search_on_io(search_opts, collection, core->io, boundaries);

	// Print the hits.
	// NOTE: The string address is 0x004005ea.
	// This is the virtual address where the string starts.
	// If you examine the two bytes before the string's address
	// you will notice it is preceeded by a BOM:
	// ```
	// > px 16 @ 0x004005e8
	// - offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
	// 0x004005e8  fffe 4800 6500 6c00 6c00 6f00 2000 5700  ..H.e.l.l.o. .W.
	// ```
	// So the string search does not count the BOM to the string!
	mu_assert_eq(rz_list_length(hits), 1, "Incorrect number of strings.");
	const RzSearchHit *hit = rz_list_get_n(hits, 0);
	printf("Hit at 0x%" PFMT64x " size: %" PFMTSZd "\n", hit->address, hit->size);
	mu_assert_true(hit->size == 22, "Incorrect size");
	mu_assert_eq(hit->address, 0x004005ea, "Incorrect address");
	rz_list_free(hits);
	rz_list_free(boundaries);
	rz_search_collection_free(collection);
	rz_search_opt_free(search_opts);
	rz_core_free(core);
	mu_end;
}

/**
 * \brief Do a regex search for strings of multiple encodings in a single file.
 */
int test_rz_str_search_multiple_enc(void) {
	// Open file as RzBuffer
	RzBuffer *file_buffer = rz_buf_new_file(files[2], O_RDONLY, 0);
	mu_assert_notnull(file_buffer, "Failed to open file");

	// Setup search options. These are _not_ specific for the string search.
	// They are applicable to the whole search module, independently what
	// is searched (bytes, strings, cryptographic material, values...).
	// Configuring specific values is optional.
	RzSearchOpt *search_opts = rz_search_opt_new();
	mu_assert_notnull(search_opts, "NULL check failed");
	rz_search_opt_set_max_threads(search_opts, N_THREADS);
	rz_search_opt_set_max_hits(search_opts, 10);
	rz_search_opt_set_show_progress_from_str(search_opts, "no");
	rz_search_opt_set_chunk_size(search_opts, ELEMENT_SIZE);

	// The find options allow to configure string specific settings.
	RzSearchFindOpt *find_opts = rz_search_find_opt_new();
	mu_assert_notnull(find_opts, "NULL check failed");

	// Set alignment to 1, because we search UTF-8/16/32.
	size_t match_alignment = 1;
	rz_search_find_opt_set_alignment(find_opts, match_alignment);
	rz_search_find_opt_set_overlap_match(find_opts, false);

	// Assign find options to the search options.
	rz_search_opt_set_find_options(search_opts, find_opts);

	// Please refer to librz/search/README.md for an explanation why string scan options
	// are needed for an IBM037 search.
	RzUtilStrScanOptions scan_opt = {
		.max_str_length = ELEMENT_SIZE,
		.min_str_length = 2,
		.prefer_big_endian = false,
		.check_ascii_freq = false,
	};

	RzSearchCollection *collection = rz_search_collection_strings(&scan_opt, N_THREADS);
	mu_assert_notnull(collection, "NULL check failed");

	// Now add the patterns we search for. One for each encoding in the file.
	// utf8/utf32le/utf16be
	mu_assert_true(rz_search_collection_string_add(collection, patterns[2][0], RZ_REGEX_EXTENDED, match_alignment, RZ_STRING_ENC_UTF8), "Adding failed");
	mu_assert_true(rz_search_collection_string_add(collection, patterns[2][0], RZ_REGEX_EXTENDED, match_alignment, RZ_STRING_ENC_UTF16BE), "Adding failed");
	mu_assert_true(rz_search_collection_string_add(collection, patterns[2][0], RZ_REGEX_EXTENDED, match_alignment, RZ_STRING_ENC_UTF32LE), "Adding failed");
	mu_assert_true(rz_search_collection_string_add(collection, patterns[3][0], RZ_REGEX_EXTENDED, match_alignment, RZ_STRING_ENC_IBM037), "Adding failed");

	RzList *hits = rz_search_on_buffer(search_opts, collection, file_buffer, NULL);
	mu_assert_notnull(hits, "NULL check failed");
	mu_assert_eq(rz_list_length(hits), 7, "Incorrect number of strings.");
	const RzSearchHit *hit;
	// Hits are sorted by address and size.
	// There are two matches for the pattern: "и.{3}м"
	// "ипсум" and "ит ам". So 6 in total, two for each encoding.
	hit = rz_list_get_n(hits, 0);
	mu_assert_eq(hit->address, 0x0000000b, "Incorrect address");
	mu_assert_eq(hit->size, 10, "Incorrect size");
	hit = rz_list_get_n(hits, 1);
	mu_assert_eq(hit->address, 0x00000023, "Incorrect address");
	mu_assert_eq(hit->size, 9, "Incorrect size");
	hit = rz_list_get_n(hits, 2);
	// The IBM037 string
	mu_assert_eq(hit->address, 0x00000050, "Incorrect address");
	mu_assert_eq(hit->size, 7, "Incorrect size");
	hit = rz_list_get_n(hits, 3);
	mu_assert_eq(hit->address, 0x00000087, "Incorrect address");
	mu_assert_eq(hit->size, 20, "Incorrect size");
	hit = rz_list_get_n(hits, 4);
	mu_assert_eq(hit->address, 0x000000bb, "Incorrect address");
	mu_assert_eq(hit->size, 20, "Incorrect size");
	hit = rz_list_get_n(hits, 5);
	mu_assert_eq(hit->address, 0x00000314, "Incorrect address");
	mu_assert_eq(hit->size, 10, "Incorrect size");
	hit = rz_list_get_n(hits, 6);
	mu_assert_eq(hit->address, 0x0000032e, "Incorrect address");
	mu_assert_eq(hit->size, 10, "Incorrect size");

	rz_list_free(hits);
	rz_search_collection_free(collection);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_str_search_single_simple);
	mu_run_test(test_rz_str_search_io_simple);
	mu_run_test(test_rz_str_search_multiple_enc);
	return tests_passed != tests_run;
}

mu_main(all_tests)
