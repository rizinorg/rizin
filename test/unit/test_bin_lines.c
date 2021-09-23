// SPDX-FileCopyrightText: 2021 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include "minunit.h"

bool test_source_line_info_builder_empty() {
	RzBinSourceLineInfoBuilder bob;
	rz_bin_source_line_info_builder_init(&bob);
	// add nothing
	RzBinSourceLineInfo *li = rz_bin_source_line_info_builder_build_and_fini(&bob);
	mu_assert_eq(li->samples_count, 0, "samples count");
	mu_assert_null(li->samples, "samples");
	const RzBinSourceLineSample *sample = rz_bin_source_line_info_get_first_at(li, 0x42);
	mu_assert_null(sample, "no sample");
	rz_bin_source_line_info_free(li);
	mu_end;
}

bool test_source_line_info_builder() {
#define FUZZ_COUNT 200
	for (size_t f = 0; f < FUZZ_COUNT; f++) {
#undef FUZZ_COUNT
		RzBinSourceLineInfoBuilder bob;
		rz_bin_source_line_info_builder_init(&bob);

		// push the samples in random orders
#define SAMPLES_COUNT 15
		bool samples_applied[SAMPLES_COUNT] = { 0 };
		for (size_t i = 0; i < SAMPLES_COUNT; i++) {
			size_t j = rand() % SAMPLES_COUNT;
			while (samples_applied[j]) {
				j = (j + 1) % SAMPLES_COUNT;
			}
#undef SAMPLES_COUNT
			samples_applied[j] = true;
			switch (j) {
			case 0:
				rz_bin_source_line_info_builder_push_sample(&bob, 0x1000, 42, 3, "mayan.c");
				break;
			case 1:
				rz_bin_source_line_info_builder_push_sample(&bob, 0x1001, 0, 5, "mayan.c");
				break;
			case 2:
				rz_bin_source_line_info_builder_push_sample(&bob, 0x1001, 1337, 1, "mayan.c");
				break;
			case 3:
				rz_bin_source_line_info_builder_push_sample(&bob, 0x1002, 123, 2, "mayan.c");
				break;
			case 4:
				rz_bin_source_line_info_builder_push_sample(&bob, 0x1002, 34, 123, "panoramas.c");
				break;
			case 5:
				rz_bin_source_line_info_builder_push_sample(&bob, 0x1005, 0, 0, NULL);
				break;
			case 6:
				rz_bin_source_line_info_builder_push_sample(&bob, 0x1005, 23, 0, "mayan.c");
				break;
			case 7:
				rz_bin_source_line_info_builder_push_sample(&bob, 0x1010, 0, 0, NULL);
				break;
			case 8:
				rz_bin_source_line_info_builder_push_sample(&bob, 0x1010, 10, 100, NULL);
				break;
			case 9:
				rz_bin_source_line_info_builder_push_sample(&bob, 0x1010, 10, 23, "panoramas.c");
				break;
			case 10:
				rz_bin_source_line_info_builder_push_sample(&bob, 0x1020, 4, 71, "pyramid.c");
				break;
			case 11:
				rz_bin_source_line_info_builder_push_sample(&bob, 0x1020, 23, 12, "pyjamas.c");
				break;
			case 12:
				rz_bin_source_line_info_builder_push_sample(&bob, 0x1080, 0, 0, NULL);
				break;
			case 13:
				rz_bin_source_line_info_builder_push_sample(&bob, 0x1090, 0, 0, NULL);
				break;
			case 14:
				rz_bin_source_line_info_builder_push_sample(&bob, 0x2000, 52, 17, "pyramania.c");
				break;
			default:
				break;
			}
		}

		RzBinSourceLineInfo *li = rz_bin_source_line_info_builder_build_and_fini(&bob);

		static const RzBinSourceLineSample samples_expected[] = {
			{ 0x1000, 42, 3, "mayan.c" },
			{ 0x1001, 0, 5, "mayan.c" },
			{ 0x1001, 1337, 1, "mayan.c" },
			{ 0x1002, 34, 123, "panoramas.c" },
			{ 0x1002, 123, 2, "mayan.c" },
			{ 0x1005, 23, 0, "mayan.c" },
			{ 0x1010, 10, 23, "panoramas.c" },
			{ 0x1010, 10, 100, NULL },
			{ 0x1020, 4, 71, "pyramid.c" },
			{ 0x1020, 23, 12, "pyjamas.c" },
			{ 0x1080, 0, 0, NULL },
			{ 0x1090, 0, 0, NULL },
			{ 0x2000, 52, 17, "pyramania.c" }
		};

		mu_assert_eq(li->samples_count, RZ_ARRAY_SIZE(samples_expected), "samples count");
		for (size_t i = 0; i < RZ_ARRAY_SIZE(samples_expected); i++) {
			const RzBinSourceLineSample *a = &li->samples[i];
			const RzBinSourceLineSample *e = &samples_expected[i];
			mu_assert_eq(a->address, e->address, "sample address");
			if (e->line) {
				mu_assert_eq(a->line, e->line, "sample line");
				mu_assert_eq(a->column, e->column, "sample column");
				if (e->file) {
					mu_assert_notnull(a->file, "sample file");
					mu_assert_streq(a->file, e->file, "sample file");
				} else {
					mu_assert_null(a->file, "sample file");
				}
			} else {
				mu_assert_eq(a->line, 0, "closing line");
				// rest of closing entries is irrelevant
			}
		}

		rz_bin_source_line_info_free(li);
	}
	mu_end;
}

bool test_source_line_info_builder_fuzz() {
	const char *const test_filenames[] = {
		"into.c",
		"the.c",
		"black.c",
		"wide.c",
		"open.c"
	};

#define FUZZ_COUNT 200
	for (size_t f = 0; f < FUZZ_COUNT; f++) {
#undef FUZZ_COUNT
		RzBinSourceLineInfoBuilder bob;
		rz_bin_source_line_info_builder_init(&bob);

		// generate a lot of random samples and check them against a
		// super slow but super simple equivalent algorithm
#define SAMPLES_COUNT 0x200
		RzBinSourceLineSample samples[SAMPLES_COUNT] = { 0 };
		for (size_t i = 0; i < SAMPLES_COUNT; i++) {
			samples[i].address = rand() % 0x100;
			if (rand() % 10 > 2) {
				// non-closing entry
				samples[i].line = rand() % 16;
				samples[i].column = rand() % 16;
				samples[i].file = rand() % 10 == 0 ? NULL : test_filenames[rand() % RZ_ARRAY_SIZE(test_filenames)];
			}
			rz_bin_source_line_info_builder_push_sample(&bob, samples[i].address, samples[i].line, samples[i].column, samples[i].file);
		}
		RzBinSourceLineInfo *li = rz_bin_source_line_info_builder_build_and_fini(&bob);

		// every original sample must be correctly represented in the result...
		for (size_t i = 0; i < SAMPLES_COUNT; i++) {
			RzBinSourceLineSample *s = &samples[i];
			if (rz_bin_source_line_sample_is_closing(s)) {
				for (size_t j = 0; j < SAMPLES_COUNT; j++) {
					if (j == i) {
						continue;
					}
					if (samples[j].address == s->address && !rz_bin_source_line_sample_is_closing(&samples[j])) {
						// ...unless the sample is a closing one and overwritten by a
						// non-closing one at the same address, in which case there must be only
						// non-closing samples at this address in the result.
						for (size_t k = 0; k < li->samples_count; k++) {
							RzBinSourceLineSample *a = &li->samples[k];
							if (a->address > s->address) {
								// nothing interesting after here
								break;
							}
							if (a->address < s->address) {
								// not there yet
								continue;
							}
							mu_assert_true(!rz_bin_source_line_sample_is_closing(a), "closing sample override");
						}
						goto skip;
					}
				}
			}
			const RzBinSourceLineSample *a = rz_bin_source_line_info_get_first_at(li, s->address);
			if (rz_bin_source_line_sample_is_closing(s)) {
				mu_assert_null(a, "result sample for original closing sample");
				continue;
			}
			while (true) {
				mu_assert_notnull(a, "result sample for original sample");
				mu_assert_eq(a->address, s->address, "result sample addr");
				if (a->line == s->line && a->column == s->column &&
					((!a->file && !s->file) || (a->file && s->file && !strcmp(a->file, s->file)))) {
					// found it!
					break;
				}
				a = rz_bin_source_line_info_get_next(li, a);
			}
		skip:
			continue;
		}

		// every resulting sample must be the equivalent of some original sample
		for (size_t i = 0; i < li->samples_count; i++) {
			RzBinSourceLineSample *a = &li->samples[i];
			if (i) {
				// little side-check that everything is sorted
				mu_assert_true(li->samples[i - 1].address <= a->address, "increasing chain");
			}
			bool found = false;
			for (size_t j = 0; j < SAMPLES_COUNT; j++) {
				RzBinSourceLineSample *s = &samples[j];
				if (a->address == s->address &&
					((rz_bin_source_line_sample_is_closing(a) && rz_bin_source_line_sample_is_closing(s)) || (a->line == s->line && a->column == s->column && ((!a->file && !s->file) || (a->file && s->file && !strcmp(a->file, s->file)))))) {
					found = true;
					break;
				}
			}
			mu_assert_true(found, "original sample for result sample");
		}

		rz_bin_source_line_info_free(li);
	}
#undef SAMPLES_COUNT
	mu_end;
}

bool test_source_line_info_query() {
	static const RzBinSourceLineSample samples[] = {
		{ 0x1000, 42, 3, "mayan.c" },
		{ 0x1001, 0, 5, "mayan.c" },
		{ 0x1001, 1337, 1, "mayan.c" },
		{ 0x1002, 34, 123, "panoramas.c" },
		{ 0x1002, 123, 2, "mayan.c" },
		{ 0x1005, 23, 0, "mayan.c" },
		{ 0x1010, 10, 23, "panoramas.c" },
		{ 0x1010, 10, 100, NULL },
		{ 0x1020, 4, 71, "pyramid.c" },
		{ 0x1020, 23, 12, "pyjamas.c" },
		{ 0x1080, 0, 0, NULL },
		{ 0x1090, 0, 0, NULL },
		{ 0x2000, 52, 17, "pyramania.c" }
	};

	RzBinSourceLineInfo *li = RZ_NEW0(RzBinSourceLineInfo);
	li->samples = rz_mem_dup(samples, sizeof(samples));
	li->samples_count = RZ_ARRAY_SIZE(samples);
	rz_str_constpool_init(&li->filename_pool);
	for (size_t i = 0; i < RZ_ARRAY_SIZE(samples); i++) {
		if (li->samples[i].file) {
			li->samples[i].file = rz_str_constpool_get(&li->filename_pool, li->samples[i].file);
		}
	}

	const RzBinSourceLineSample *s = rz_bin_source_line_info_get_first_at(li, 0);
	mu_assert_null(s, "sample");

	s = rz_bin_source_line_info_get_first_at(li, 0xfff);
	mu_assert_null(s, "sample");

	s = rz_bin_source_line_info_get_first_at(li, 0x1000);
	mu_assert_notnull(s, "sample");
	mu_assert_eq(s->address, 0x1000, "sample addr");
	mu_assert_eq(s->line, 42, "sample line");
	mu_assert_eq(s->column, 3, "sample column");
	mu_assert_streq(s->file, "mayan.c", "sample file");
	s = rz_bin_source_line_info_get_next(li, s);
	mu_assert_null(s, "sample");

	s = rz_bin_source_line_info_get_first_at(li, 0x1001);
	mu_assert_notnull(s, "sample");
	mu_assert_eq(s->address, 0x1001, "sample addr");
	mu_assert_eq(s->line, 0, "sample line");
	mu_assert_eq(s->column, 5, "sample column");
	mu_assert_streq(s->file, "mayan.c", "sample file");
	s = rz_bin_source_line_info_get_next(li, s);
	mu_assert_notnull(s, "sample");
	mu_assert_eq(s->address, 0x1001, "sample addr");
	mu_assert_eq(s->line, 1337, "sample line");
	mu_assert_eq(s->column, 1, "sample column");
	mu_assert_streq(s->file, "mayan.c", "sample file");
	s = rz_bin_source_line_info_get_next(li, s);
	mu_assert_null(s, "sample");

	s = rz_bin_source_line_info_get_first_at(li, 0x1002);
	mu_assert_notnull(s, "sample");
	mu_assert_eq(s->address, 0x1002, "sample addr");
	mu_assert_eq(s->line, 34, "sample line");
	mu_assert_eq(s->column, 123, "sample column");
	mu_assert_streq(s->file, "panoramas.c", "sample file");
	s = rz_bin_source_line_info_get_next(li, s);
	mu_assert_notnull(s, "sample");
	mu_assert_eq(s->address, 0x1002, "sample addr");
	mu_assert_eq(s->line, 123, "sample line");
	mu_assert_eq(s->column, 2, "sample column");
	mu_assert_streq(s->file, "mayan.c", "sample file");
	s = rz_bin_source_line_info_get_next(li, s);
	mu_assert_null(s, "sample");

	s = rz_bin_source_line_info_get_first_at(li, 0x1003);
	mu_assert_notnull(s, "sample");
	mu_assert_eq(s->address, 0x1002, "sample addr");
	mu_assert_eq(s->line, 34, "sample line");
	mu_assert_eq(s->column, 123, "sample column");
	mu_assert_streq(s->file, "panoramas.c", "sample file");
	s = rz_bin_source_line_info_get_next(li, s);
	mu_assert_notnull(s, "sample");
	mu_assert_eq(s->address, 0x1002, "sample addr");
	mu_assert_eq(s->line, 123, "sample line");
	mu_assert_eq(s->column, 2, "sample column");
	mu_assert_streq(s->file, "mayan.c", "sample file");
	s = rz_bin_source_line_info_get_next(li, s);
	mu_assert_null(s, "sample");

	s = rz_bin_source_line_info_get_first_at(li, 0x1004);
	mu_assert_notnull(s, "sample");
	mu_assert_eq(s->address, 0x1002, "sample addr");
	mu_assert_eq(s->line, 34, "sample line");
	mu_assert_eq(s->column, 123, "sample column");
	mu_assert_streq(s->file, "panoramas.c", "sample file");
	s = rz_bin_source_line_info_get_next(li, s);
	mu_assert_notnull(s, "sample");
	mu_assert_eq(s->address, 0x1002, "sample addr");
	mu_assert_eq(s->line, 123, "sample line");
	mu_assert_eq(s->column, 2, "sample column");
	mu_assert_streq(s->file, "mayan.c", "sample file");
	s = rz_bin_source_line_info_get_next(li, s);
	mu_assert_null(s, "sample");

	s = rz_bin_source_line_info_get_first_at(li, 0x1005);
	mu_assert_notnull(s, "sample");
	mu_assert_eq(s->address, 0x1005, "sample addr");
	mu_assert_eq(s->line, 23, "sample line");
	mu_assert_eq(s->column, 0, "sample column");
	mu_assert_streq(s->file, "mayan.c", "sample file");
	s = rz_bin_source_line_info_get_next(li, s);
	mu_assert_null(s, "sample");

	s = rz_bin_source_line_info_get_first_at(li, 0x1011);
	mu_assert_notnull(s, "sample");
	mu_assert_eq(s->address, 0x1010, "sample addr");
	mu_assert_eq(s->line, 10, "sample line");
	mu_assert_eq(s->column, 23, "sample column");
	mu_assert_streq(s->file, "panoramas.c", "sample file");
	s = rz_bin_source_line_info_get_next(li, s);
	mu_assert_notnull(s, "sample");
	mu_assert_eq(s->address, 0x1010, "sample addr");
	mu_assert_eq(s->line, 10, "sample line");
	mu_assert_eq(s->column, 100, "sample column");
	mu_assert_null(s->file, "sample file");
	s = rz_bin_source_line_info_get_next(li, s);
	mu_assert_null(s, "sample");

	s = rz_bin_source_line_info_get_first_at(li, 0x1020);
	mu_assert_notnull(s, "sample");
	mu_assert_eq(s->address, 0x1020, "sample addr");
	mu_assert_eq(s->line, 4, "sample line");
	mu_assert_eq(s->column, 71, "sample column");
	mu_assert_streq(s->file, "pyramid.c", "sample file");
	s = rz_bin_source_line_info_get_next(li, s);
	mu_assert_notnull(s, "sample");
	mu_assert_eq(s->address, 0x1020, "sample addr");
	mu_assert_eq(s->line, 23, "sample line");
	mu_assert_eq(s->column, 12, "sample column");
	mu_assert_streq(s->file, "pyjamas.c", "sample file");
	s = rz_bin_source_line_info_get_next(li, s);
	mu_assert_null(s, "sample");

	s = rz_bin_source_line_info_get_first_at(li, 0x107f);
	mu_assert_notnull(s, "sample");
	mu_assert_eq(s->address, 0x1020, "sample addr");
	mu_assert_eq(s->line, 4, "sample line");
	mu_assert_eq(s->column, 71, "sample column");
	mu_assert_streq(s->file, "pyramid.c", "sample file");
	s = rz_bin_source_line_info_get_next(li, s);
	mu_assert_notnull(s, "sample");
	mu_assert_eq(s->address, 0x1020, "sample addr");
	mu_assert_eq(s->line, 23, "sample line");
	mu_assert_eq(s->column, 12, "sample column");
	mu_assert_streq(s->file, "pyjamas.c", "sample file");
	s = rz_bin_source_line_info_get_next(li, s);
	mu_assert_null(s, "sample");

	s = rz_bin_source_line_info_get_first_at(li, 0x1080);
	mu_assert_null(s, "sample");
	s = rz_bin_source_line_info_get_first_at(li, 0x1081);
	mu_assert_null(s, "sample");
	s = rz_bin_source_line_info_get_first_at(li, 0x1090);
	mu_assert_null(s, "sample");
	s = rz_bin_source_line_info_get_first_at(li, 0x1fff);
	mu_assert_null(s, "sample");

	s = rz_bin_source_line_info_get_first_at(li, 0x2000);
	mu_assert_notnull(s, "sample");
	mu_assert_eq(s->address, 0x2000, "sample addr");
	mu_assert_eq(s->line, 52, "sample line");
	mu_assert_eq(s->column, 17, "sample column");
	mu_assert_streq(s->file, "pyramania.c", "sample file");
	s = rz_bin_source_line_info_get_next(li, s);
	mu_assert_null(s, "sample");

	s = rz_bin_source_line_info_get_first_at(li, 0x500000);
	mu_assert_notnull(s, "sample");
	mu_assert_eq(s->address, 0x2000, "sample addr");
	mu_assert_eq(s->line, 52, "sample line");
	mu_assert_eq(s->column, 17, "sample column");
	mu_assert_streq(s->file, "pyramania.c", "sample file");
	s = rz_bin_source_line_info_get_next(li, s);
	mu_assert_null(s, "sample");

	rz_bin_source_line_info_free(li);
	mu_end;
}

bool all_tests() {
	srand(time(0));
	mu_run_test(test_source_line_info_builder_empty);
	mu_run_test(test_source_line_info_builder);
	mu_run_test(test_source_line_info_builder_fuzz);
	mu_run_test(test_source_line_info_query);
	return tests_passed != tests_run;
}

mu_main(all_tests)
