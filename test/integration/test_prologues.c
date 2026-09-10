// SPDX-FileCopyrightText: 2026 MrQuantum1915 <darshanpatelgdh@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "../unit/minunit.h"
#include <rz_prologues.h>
#include "test_prologues.inc"

static RzBinFile *open_bin_file(RzBin *bin, const char *path) {
	RzBuffer *buf = rz_buf_new_file(path, O_RDONLY, 0);
	if (!buf) {
		return NULL;
	}
	RzBinOptions opt;
	rz_bin_options_init(&opt, -1, 0, 0, false);
	opt.filename = path;
	RzBinFile *bf = rz_bin_open_buf(bin, buf, &opt);
	rz_buf_free(buf);
	return bf;
}

bool test_prologues_arch_check() {
	RzBinInfo info = { 0 };
	info.arch = "arm";
	info.bits = 64;
	info.big_endian = false;
	mu_assert_true(rz_prologues_arch_check(&info, NULL), "NULL target_arch should return true");

	// empty target_arch , should adopt from bininfo
	RzProloguesArchInfo arch_info = { 0 };
	mu_assert_true(rz_prologues_arch_check(&info, &arch_info), "should adopt from bininfo");
	mu_assert_streq(arch_info.arch, "arm", "arch should be adopted as 'arm'");
	mu_assert_eq(arch_info.bits, 64, "bits should be adopted as 64");
	mu_assert_false(arch_info.big_endian, "endian should be adopted as little");
	mu_assert_true(rz_prologues_arch_check(&info, &arch_info), "matching arch should return true");
	rz_prologues_arch_info_fini(&arch_info);
	mu_assert_null(arch_info.arch, "arch should be NULL after fini");
	mu_assert_eq(arch_info.bits, 0, "bits should be 0 after fini");
	// null arch init should be safe
	rz_prologues_arch_info_init(&arch_info, NULL, 0, false);
	mu_assert_null(arch_info.arch, "NULL arch should remain NULL after init");
	mu_assert_eq(arch_info.bits, 0, "bits should be 0 for 0 input");
	mu_assert_false(arch_info.big_endian, "endian should be false");

	RzProloguesArchInfo mips_info = { 0 };
	rz_prologues_arch_info_init(&mips_info, "mips", 32, false);
	mu_assert_streq(mips_info.arch, "mips", "arch should be 'mips'");
	mu_assert_eq(mips_info.bits, 32, "bits should be 32");
	mu_assert_false(mips_info.big_endian, "endian should be little");
	mu_assert_false(rz_prologues_arch_check(&info, &mips_info), "arch mismatch should return false");
	rz_prologues_arch_info_fini(&mips_info);

	RzProloguesArchInfo arm32_info = { 0 };
	rz_prologues_arch_info_init(&arm32_info, "arm", 32, false);
	mu_assert_false(rz_prologues_arch_check(&info, &arm32_info), "bits mismatch should return false");
	rz_prologues_arch_info_fini(&arm32_info);

	RzProloguesArchInfo armbe_info = { 0 };
	rz_prologues_arch_info_init(&armbe_info, "arm", 64, true);
	mu_assert_false(rz_prologues_arch_check(&info, &armbe_info), "endian mismatch should return false");
	rz_prologues_arch_info_fini(&armbe_info);

	// partial adopt (bits adopt, arch already set)
	RzProloguesArchInfo partial = { 0 };
	rz_prologues_arch_info_init(&partial, "arm", 0, false);
	mu_assert_true(rz_prologues_arch_check(&info, &partial), "partial arch match, adopt bits");
	mu_assert_eq(partial.bits, 64, "bits should be adopted as 64 from bininfo");
	rz_prologues_arch_info_fini(&partial);

	rz_prologues_arch_info_fini(NULL); // should be safe

	mu_end;
}

bool test_prologues_generate() {

	RzProloguesArchInfo arch_info = { 0 };
	RzTrie *pg_trie = rz_prologues_trie_new();
	mu_assert_notnull(pg_trie, "Failed to create prologues trie");
	mu_assert_notnull(pg_trie->free, "Free cb should be set");
	mu_assert_notnull(pg_trie->init, "init cb should be set");
	mu_assert_notnull(pg_trie->match, "match cb should be set");
	mu_assert_notnull(pg_trie->root, "root node should be set");

	RzBin *bin = rz_bin_new();
	mu_assert_notnull(bin, "Failed to create RzBin instance");
	RzIO *io = rz_io_new();
	mu_assert_notnull(io, "Failed to create RzIO instance");
	io->ff = true;
	rz_io_bind(io, &bin->iob);

	RzBinFile *bf1 = open_bin_file(bin, "bins/elf/core/crash-linux-arm64");
	mu_assert_notnull(bf1, "couldn't open file");

	// single bin
	// - raw extract
	mu_assert_true(rz_prologues_trie_feed_binfile(pg_trie, bf1, 8, &arch_info, NULL),
		"Failed to feed binfile into prologues trie");
	RzVector *prologues = rz_prologues_extract_raw_from_trie(pg_trie, 8);
	mu_assert_notnull(prologues, "Failed to extract raw prologues from trie");
	mu_assert_eq(rz_vector_len(prologues), 8, "no. of raw prologues extracted differs");
	RzStructuredData *sd = rz_prologues_to_structured_data(prologues, 8, &arch_info);
	mu_assert_notnull(sd, "Failed to convert prologues to structured data");
	char *output = rz_structured_data_to_yaml(sd);
	mu_assert_notnull(output, "Failed to convert structured data to YAML");
	mu_assert_streq(output, crash_linux_arm64_raw, "YAML output mismatch");
	RZ_FREE(output);
	rz_structured_data_free(sd);
	rz_vector_free(prologues);

	// - generalize
	prologues = rz_prologues_generalize_and_extract(pg_trie, 8, 0.8);
	mu_assert_notnull(prologues, "Failed to generalize prologues from trie");
	mu_assert_eq(rz_vector_len(prologues), 6, "no. of prologues extracted differs");
	sd = rz_prologues_to_structured_data(prologues, 8, &arch_info);
	mu_assert_notnull(sd, "Failed to convert prologues to structured data");
	output = rz_structured_data_to_yaml(sd);
	mu_assert_notnull(output, "Failed to convert structured data to YAML");
	mu_assert_streq(output, crash_linux_arm64_generalized, "YAML output mismatch");
	RZ_FREE(output);
	rz_structured_data_free(sd);
	rz_vector_free(prologues);

	rz_prologues_arch_info_fini(&arch_info);
	rz_trie_free(pg_trie);

	// all bins
	pg_trie = rz_prologues_trie_new();
	RzBinFile *bf2 = open_bin_file(bin, "bins/elf/libarm64.so");
	mu_assert_notnull(bf2, "couldn't open 2nd file");
	RzBinFile *bf3 = open_bin_file(bin, "bins/elf/graphascii.c-clang-arm64-O0.o");
	mu_assert_notnull(bf3, "couldn't open 3rd file");

	RzSetS *processed_files = rz_set_s_new(HT_STR_DUP);
	mu_assert_notnull(processed_files, "couldn't create processed files set");
	st64 fcnt = rz_prologues_trie_feed_all_binfiles(pg_trie, bin, 8, &arch_info, processed_files);
	mu_assert_eq(fcnt, 3, "valid processed file count mismatch");
	mu_assert_eq(rz_set_s_size(processed_files), 3, "processed file set size mismatch");

	prologues = rz_prologues_generalize_and_extract(pg_trie, 8, 0.7);
	mu_assert_notnull(prologues, "Failed to generalize prologues from trie");
	mu_assert_eq(rz_vector_len(prologues), 9, "no. of prologues extracted differs");
	sd = rz_prologues_to_structured_data(prologues, 8, &arch_info);
	mu_assert_notnull(sd, "Failed to convert prologues to structured data");

	output = rz_structured_data_to_yaml(sd);
	mu_assert_notnull(output, "Failed to convert structured data to YAML");
	mu_assert_streq(output, multiple_open_file, "YAML output mismatch");
	RZ_FREE(output);
	rz_structured_data_free(sd);
	rz_vector_free(prologues);

	rz_trie_free(pg_trie);
	rz_bin_file_delete(bin, bf1);
	rz_bin_file_delete(bin, bf2);
	rz_bin_file_delete(bin, bf3);

	// dir
	rz_prologues_arch_info_fini(&arch_info);
	rz_prologues_arch_info_init(&arch_info, "mips", 32, false);

	rz_set_s_free(processed_files);
	processed_files = rz_set_s_new(HT_STR_DUP);
	pg_trie = rz_prologues_trie_new();
	// nonexistent
	fcnt = rz_prologues_trie_feed_directory(pg_trie, bin, "nonexistent/dir", 8, NULL, NULL);
	mu_assert_eq(fcnt, -1, "non-existent directory should return -1");
	fcnt = rz_prologues_trie_feed_directory(pg_trie, bin, "bins/elf", 8, &arch_info, processed_files);
	mu_assert_eq(fcnt, 4, "valid processed file count mismatch");
	mu_assert_eq(rz_set_s_size(processed_files), 4, "processed file set size mismatch");

	prologues = rz_prologues_generalize_and_extract(pg_trie, 8, 0.7);
	mu_assert_notnull(prologues, "Failed to generalize prologues from trie");
	mu_assert_eq(rz_vector_len(prologues), 11, "no. of prologues extracted differs");
	sd = rz_prologues_to_structured_data(prologues, 8, &arch_info);
	mu_assert_notnull(sd, "Failed to convert prologues to structured data");

	output = rz_structured_data_to_yaml(sd);
	mu_assert_notnull(output, "Failed to convert structured data to YAML");
	mu_assert_streq(output, prologues_from_dir, "YAML output mismatch");
	RZ_FREE(output);
	rz_structured_data_free(sd);
	rz_vector_free(prologues);

	rz_set_s_free(processed_files);
	rz_trie_free(pg_trie);

	// trie output
	pg_trie = rz_prologues_trie_new();
	rz_prologues_arch_info_fini(&arch_info);

	RzBinFile *bf4 = open_bin_file(bin, "bins/elf/graphascii.c-clang-arm64-O0.o");
	mu_assert_notnull(bf4, "couldn't open file");
	processed_files = rz_set_s_new(HT_STR_DUP);
	mu_assert_notnull(processed_files, "couldn't create processed files set");
	mu_assert_true(rz_prologues_trie_feed_binfile(pg_trie, bf4, 3, &arch_info, processed_files),
		"Failed to feed binfile into prologues trie");

	prologues = rz_prologues_generalize_and_extract(pg_trie, 3, 0.8);
	sd = rz_prologues_trie_to_structured_data(pg_trie, 3, &arch_info, processed_files);
	mu_assert_notnull(sd, "Failed to convert prologues trie to structured data");
	output = rz_structured_data_to_yaml(sd);
	mu_assert_notnull(output, "Failed to convert structured data to YAML");
	mu_assert_streq(output, trie_output, "YAML output mismatch");

	// skip duplicate feed
	mu_assert_false(rz_prologues_trie_feed_binfile(pg_trie, bf4, 3, &arch_info, processed_files),
		"Duplicate feed should be skipped");
	mu_assert_eq(rz_set_s_size(processed_files), 1, "processed file set size should still be 1");

	// arch mismatch
	RzProloguesArchInfo mips_arch = { 0 };
	rz_prologues_arch_info_init(&mips_arch, "mips", 32, false);
	// bf4 = arm64 , targeting mips should fail
	mu_assert_false(rz_prologues_trie_feed_binfile(pg_trie, bf4, 8, &mips_arch, NULL),
		"arch-mismatch feed should return false");
	rz_prologues_arch_info_fini(&mips_arch);

	rz_vector_free(prologues);
	rz_set_s_free(processed_files);
	RZ_FREE(output);
	rz_structured_data_free(sd);
	rz_trie_free(pg_trie);
	rz_bin_file_delete(bin, bf4);

	rz_io_free(io);
	rz_bin_free(bin);

	mu_end;
}

bool all_tests() {
	mu_run_test(test_prologues_arch_check);
	mu_run_test(test_prologues_generate);
	return tests_passed != tests_run;
}

mu_main(all_tests)
