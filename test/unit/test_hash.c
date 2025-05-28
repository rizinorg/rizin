// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_hash.h>
#include "minunit.h"

typedef struct {
	const ut8 *input;
	size_t input_size;
	const char *algo;
	const char *expected;
} hash_data_t;

typedef struct {
	const ut8 *input;
	size_t input_size;
	const ut8 *key;
	size_t key_size;
	const char *algo;
	const char *expected;
} hmac_data_t;

static hmac_data_t hmacs_to_test[] = {
#define INDATA(v, x) .v = (ut8 *)(x), .v##_size = (sizeof(x) - 1)
	{ INDATA(input, "HelloWorld"), INDATA(key, "SuperSecretKeyWithSoManyWordsThatCouldBeBad"), .algo = "md4", .expected = "5110f44d655399f9e0e9bc0182eac2ff" },
	{ INDATA(input, "HelloWorld"), INDATA(key, "SuperSecretKeyWithSoManyWordsThatCouldBeBad"), .algo = "md5", .expected = "d281b8d617a0917ba067048227a94833" },
	{ INDATA(input, "HelloWorld"), INDATA(key, "SuperSecretKeyWithSoManyWordsThatCouldBeBad"), .algo = "sha1", .expected = "1c6989f139c68b7f55ecf88c4a288b6a45062894" },
	{ INDATA(input, "HelloWorld"), INDATA(key, "SuperSecretKeyWithSoManyWordsThatCouldBeBad"), .algo = "sha256", .expected = "f44d2995b9a376a8bfa5250144e16970f0a4b11684c7dafd8b70718bcbd87bd9" },
	{ INDATA(input, "HelloWorld"), INDATA(key, "SuperSecretKeyWithSoManyWordsThatCouldBeBad"), .algo = "sha384", .expected = "726c71ed3a2f057c71b4c8bc4e2b0c53fa16e93671c45bb9587eb3f30468c3b56b2fe8845e7acf2b49fc68f6e3942040" },
	{ INDATA(input, "HelloWorld"), INDATA(key, "SuperSecretKeyWithSoManyWordsThatCouldBeBad"), .algo = "sha512", .expected = "610c4763276013ae15bdc3896cc9397027d3b69cd6b450e13a872c529750dd135e0ead3b23a3a4bde0e31d851eac33c0eb800dd9741235845c4ac1d8b51d6696" },
#undef INDATA
};

static hash_data_t hashes_to_test[] = {
#define INDATA(x) .input = (ut8 *)(x), .input_size = (sizeof(x) - 1)
	{ INDATA("password"), .algo = "md2", .expected = "f03881a88c6e39135f0ecc60efd609b9" },
	{ INDATA("password"), .algo = "md4", .expected = "8a9d093f14f8701df17732b2bb182c74" },
	{ INDATA("password"), .algo = "md5", .expected = "5f4dcc3b5aa765d61d8327deb882cf99" },
	{ INDATA("password"), .algo = "sha1", .expected = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8" },
	{ INDATA("password"), .algo = "sha256", .expected = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" },
	{ INDATA("password"), .algo = "sha384", .expected = "a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7" },
	{ INDATA("password"), .algo = "sha512", .expected = "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86" },
	{ INDATA("password"), .algo = "sm3", .expected = "08594e140bcc046e345325435218f67a85c38c63de6443b197b544d70ee62f26" },
	{ INDATA("password"), .algo = "blake3", .expected = "7f2611ba158b6dcea4a69c229c303358c5e04493abeadee106a4bfa464d55787" },
	{ INDATA("password"), .algo = "fletcher8", .expected = "76" },
	{ INDATA("password"), .algo = "fletcher16", .expected = "7698" },
	{ INDATA("password"), .algo = "fletcher32", .expected = "cda87d23" },
	{ INDATA("password"), .algo = "fletcher64", .expected = "e7d0e5d75732594b" },
	{ INDATA("password"), .algo = "adler32", .expected = "7403910f" },
	{ INDATA("password"), .algo = "crc8smbus", .expected = "4f" },
	{ INDATA("password"), .algo = "crc8cdma2000", .expected = "d6" },
	{ INDATA("password"), .algo = "crc8darc", .expected = "57" },
	{ INDATA("password"), .algo = "crc8dvbs2", .expected = "b0" },
	{ INDATA("password"), .algo = "crc8ebu", .expected = "ff" },
	{ INDATA("password"), .algo = "crc8icode", .expected = "8e" },
	{ INDATA("password"), .algo = "crc8itu", .expected = "1a" },
	{ INDATA("password"), .algo = "crc8maxim", .expected = "b5" },
	{ INDATA("password"), .algo = "crc8rohc", .expected = "f1" },
	{ INDATA("password"), .algo = "crc8wcdma", .expected = "ad" },
	{ INDATA("password"), .algo = "crc15can", .expected = "2dbc" },
	{ INDATA("password"), .algo = "crc16", .expected = "c877" },
	{ INDATA("password"), .algo = "crc16citt", .expected = "147a" },
	{ INDATA("password"), .algo = "crc16usb", .expected = "3cc8" },
	{ INDATA("password"), .algo = "crc16hdlc", .expected = "55a1" },
	{ INDATA("password"), .algo = "crc16augccitt", .expected = "c47d" },
	{ INDATA("password"), .algo = "crc16buypass", .expected = "7e5b" },
	{ INDATA("password"), .algo = "crc16cdma2000", .expected = "c1f8" },
	{ INDATA("password"), .algo = "crc16dds110", .expected = "70bb" },
	{ INDATA("password"), .algo = "crc16dectr", .expected = "c868" },
	{ INDATA("password"), .algo = "crc16dectx", .expected = "c869" },
	{ INDATA("password"), .algo = "crc16dnp", .expected = "8237" },
	{ INDATA("password"), .algo = "crc16en13757", .expected = "17f7" },
	{ INDATA("password"), .algo = "crc16genibus", .expected = "eb85" },
	{ INDATA("password"), .algo = "crc16maxim", .expected = "3788" },
	{ INDATA("password"), .algo = "crc16mcrf4xx", .expected = "aa5e" },
	{ INDATA("password"), .algo = "crc16riello", .expected = "8b92" },
	{ INDATA("password"), .algo = "crc16t10dif", .expected = "fe6b" },
	{ INDATA("password"), .algo = "crc16teledisk", .expected = "06b3" },
	{ INDATA("password"), .algo = "crc16tms37157", .expected = "d6a5" },
	{ INDATA("password"), .algo = "crca", .expected = "83e8" },
	{ INDATA("password"), .algo = "crc16kermit", .expected = "d6d2" },
	{ INDATA("password"), .algo = "crc16modbus", .expected = "c337" },
	{ INDATA("password"), .algo = "crc16x25", .expected = "55a1" },
	{ INDATA("password"), .algo = "crc16xmodem", .expected = "2544" },
	{ INDATA("password"), .algo = "crc24", .expected = "00c0b593" },
	{ INDATA("password"), .algo = "crc32", .expected = "35c246d5" },
	{ INDATA("password"), .algo = "crc32ecma267", .expected = "c052c9e1" },
	{ INDATA("password"), .algo = "crc32c", .expected = "7c3e8628" },
	{ INDATA("password"), .algo = "crc32bzip2", .expected = "4fa7edbb" },
	{ INDATA("password"), .algo = "crc32d", .expected = "e9eca318" },
	{ INDATA("password"), .algo = "crc32mpeg2", .expected = "b0581244" },
	{ INDATA("password"), .algo = "crc32posix", .expected = "26a356e2" },
	{ INDATA("password"), .algo = "crc32q", .expected = "6f0ccd44" },
	{ INDATA("password"), .algo = "crc32jamcrc", .expected = "ca3db92a" },
	{ INDATA("password"), .algo = "crc32xfer", .expected = "d393113f" },
	{ INDATA("password"), .algo = "crc64", .expected = "d58a75cf65cbba3c" },
	{ INDATA("password"), .algo = "crc64ecma182", .expected = "d58a75cf65cbba3c" },
	{ INDATA("password"), .algo = "crc64we", .expected = "d6d9348dc305ec51" },
	{ INDATA("password"), .algo = "crc64xz", .expected = "973e3e8df55a98d9" },
	{ INDATA("password"), .algo = "crc64iso", .expected = "f07dcc2aac6c740e" },
	{ INDATA("password"), .algo = "xor8", .expected = "1f" },
	{ INDATA("password"), .algo = "xor16", .expected = "740f" },
	{ INDATA("password"), .algo = "xxhash32", .expected = "ed6c6c10" },
	{ INDATA("password"), .algo = "parity", .expected = "01" },
	{ INDATA("password"), .algo = "entropy", .expected = "2.75000000" },
	{ INDATA("password"), .algo = "entropy_fract", .expected = "0.91666667" },
	{ INDATA("abcdefgh"), .algo = "temperature", .expected = "1.00000000" },
	{ INDATA("a"), .algo = "temperature", .expected = "0.00000000" }
#undef INDATA
};

bool test_message_digest_configure() {
	bool boolean;
	RzHashCfg *md = NULL;
	RzHash *rh = rz_hash_new();

	md = rz_hash_cfg_new(rh);
	mu_assert_notnull(md, "rz_hash_cfg_new");

	boolean = rz_hash_cfg_configure(md, "gibberish");
	mu_assert_false(boolean, "rz_hash_cfg_configure 'gibberish'");

	boolean = rz_hash_cfg_configure(md, "");
	mu_assert_false(boolean, "rz_hash_cfg_configure ''");

	boolean = rz_hash_cfg_configure(md, "md5");
	mu_assert_true(boolean, "rz_hash_cfg_configure 'md5'");

	boolean = rz_hash_cfg_configure(md, "sha1");
	mu_assert_true(boolean, "rz_hash_cfg_configure 'sha1'");

	boolean = rz_hash_cfg_configure(md, "sha1");
	mu_assert_false(boolean, "rz_hash_cfg_configure 'sha1' again");

	boolean = rz_hash_cfg_configure(md, "all");
	mu_assert_false(boolean, "rz_hash_cfg_configure can't configure 'all' when other algos has been configured");

	rz_hash_cfg_free(md);

	md = rz_hash_cfg_new_with_algo2(rh, "gibberish");
	mu_assert_null(md, "rz_hash_cfg_new_with_algo2 with gibberish algo");

	md = rz_hash_cfg_new_with_algo2(rh, "");
	mu_assert_null(md, "rz_hash_cfg_new_with_algo2 with '' algo");

	rz_hash_free(rh);
	mu_end;
}

bool test_message_digest_hmac_stringified() {
	char message[256];
	char *result = NULL;
	bool boolean;
	RzHashSize size;
	RzHashCfg *md = NULL;
	RzHash *rh = rz_hash_new();

	for (size_t i = 0; i < RZ_ARRAY_SIZE(hmacs_to_test); ++i) {
		hmac_data_t *hd = &hmacs_to_test[i];

		md = rz_hash_cfg_new_with_algo(rh, hd->algo, hd->key, hd->key_size);
		snprintf(message, sizeof(message), "rz_hash_cfg_new_with_algo hmac-%s digest", hd->algo);
		mu_assert_notnull(md, message);

		boolean = rz_hash_cfg_update(md, hd->input, hd->input_size);
		snprintf(message, sizeof(message), "rz_hash_cfg_update hmac-%s digest", hd->algo);
		mu_assert_true(boolean, message);

		boolean = rz_hash_cfg_final(md);
		snprintf(message, sizeof(message), "rz_hash_cfg_final hmac-%s digest", hd->algo);
		mu_assert_true(boolean, message);

		result = rz_hash_cfg_get_result_string(md, hd->algo, &size, false);
		snprintf(message, sizeof(message), "rz_hash_cfg_get_result_string hmac-%s digest", hd->algo);
		mu_assert_streq(result, hd->expected, message);

		free(result);
		result = NULL;
		rz_hash_cfg_free(md);
	}
	free(result);
	rz_hash_free(rh);

	mu_end;
}

bool test_message_digest_api_stringified() {
	char message[256];
	char *result = NULL;
	bool boolean;
	RzHashSize size;
	RzHashCfg *md = NULL;
	RzHash *rh = rz_hash_new();

	for (size_t i = 0; i < RZ_ARRAY_SIZE(hashes_to_test); ++i) {
		hash_data_t *hd = &hashes_to_test[i];

		md = rz_hash_cfg_new_with_algo2(rh, hd->algo);
		snprintf(message, sizeof(message), "rz_hash_cfg_new_with_algo %s digest", hd->algo);
		mu_assert_notnull(md, message);

		boolean = rz_hash_cfg_update(md, hd->input, hd->input_size);
		snprintf(message, sizeof(message), "rz_hash_cfg_update %s digest", hd->algo);
		mu_assert_true(boolean, message);

		boolean = rz_hash_cfg_final(md);
		snprintf(message, sizeof(message), "rz_hash_cfg_final %s digest", hd->algo);
		mu_assert_true(boolean, message);

		result = rz_hash_cfg_get_result_string(md, hd->algo, &size, false);
		snprintf(message, sizeof(message), "rz_hash_cfg_get_result_string %s digest", hd->algo);
		mu_assert_streq(result, hd->expected, message);

		free(result);
		result = NULL;
		rz_hash_cfg_free(md);
	}
	free(result);
	rz_hash_free(rh);

	mu_end;
}

bool test_message_digest_small_block_stringified() {
	char message[256];
	char *result = NULL;
	RzHashSize size;
	RzHash *rh = rz_hash_new();

	for (size_t i = 0; i < RZ_ARRAY_SIZE(hashes_to_test); ++i) {
		hash_data_t *hd = &hashes_to_test[i];
		snprintf(message, sizeof(message), "calculate %s digest", hd->algo);
		result = rz_hash_cfg_calculate_small_block_string(rh, hd->algo, hd->input, hd->input_size, &size, false);
		mu_assert_streq(result, hd->expected, message);
		free(result);
		result = NULL;
	}
	free(result);
	rz_hash_free(rh);

	mu_end;
}

bool all_tests() {
	mu_run_test(test_message_digest_configure);
	mu_run_test(test_message_digest_api_stringified);
	mu_run_test(test_message_digest_hmac_stringified);
	mu_run_test(test_message_digest_small_block_stringified);
	return tests_passed != tests_run;
}

mu_main(all_tests)
