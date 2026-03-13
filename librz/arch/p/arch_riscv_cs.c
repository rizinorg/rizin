// SPDX-FileCopyrightText: 2024-2026 moste00 <ubermenchun@gmail.com>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: BSD-3-Clause

#include <deprecated_arch_helper.h>
#include <stddef.h>
#include <string.h>
#include <capstone/riscv.h>
#include "capstone.h"
#include "rz_util/rz_log.h"
#include "arch_riscv_extension_parser.inc"

cs_mode cs_mode_from_feature_flag(ut64 feature_flag) {
	switch (feature_flag) {
	case RISCV_FeatureStdExtF:
	case RISCV_FeatureStdExtD:
		return CS_MODE_RISCV_FD;
	case RISCV_FeatureStdExtV:
		return CS_MODE_RISCV_V;
	case RISCV_FeatureStdExtZfinx:
	case RISCV_FeatureStdExtZdinx:
	case RISCV_FeatureStdExtZhinx:
	case RISCV_FeatureStdExtZhinxmin:
		return CS_MODE_RISCV_ZFINX;
	case RISCV_FeatureStdExtC:
		return CS_MODE_RISCV_C;
	case RISCV_FeatureStdExtZcmp:
	case RISCV_FeatureStdExtZcmt:
	case RISCV_FeatureStdExtZce:
		return CS_MODE_RISCV_ZCMP_ZCMT_ZCE;
	case RISCV_FeatureStdExtZicfiss:
		return CS_MODE_RISCV_ZICFISS;
	case RISCV_FeatureStdExtA:
		return CS_MODE_RISCV_A;
	case RISCV_FeatureStdExtZba:
		return CS_MODE_RISCV_ZBA;
	case RISCV_FeatureStdExtZbb:
		return CS_MODE_RISCV_ZBB;
	case RISCV_FeatureStdExtZbc:
		return CS_MODE_RISCV_ZBC;
	case RISCV_FeatureStdExtZbkb:
		return CS_MODE_RISCV_ZBKB;
	case RISCV_FeatureStdExtZbkc:
		return CS_MODE_RISCV_ZBKC;
	case RISCV_FeatureStdExtZbkx:
		return CS_MODE_RISCV_ZBKX;
	case RISCV_FeatureStdExtZbs:
		return CS_MODE_RISCV_ZBS;
	}

	return 0;
}

size_t expect_str(const char *arch_str, const char *expected, size_t curr) {
	size_t l = strlen(expected);
	if (strncmp(&arch_str[curr], expected, l) != 0) {
		RZ_LOG_ERROR("Invalid architecture string: expected %s to equal %s\n",
			arch_str, expected);
		return curr;
	}

	return curr + l;
}

size_t expect_char(const char *arch_str, char c, size_t curr) {
	if (arch_str[curr] == '\0') {
		RZ_LOG_ERROR("Invalid architecture string: expected %c, found end of string\n",
			c);
		return curr;
	}

	if (arch_str[curr] != c) {
		RZ_LOG_ERROR("Invalid architecture string: expected %c to equal %c\n",
			arch_str[curr], c);
		return curr;
	}

	return curr + 1;
}

size_t expect_any_str_of(const char *arch_str, const char **expected, size_t curr) {
	size_t i = 0;
	while (expected[i] != NULL) {
		if (strncmp(&arch_str[curr], expected[i], strlen(expected[i])) == 0) {
			return curr + strlen(expected[i]);
		}
		i++;
	}

	i = 0;
	RZ_LOG_ERROR("Invalid architecture string: expected %s to equal any string from [",
		arch_str);
	while (expected[i] != NULL) {
		RZ_LOG_ERROR("%s,", expected[i]);
		i++;
	}
	RZ_LOG_ERROR("]\n");

	return curr;
}

size_t skip_digit_sequence(const char *arch_str, size_t curr) {
	while (arch_str[curr] != '\0') {
		if (!isdigit(arch_str[curr])) {
			break;
		}
		curr++;
	}

	return curr;
}

size_t skip_extension_version(const char *arch_str, size_t curr) {
	curr = skip_digit_sequence(arch_str, curr);
	// now reached the 'p' in the middle of the 2 version numbers
	size_t curr1 = expect_char(arch_str, 'p', curr);
	if (curr1 == curr) {
		// error, expected p
		RZ_LOG_ERROR("Invalid architecture string: expected the version separator 'p' at index %zu"
			     "in archiecture string %s, found %c instead\n",
			curr, arch_str, arch_str[curr]);
		return curr;
	}

	return skip_digit_sequence(arch_str, curr1);
}

size_t skip_till_char(const char *arch_str, char c, size_t curr) {
	while (arch_str[curr] != '\0') {
		if (arch_str[curr] == c) {
			return curr;
		}
		curr++;
	}

	return curr;
}

#define CHECK_BAD_HEADER(before, after) \
	if (before == after) { \
		RZ_LOG_ERROR("Bad architecture string header at index %zu in archiecture string %s" \
			     "\n Will continue parsing the rest of the string from the next '_'\n", \
			before, arch_str); \
		return skip_till_char(arch_str, '_', before); \
	}

size_t expect_architecture_string_header(const char *arch_str) {
	size_t curr = 0;
	size_t curr1 = expect_str(arch_str, "rv", curr);
	CHECK_BAD_HEADER(curr, curr1);
	size_t curr2 = expect_any_str_of(arch_str, (const char *[]){ "32", "64", NULL }, curr1);
	CHECK_BAD_HEADER(curr1, curr2);
	size_t curr3 = expect_char(arch_str, 'i', curr2);
	CHECK_BAD_HEADER(curr2, curr3);
	size_t curr4 = skip_extension_version(arch_str, curr3);
	CHECK_BAD_HEADER(curr3, curr4)
	size_t curr5 = expect_char(arch_str, '_', curr4);
	CHECK_BAD_HEADER(curr4, curr5)

	return curr5;
}

bool expect_extension(const char *arch_str, size_t *curr, cs_mode *cs_mode) {
	ut64 flag = ~0;

	switch (try_consume_riscv_ext_from(arch_str, curr, &flag)) {
	case RISCV_EXT_PARSE_END_OF_STRING:
		*cs_mode |= cs_mode_from_feature_flag(flag);
		return true;

	case RISCV_EXT_PARSE_STOPPED_AT_NUMBER:
		*cs_mode |= cs_mode_from_feature_flag(flag);
		*curr = skip_extension_version(arch_str, *curr);
		return false;

	// weird, this means the extension is malformed as it has no version
	// but we can still continue with the next underscore
	case RISCV_EXT_PARSE_STOPPED_AT_UNDERSCORE:
		*curr = expect_char(arch_str, '_', *curr);
		*cs_mode |= cs_mode_from_feature_flag(flag);
		*curr = skip_extension_version(arch_str, *curr);
		return false;

	// bad mode, don't accumulate into result
	// but keep ignoring chars till the underscore or end of string
	case RISCV_EXT_PARSE_STOPPED_AT_UNEXPECTED:
		*curr = skip_till_char(arch_str, '_', *curr);
		return false;

	case RISCV_EXT_PARSE_NO_MATCH_END_OF_STRING:
		return true;

	case RISCV_EXT_PARSE_NO_MATCH_NUMBER:
		*curr = skip_extension_version(arch_str, *curr);
		return false;

	case RISCV_EXT_PARSE_NO_MATCH_UNDERSCORE:
		*curr = expect_char(arch_str, '_', *curr);
		*curr = skip_extension_version(arch_str, *curr);
		return false;

	case RISCV_EXT_PARSE_NO_MATCH_UNEXPECTED:
		*curr = skip_till_char(arch_str, '_', *curr);
		return false;
	}

	// unreachable
	rz_warn_if_reached();
	return true; // done, this is a bad state and we should terminate parsing immediately
}

cs_mode expect_extensions(const char *arch_str, size_t curr) {
	cs_mode cs_mode = 0;
	bool done = false;
	while (arch_str[curr] != '\0' && !done) {
		done = expect_extension(arch_str, &curr, &cs_mode);
		if (arch_str[curr] != '\0') {
			curr = expect_char(arch_str, '_', curr);
		}
	}

	return cs_mode;
}

bool check_all_whitespace(const char *str) {
	while (*str) {
		if (!isspace(*str)) {
			return false;
		}
		str++;
	}

	return true;
}
size_t mode_from_arch_string(const char *arch_str) {
	if (!arch_str || check_all_whitespace(arch_str) || RZ_STR_EQ(arch_str, "riscv")) {
		RZ_LOG_INFO("RISCV: empty architecture string, no non-default extensions enabled\n");
		return 0;
	}
	size_t curr = expect_architecture_string_header(arch_str);

	return expect_extensions(arch_str, curr);
}

#include "analysis/analysis_riscv_cs.c"
#include "asm/asm_riscv_cs.c"

RZ_ARCH_PLUGIN_DEFINE_DEPRECATED(riscv_cs);
