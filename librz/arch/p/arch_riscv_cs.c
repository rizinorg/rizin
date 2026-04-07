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

#define ARCH_RISCV_CPUS     "rv32,rv64,rocket-rv32,rocket-rv64,sifive-e20,sifive-e21,sifive-e24,sifive-e31,sifive-e34,sifive-e76,sifive-s21,sifive-s51,sifive-s54,sifive-s76,sifive-u54,sifive-u74,sifive-x280,sifive-p450,sifive-p670,syntacore-scr1-base,syntacore-scr1-max,veyron-v1,xiangshan-nanhu,spacemit-x60"
#define ARCH_RISCV_FEATURES "f,d,v,zfinx,zdinx,zhinx,zhinxmin,c,zcmp,zcmt,zce,zicfiss,a,zba,zbb,zbc,zbkb,zbkc,zbkx,zbs,corev,thead,sifive,bitmanip"

#define RV32_AC    (CS_MODE_RISCV32 | CS_MODE_RISCV_A | CS_MODE_RISCV_FD | CS_MODE_RISCV_C)
#define RV32_AFDC  (CS_MODE_RISCV32 | CS_MODE_RISCV_A | CS_MODE_RISCV_FD | CS_MODE_RISCV_C)
#define RV64_AC    (CS_MODE_RISCV64 | CS_MODE_RISCV_A | CS_MODE_RISCV_FD | CS_MODE_RISCV_C)
#define RV64_AFDC  (CS_MODE_RISCV64 | CS_MODE_RISCV_A | CS_MODE_RISCV_FD | CS_MODE_RISCV_C)
#define RV64_AFDCV (CS_MODE_RISCV64 | CS_MODE_RISCV_A | CS_MODE_RISCV_FD | CS_MODE_RISCV_C | CS_MODE_RISCV_V)

typedef struct riscv_match_s {
	const char *keyword;
	cs_mode feature;
} riscv_match_t;

static const riscv_match_t riscv_cpus[] = {
	// clang-format off
	{ "rv32", CS_MODE_RISCV32 },
	{ "rv64", CS_MODE_RISCV64 },
	{ "rv32e", (CS_MODE_RISCV32 | CS_MODE_RISCV_E) },
	{ "mips-p8700", (RV64_AFDC | CS_MODE_RISCV_ZBA | CS_MODE_RISCV_ZBB) },
	{ "sifive-e20", (CS_MODE_RISCV32 | CS_MODE_RISCV_C) },
	{ "sifive-e21", (RV64_AC) },
	{ "sifive-e24", (RV32_AFDC) },
	{ "sifive-e31", (RV64_AC) },
	{ "sifive-e34", (RV32_AFDC) },
	{ "sifive-e76", (RV32_AFDC) },
	{ "sifive-s21", (RV64_AC) },
	{ "sifive-s51", (RV64_AC) },
	{ "sifive-s54", (RV64_AFDC) },
	{ "sifive-s76", (RV64_AFDC) },
	{ "sifive-u54", (RV64_AFDC) },
	{ "sifive-u74", (RV64_AFDC) },
	{ "sifive-x280", (RV64_AFDCV | CS_MODE_RISCV_ZBA | CS_MODE_RISCV_ZBB | CS_MODE_RISCV_SIFIVE) },
	{ "sifive-x390", (RV64_AFDCV | CS_MODE_RISCV_SIFIVE) },
	{ "sifive-p450", (RV64_AFDC) },
	{ "sifive-p470", (RV64_AFDCV) },
	{ "sifive-p550", (RV64_AFDC | CS_MODE_RISCV_ZBA | CS_MODE_RISCV_ZBB) },
	{ "sifive-p670", (RV64_AFDCV) },
	{ "sifive-p870", (RV64_AFDCV | CS_MODE_RISCV_BITMANIP) },
	{ "syntacore-scr1-base", (CS_MODE_RISCV32 | CS_MODE_RISCV_C) },
	{ "syntacore-scr1-max", (CS_MODE_RISCV32 | CS_MODE_RISCV_C) },
	{ "syntacore-scr3-rv32", (CS_MODE_RISCV32 | CS_MODE_RISCV_C) },
	{ "syntacore-scr3-rv64", (CS_MODE_RISCV64 | CS_MODE_RISCV_A | CS_MODE_RISCV_C) },
	{ "syntacore-scr4-rv32", (CS_MODE_RISCV32 | CS_MODE_RISCV_FD | CS_MODE_RISCV_C) },
	{ "syntacore-scr4-rv64", (RV64_AFDC) },
	{ "syntacore-scr5-rv32", (RV32_AFDC) },
	{ "syntacore-scr5-rv64", (RV64_AFDC) },
	{ "syntacore-scr7", (RV64_AFDCV | CS_MODE_RISCV_ZBA | CS_MODE_RISCV_ZBB | CS_MODE_RISCV_ZBC | CS_MODE_RISCV_ZBS) },
	{ "tt-ascalon-x", (RV64_AFDCV) },
	{ "veyron-v1", (RV64_AFDC | CS_MODE_RISCV_ZBA | CS_MODE_RISCV_ZBB | CS_MODE_RISCV_ZBC | CS_MODE_RISCV_ZBS) },
	{ "xiangshan-nanhu", (RV64_AFDC | CS_MODE_RISCV_ZBA | CS_MODE_RISCV_ZBB | CS_MODE_RISCV_ZBC | CS_MODE_RISCV_ZBS) },
	{ "xiangshan-kunminghu", (RV64_AFDCV | CS_MODE_RISCV_ZBC) },
	{ "spacemit-a100", (RV64_AFDCV | CS_MODE_RISCV_ZBC | CS_MODE_RISCV_ZBKC) },
	{ "spacemit-x60", (RV64_AFDCV | CS_MODE_RISCV_ZBC | CS_MODE_RISCV_ZBKC) },
	{ "spacemit-x100", (RV64_AFDCV | CS_MODE_RISCV_ZBC | CS_MODE_RISCV_ZBKC) },
	{ "rp2350-hazard3", (RV32_AC | CS_MODE_RISCV_ZBA | CS_MODE_RISCV_ZBB | CS_MODE_RISCV_ZBC | CS_MODE_RISCV_ZBS | CS_MODE_RISCV_ZCMP_ZCMT_ZCE | CS_MODE_RISCV_ZBKB) },
	{ "andes-a25", (RV32_AFDC) },
	{ "andes-ax25", (RV64_AFDC) },
	{ "andes-n45", (RV32_AFDC) },
	{ "andes-nx45", (RV64_AFDC) },
	{ "andes-a45", (RV32_AFDC) },
	{ "andes-ax45", (RV64_AFDC) },
	{ "andes-ax45mpv", (RV64_AFDCV) },
	{ "et-soc1", (CS_MODE_RISCV64 | CS_MODE_RISCV_FD | CS_MODE_RISCV_C) },
	{ "an-erbium", (CS_MODE_RISCV64 | CS_MODE_RISCV_FD | CS_MODE_RISCV_C) },
	{ "xt-c910v2", (RV64_AFDC | CS_MODE_RISCV_ZBC | CS_MODE_RISCV_THEAD) },
	{ "xt-c920v2", (RV64_AFDCV | CS_MODE_RISCV_ZBC | CS_MODE_RISCV_THEAD) },
	// clang-format on
};

static const riscv_match_t riscv_features[] = {
	// clang-format off
	{ "f"       , (CS_MODE_RISCV_FD) },
	{ "d"       , (CS_MODE_RISCV_FD) },
	{ "v"       , (CS_MODE_RISCV_V) },
	{ "zfinx"   , (CS_MODE_RISCV_ZFINX) },
	{ "zdinx"   , (CS_MODE_RISCV_ZFINX) },
	{ "zhinx"   , (CS_MODE_RISCV_ZFINX) },
	{ "zhinxmin", (CS_MODE_RISCV_ZFINX) },
	{ "c"       , (CS_MODE_RISCV_C) },
	{ "zcmp"    , (CS_MODE_RISCV_ZCMP_ZCMT_ZCE) },
	{ "zcmt"    , (CS_MODE_RISCV_ZCMP_ZCMT_ZCE) },
	{ "zce"     , (CS_MODE_RISCV_ZCMP_ZCMT_ZCE) },
	{ "zicfiss" , (CS_MODE_RISCV_ZICFISS) },
	{ "a"       , (CS_MODE_RISCV_A) },
	{ "zba"     , (CS_MODE_RISCV_ZBA) },
	{ "zbb"     , (CS_MODE_RISCV_ZBB) },
	{ "zbc"     , (CS_MODE_RISCV_ZBC) },
	{ "zbkb"    , (CS_MODE_RISCV_ZBKB) },
	{ "zbkc"    , (CS_MODE_RISCV_ZBKC) },
	{ "zbkx"    , (CS_MODE_RISCV_ZBKX) },
	{ "zbs"     , (CS_MODE_RISCV_ZBS) },
	{ "corev"   , (CS_MODE_RISCV_COREV) },
	{ "thead"   , (CS_MODE_RISCV_THEAD) },
	{ "sifive"  , (CS_MODE_RISCV_SIFIVE) },
	{ "bitmanip", (CS_MODE_RISCV_BITMANIP) },
	// clang-format on
};

static cs_mode cs_mode_from_feature_flag(ut64 feature_flag) {
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

static size_t expect_str(const char *arch_str, const char *expected, size_t curr) {
	size_t l = strlen(expected);
	if (strncmp(&arch_str[curr], expected, l) != 0) {
		RZ_LOG_ERROR("Invalid architecture string: expected %s to equal %s\n",
			arch_str, expected);
		return curr;
	}

	return curr + l;
}

static size_t expect_char(const char *arch_str, char c, size_t curr) {
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

static size_t expect_any_str_of(const char *arch_str, const char **expected, size_t curr) {
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

static size_t skip_digit_sequence(const char *arch_str, size_t curr) {
	while (arch_str[curr] != '\0') {
		if (!isdigit(arch_str[curr])) {
			break;
		}
		curr++;
	}

	return curr;
}

static size_t skip_extension_version(const char *arch_str, size_t curr) {
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

static size_t skip_till_char(const char *arch_str, char c, size_t curr) {
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

static size_t expect_architecture_string_header(const char *arch_str) {
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

static bool expect_extension(const char *arch_str, size_t *curr, cs_mode *cs_mode) {
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

static cs_mode expect_extensions(const char *arch_str, size_t curr) {
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

static bool check_all_whitespace(const char *str) {
	while (*str) {
		if (!isspace(*str)) {
			return false;
		}
		str++;
	}

	return true;
}

static size_t find_known_cpu_from_list(const char *cpu) {
	if (RZ_STR_ISEMPTY(cpu)) {
		return 0;
	}

	for (size_t i = 0; i < RZ_ARRAY_SIZE(riscv_cpus); ++i) {
		if (RZ_STR_EQ(cpu, riscv_cpus[i].keyword)) {
			return riscv_cpus[i].feature;
		}
	}

	return 0;
}

static size_t resolve_features_from_list(const char *features) {
	if (RZ_STR_ISEMPTY(features)) {
		return 0;
	}

	size_t modes = 0;
	const char *feat;
	RzListIter *it;
	RzList *tokens = rz_str_split_duplist(features, ",", true);

	rz_list_foreach (tokens, it, feat) {
		if (RZ_STR_ISEMPTY(feat)) {
			continue;
		}
		for (size_t i = 0; i < RZ_ARRAY_SIZE(riscv_features); ++i) {
			if (RZ_STR_EQ(feat, riscv_features[i].keyword)) {
				modes |= riscv_features[i].feature;
			}
		}
	}
	return modes;
}

static size_t mode_from_arch_string(const char *cpu) {
	size_t mode = 0;
	if (!cpu || check_all_whitespace(cpu) || RZ_STR_EQ(cpu, "riscv")) {
		RZ_LOG_INFO("RISCV: empty architecture string, no non-default extensions enabled\n");
		return 0;
	} else if ((mode = find_known_cpu_from_list(cpu))) {
		return mode;
	}

	size_t curr = expect_architecture_string_header(cpu);
	return expect_extensions(cpu, curr);
}

#include "analysis/analysis_riscv_cs.c"
#include "asm/asm_riscv_cs.c"

RZ_ARCH_PLUGIN_DEFINE_DEPRECATED(riscv_cs);
