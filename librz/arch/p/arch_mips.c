// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <deprecated_arch_helper.h>
#include <capstone/capstone.h>

#define EXTRA_CPUS "r2300,r2600,r2800,r2000a,r2000,r3000a,r3000,r10000"

#if CS_NEXT_VERSION < 6
#define CAPSTONE_CPUS     "micromips,mips1,mips2,mips3,mips4,mips16,mips32,mips32r6,mips64"
#define CAPSTONE_FEATURES ""
#else
#define CAPSTONE_CPUS     "micromips,mips1,mips2,mips32r2,mips32r3,mips32r5,mips32r6,mips3,mips4,mips5,mips64r2,mips64r3,mips64r5,mips64r6,octeon,octeonp,nanomips,nms1,i7200,micro32r3,micro32r6"
#define CAPSTONE_FEATURES "noptr64,nofloat"
#endif

#define MIPS_CPUS     CAPSTONE_CPUS "," EXTRA_CPUS
#define MIPS_FEATURES CAPSTONE_FEATURES

static bool cs_mode_from_cpu(const char *cpu, const char *features, int bits, bool big_endian, cs_mode *mode) {
	cs_mode _mode = (big_endian) ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
#if CS_NEXT_VERSION < 6
	(void)features;
#define return_on_cpu(cpu_name, mode_flag) \
	do { \
		if (!strcmp(cpu, cpu_name)) { \
			*mode = _mode | mode_flag; \
			return true; \
		} \
	} while (0)

	switch (bits) {
	case 64:
		_mode |= CS_MODE_MIPS64;
		break;
	case 32:
		_mode |= CS_MODE_MIPS32;
		break;
	default:
		return false;
	}

	if (RZ_STR_ISEMPTY(cpu)) {
		*mode = _mode;
		return true;
	}

	return_on_cpu("micromips", CS_MODE_MICRO);
	return_on_cpu("mips1", CS_MODE_MIPS2); // mips1 is subset of mips2
	return_on_cpu("mips2", CS_MODE_MIPS2);
	return_on_cpu("mips3", CS_MODE_MIPS3);
	return_on_cpu("mips4", CS_MODE_MIPS32); // old capstone uses the same
	return_on_cpu("mips16", CS_MODE_MIPS32); // old capstone uses the same
	return_on_cpu("mips32", CS_MODE_MIPS32);
	return_on_cpu("mips32r6", CS_MODE_MIPS32R6);
	return_on_cpu("mips64", CS_MODE_MIPS64);

	// extra cpus
	return_on_cpu("r2300", CS_MODE_MIPS2);
	return_on_cpu("r2600", CS_MODE_MIPS2);
	return_on_cpu("r2800", CS_MODE_MIPS2);
	return_on_cpu("r2000a", CS_MODE_MIPS2);
	return_on_cpu("r2000", CS_MODE_MIPS2);
	return_on_cpu("r3000a", CS_MODE_MIPS2); // ISA mips2
	return_on_cpu("r3000", CS_MODE_MIPS2); // ISA mips2
	return_on_cpu("r10000", CS_MODE_MIPS32); // old capstone uses the same

	return false;
#else
#define return_on_cpu(cpu_name, mode_flag) \
	do { \
		if (cpu_len == strlen(cpu_name) && \
			!strncmp(cpu, cpu_name, cpu_len)) { \
			*mode = _mode | mode_flag; \
			return true; \
		} \
	} while (0)

	bool is_noptr64 = RZ_STR_ISNOTEMPTY(features) && strstr(features, "noptr64");
	if (!is_noptr64 && bits > 16) {
		_mode |= CS_MODE_MIPS_PTR64;
	}

	bool is_nofloat = RZ_STR_ISNOTEMPTY(features) && strstr(features, "nofloat");
	if (is_nofloat) {
		_mode |= CS_MODE_MIPS_NOFLOAT;
	}
	if (RZ_STR_ISEMPTY(cpu) || cpu[0] == '+') {
		switch (bits) {
		case 64: // generic mips64
			*mode = _mode | CS_MODE_MIPS64;
			return true;
		case 32: // generic mips32
			*mode = _mode | CS_MODE_MIPS32;
			return true;
		case 16: // generic mips16
			*mode = _mode | CS_MODE_MIPS16;
			return true;
		default:
			return false;
		}
		return true;
	}

	size_t cpu_len = strlen(cpu);
	const char *plus = NULL;
	if ((plus = strchr(cpu, '+'))) {
		cpu_len = plus - cpu;
	}

	return_on_cpu("micromips", CS_MODE_MICRO);
	return_on_cpu("mips1", CS_MODE_MIPS1);
	return_on_cpu("mips2", CS_MODE_MIPS2);
	return_on_cpu("mips16", CS_MODE_MIPS16);
	return_on_cpu("mips32", CS_MODE_MIPS32);
	return_on_cpu("mips32r2", CS_MODE_MIPS32R2);
	return_on_cpu("mips32r3", CS_MODE_MIPS32R3);
	return_on_cpu("mips32r5", CS_MODE_MIPS32R5);
	return_on_cpu("mips32r6", CS_MODE_MIPS32R6);
	return_on_cpu("mips3", CS_MODE_MIPS3);
	return_on_cpu("mips4", CS_MODE_MIPS4);
	return_on_cpu("mips5", CS_MODE_MIPS5);
	return_on_cpu("mips64", CS_MODE_MIPS64);
	return_on_cpu("mips64r2", CS_MODE_MIPS64R2);
	return_on_cpu("mips64r3", CS_MODE_MIPS64R3);
	return_on_cpu("mips64r5", CS_MODE_MIPS64R5);
	return_on_cpu("mips64r6", CS_MODE_MIPS64R6);
	return_on_cpu("octeon", CS_MODE_OCTEON);
	return_on_cpu("octeonp", CS_MODE_OCTEONP);
	return_on_cpu("nanomips", CS_MODE_NANOMIPS);
	return_on_cpu("nms1", CS_MODE_NMS1);
	return_on_cpu("i7200", CS_MODE_I7200);
	return_on_cpu("micro32r3", CS_MODE_MICRO32R3);
	return_on_cpu("micro32r6", CS_MODE_MICRO32R6);

	// extra cpus
	return_on_cpu("r2300", CS_MODE_MIPS2);
	return_on_cpu("r2600", CS_MODE_MIPS2);
	return_on_cpu("r2800", CS_MODE_MIPS2);
	return_on_cpu("r2000a", CS_MODE_MIPS2);
	return_on_cpu("r2000", CS_MODE_MIPS2);
	return_on_cpu("r3000a", CS_MODE_MIPS2); // ISA mips2
	return_on_cpu("r3000", CS_MODE_MIPS2); // ISA mips2
	return_on_cpu("r10000", CS_MODE_MIPS4);

#endif /* CS_NEXT_VERSION */
	return false;
}
#undef return_on_cpu

#include "analysis/analysis_mips.c"
#include "asm/asm_mips.c"
#include "parse/parse_mips_pseudo.c"

RZ_ARCH_WITH_PARSE_PLUGIN_DEFINE_DEPRECATED(mips);
