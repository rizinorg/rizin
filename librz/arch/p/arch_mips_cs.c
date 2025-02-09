// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <deprecated_arch_helper.h>
#include <capstone/capstone.h>

/**
 * The MIPS32 and MIPS64 ISAs are a common source of confusion.
 *
 * The MIPS64 ISA level is actually a superset of the MIPS5 ISA, so it includes all instructions from MIPS5 and earlier ISAs.
 * The MIPS5 ISA level was designed by Silicon Graphics back in 1994, but never actually got used in a real life CPU.
 * It lives on as part of the MIPS64 ISA.
 *
 * MIPS32 is the 32-bit subset of MIPS64, it exists because most applications only require 32-bit processing.
 * MIPS3 can also run at 32-bit mode.
 *
 * | MIPS ISA | bits   | CPUs Covered                                                        |
 * + -------- + ------ + ------------------------------------------------------------------- +
 * | MIPS 1   | 32-bit | r2000, r3000                                                        |
 * | MIPS 2   | 32-bit | r6000                                                               |
 * | MIPS 3   | 64-bit | r4000, r4400, r4600, r4700                                          |
 * | MIPS 4   | 64-bit | r5000, rm5000, rm7000, r8000, r9000, r10000, r12000, r14000, r16000 |
 * | MIPS 5   | 64-bit | None ?                                                              |
 * | MIPS32   | 32-bit | AMD Alchemy series, 4kc, 4km... MIPS32 (r2-r6) ISA.                 |
 * | MIPS64   | 64-bit | Broadcom SiByte SB1, 5kc... MIPS64 (r2-r6) ISA.                     |
 *
 * Source: https://wiki.gentoo.org/wiki/Handbook:MIPS/Blocks/HWReqs
 */

#define EXTRA_CPUS_32 "r2300,r2600,r2800,r2000a,r2000,r3000a,r3000,r6000"
#define EXTRA_CPUS_64 "r4000,r4400,r4600,r4700,r5000,rm5000,rm7000,r8000,r9000,r10000,r12000,r14000,r16000"
#define EXTRA_CPUS    EXTRA_CPUS_32 "," EXTRA_CPUS_64

#if CS_NEXT_VERSION < 6
// first cpu is default
#define CAPSTONE_CPUS     "mips32,mips1,mips2,mips3,mips4,mips16,mips32r6,mips64,micromips"
#define CAPSTONE_FEATURES ""
#else
// first cpu is default
#define CAPSTONE_CPUS     "mips32,mips1,mips2,mips32r2,mips32r3,mips32r5,mips32r6,mips3,mips4,mips5,mips64r2,mips64r3,mips64r5,mips64r6,octeon,octeonp,nanomips,nms1,i7200,micromips,micro32r3,micro32r6"
#define CAPSTONE_FEATURES "noptr64,nofloat"
#endif

#define MIPS_CPUS     CAPSTONE_CPUS "," EXTRA_CPUS "," CAPSTONE_FEATURES
#define MIPS_FEATURES CAPSTONE_FEATURES

#define return_on_cpu(cpu_name, mode_flag) \
	do { \
		if (!strcmp(cpu, cpu_name)) { \
			*mode = _mode | mode_flag; \
			return true; \
		} \
	} while (0)

static bool cs_mode_from_cpu(const char *cpu, int bits, bool big_endian, cs_mode *mode) {
	cs_mode _mode = (big_endian) ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;

#if CS_NEXT_VERSION < 6
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
	*mode = _mode;

	if (RZ_STR_ISNOTEMPTY(cpu)) {
		return_on_cpu("micromips", CS_MODE_MICRO);
		return_on_cpu("mips1", CS_MODE_MIPS2); // mips1 is subset of mips2
		return_on_cpu("mips2", CS_MODE_MIPS2);
		return_on_cpu("mips3", CS_MODE_MIPS3);
		return_on_cpu("mips4", CS_MODE_MIPS64); // old capstone uses the same
		return_on_cpu("mips5", CS_MODE_MIPS64); // old capstone uses the same
		return_on_cpu("mips16", CS_MODE_MIPS32); // old capstone uses the same
		return_on_cpu("mips32", CS_MODE_MIPS32);
		return_on_cpu("mips32r6", CS_MODE_MIPS32R6);
		return_on_cpu("mips64", CS_MODE_MIPS64);
		return_on_cpu("mips64r2", CS_MODE_MIPS64); // fallback to mips64
		return_on_cpu("mips64r3", CS_MODE_MIPS64); // fallback to mips64
		return_on_cpu("mips64r5", CS_MODE_MIPS64); // fallback to mips64
		return_on_cpu("mips64r6", CS_MODE_MIPS64); // fallback to mips64

		// extra cpus
		return_on_cpu("r2300", CS_MODE_MIPS2); // mips1 is subset of mips2
		return_on_cpu("r2600", CS_MODE_MIPS2); // mips1 is subset of mips2
		return_on_cpu("r2800", CS_MODE_MIPS2); // mips1 is subset of mips2
		return_on_cpu("r2000a", CS_MODE_MIPS2); // mips1 is subset of mips2
		return_on_cpu("r2000", CS_MODE_MIPS2); // mips1 is subset of mips2
		return_on_cpu("r3000a", CS_MODE_MIPS2); // mips1 is subset of mips2
		return_on_cpu("r3000", CS_MODE_MIPS2); // mips1 is subset of mips2
		return_on_cpu("r6000", CS_MODE_MIPS2);
		return_on_cpu("r4000", CS_MODE_MIPS3);
		return_on_cpu("r4400", CS_MODE_MIPS3);
		return_on_cpu("r4600", CS_MODE_MIPS3);
		return_on_cpu("r4700", CS_MODE_MIPS3);
		return_on_cpu("r5000", CS_MODE_MIPS4);
		return_on_cpu("rm5000", CS_MODE_MIPS4);
		return_on_cpu("rm7000", CS_MODE_MIPS4);
		return_on_cpu("r8000", CS_MODE_MIPS4);
		return_on_cpu("r9000", CS_MODE_MIPS4);
		return_on_cpu("r10000", CS_MODE_MIPS4);
		return_on_cpu("r12000", CS_MODE_MIPS4);
		return_on_cpu("r14000", CS_MODE_MIPS4);
		return_on_cpu("r16000", CS_MODE_MIPS4);
	}

#else // CS_NEXT_VERSION >= 6
#define return_or_add_on_cpu(cpu_name, mode_flag) \
	do { \
		if (!strcmp(cpu, cpu_name)) { \
			*mode = _mode | mode_flag; \
			return true; \
		} \
		const size_t cpu_name_len = strlen(cpu_name); \
		const char *p = strstr(cpu, cpu_name); \
		if (p && (p[cpu_name_len] == '\0' || p[cpu_name_len] == ' ')) { \
			eprintf("found %s\n", cpu); \
			_add_mode |= mode_flag; \
		} \
	} while (0)

	bool is_noptr64 = RZ_STR_ISNOTEMPTY(cpu) && strstr(cpu, "+noptr64");
	if (!is_noptr64 && bits > 16) {
		_mode |= CS_MODE_MIPS_PTR64;
	}

	bool is_nofloat = RZ_STR_ISNOTEMPTY(cpu) && strstr(cpu, "+nofloat");
	if (is_nofloat) {
		_mode |= CS_MODE_MIPS_NOFLOAT;
	}

	if (RZ_STR_ISNOTEMPTY(cpu)) {
		cs_mode _add_mode = 0;
		return_or_add_on_cpu("micromips", CS_MODE_MICRO);
		return_or_add_on_cpu("mips1", CS_MODE_MIPS1);
		return_or_add_on_cpu("mips2", CS_MODE_MIPS2);
		return_or_add_on_cpu("mips16", CS_MODE_MIPS16);
		return_or_add_on_cpu("mips32", CS_MODE_MIPS3); // we always map the generic mips32 as mips3 32bits
		return_or_add_on_cpu("mips32r2", CS_MODE_MIPS32R2);
		return_or_add_on_cpu("mips32r3", CS_MODE_MIPS32R3);
		return_or_add_on_cpu("mips32r5", CS_MODE_MIPS32R5);
		return_or_add_on_cpu("mips32r6", CS_MODE_MIPS32R6);
		return_or_add_on_cpu("mips3", CS_MODE_MIPS3); // implements mips64
		return_or_add_on_cpu("mips4", CS_MODE_MIPS4); // implements mips64
		return_or_add_on_cpu("mips5", CS_MODE_MIPS5); // implements mips64
		return_or_add_on_cpu("mips64", CS_MODE_MIPS64);
		return_or_add_on_cpu("mips64r2", CS_MODE_MIPS64); // fallback to mips64
		return_or_add_on_cpu("mips64r3", CS_MODE_MIPS64R3);
		return_or_add_on_cpu("mips64r5", CS_MODE_MIPS64R5);
		return_or_add_on_cpu("mips64r6", CS_MODE_MIPS64R6);
		return_or_add_on_cpu("octeon", CS_MODE_OCTEON);
		return_or_add_on_cpu("octeonp", CS_MODE_OCTEONP);
		return_or_add_on_cpu("nanomips", CS_MODE_NANOMIPS);
		return_or_add_on_cpu("nms1", CS_MODE_NMS1);
		return_or_add_on_cpu("i7200", CS_MODE_I7200);
#undef return_or_add_on_cpu

		if (_add_mode) {
			*mode = _add_mode;
			return true;
		}

		// special cpus.
		return_on_cpu("micro32r3", CS_MODE_MICRO32R3);
		return_on_cpu("micro32r6", CS_MODE_MICRO32R6);

		// extra cpus
		return_on_cpu("r2300", CS_MODE_MIPS1);
		return_on_cpu("r2600", CS_MODE_MIPS1);
		return_on_cpu("r2800", CS_MODE_MIPS1);
		return_on_cpu("r2000a", CS_MODE_MIPS1);
		return_on_cpu("r2000", CS_MODE_MIPS1);
		return_on_cpu("r3000a", CS_MODE_MIPS1);
		return_on_cpu("r3000", CS_MODE_MIPS1);
		return_on_cpu("r6000", CS_MODE_MIPS2);
		return_on_cpu("r4000", CS_MODE_MIPS3);
		return_on_cpu("r4400", CS_MODE_MIPS3);
		return_on_cpu("r4600", CS_MODE_MIPS3);
		return_on_cpu("r4700", CS_MODE_MIPS3);
		return_on_cpu("r5000", CS_MODE_MIPS4);
		return_on_cpu("rm5000", CS_MODE_MIPS4);
		return_on_cpu("rm7000", CS_MODE_MIPS4);
		return_on_cpu("r8000", CS_MODE_MIPS4);
		return_on_cpu("r9000", CS_MODE_MIPS4);
		return_on_cpu("r10000", CS_MODE_MIPS4);
		return_on_cpu("r12000", CS_MODE_MIPS4);
		return_on_cpu("r14000", CS_MODE_MIPS4);
		return_on_cpu("r16000", CS_MODE_MIPS4);
	}

	switch (bits) {
	case 64: // generic mips64
		*mode = _mode | CS_MODE_MIPS64;
		break;
	case 32: // generic mips32
		*mode = _mode | CS_MODE_MIPS2;
		break;
	case 16: // generic mips16
		*mode = _mode | CS_MODE_MIPS16;
		break;
	default:
		return false;
	}
#endif /* CS_NEXT_VERSION */
	return true;
}
#undef return_on_cpu

#include "analysis/analysis_mips_cs.c"
#include "asm/asm_mips_cs.c"
#include "parse/parse_mips_pseudo.c"

RZ_ARCH_WITH_PARSE_PLUGIN_DEFINE_DEPRECATED(mips_cs);
