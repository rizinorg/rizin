// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_M68K_CS_H
#define RZ_M68K_CS_H

#include <rz_util/rz_str.h>
#include <capstone/capstone.h>

#define M68K_LONGEST_INSTRUCTION 22

static inline cs_mode rz_m68k_cs_mode(const char *cpu) {
	if (!cpu) {
		return CS_MODE_M68K_040;
	}
#ifdef RZ_CAPSTONE_HAS_M68K_CPU32
	if (rz_str_casestr(cpu, "cpu32")) {
		return CS_MODE_M68K_CPU32;
	}
#endif
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
	if (rz_str_casestr(cpu, "cfv1")) {
		return CS_MODE_M68K_CFV1;
	}
	if (rz_str_casestr(cpu, "cfv2")) {
		return CS_MODE_M68K_CFV2;
	}
	if (rz_str_casestr(cpu, "cfv3")) {
		return CS_MODE_M68K_CFV3;
	}
	if (rz_str_casestr(cpu, "cfv4e")) {
		return CS_MODE_M68K_CFV4E;
	}
	if (rz_str_casestr(cpu, "cfv4")) {
		return CS_MODE_M68K_CFV4;
	}
	if (rz_str_casestr(cpu, "cfv5")) {
		return CS_MODE_M68K_CFV5;
	}
	if (rz_str_casestr(cpu, "coldfire")) {
		return CS_MODE_M68K_COLDFIRE;
	}
#endif
	if (strstr(cpu, "68000")) {
		return CS_MODE_M68K_000;
	}
	if (strstr(cpu, "68010")) {
		return CS_MODE_M68K_010;
	}
	if (strstr(cpu, "68020")) {
		return CS_MODE_M68K_020;
	}
	if (strstr(cpu, "68030")) {
		return CS_MODE_M68K_030;
	}
	if (strstr(cpu, "68040")) {
		return CS_MODE_M68K_040;
	}
	if (strstr(cpu, "68060")) {
		return CS_MODE_M68K_060;
	}
	return CS_MODE_M68K_040;
}

#endif
