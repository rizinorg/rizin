// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_M68K_CS_H
#define RZ_M68K_CS_H

#include <string.h>
#include <capstone/capstone.h>

#define M68K_LONGEST_INSTRUCTION 22

static inline cs_mode rz_m68k_cs_mode(const char *cpu) {
	if (!cpu) {
		return CS_MODE_M68K_040;
	}
#ifdef RZ_CAPSTONE_HAS_M68K_CPU32
	if (strstr(cpu, "cpu32") || strstr(cpu, "CPU32")) {
		return CS_MODE_M68K_CPU32;
	}
#endif
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
	if (strstr(cpu, "cfv1") || strstr(cpu, "CFV1")) {
		return CS_MODE_M68K_CFV1;
	}
	if (strstr(cpu, "cfv2") || strstr(cpu, "CFV2")) {
		return CS_MODE_M68K_CFV2;
	}
	if (strstr(cpu, "cfv3") || strstr(cpu, "CFV3")) {
		return CS_MODE_M68K_CFV3;
	}
	if (strstr(cpu, "cfv4e") || strstr(cpu, "CFV4E")) {
		return CS_MODE_M68K_CFV4E;
	}
	if (strstr(cpu, "cfv4") || strstr(cpu, "CFV4")) {
		return CS_MODE_M68K_CFV4;
	}
	if (strstr(cpu, "cfv5") || strstr(cpu, "CFV5")) {
		return CS_MODE_M68K_CFV5;
	}
	if (strstr(cpu, "coldfire") || strstr(cpu, "ColdFire") || strstr(cpu, "COLDFIRE")) {
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
