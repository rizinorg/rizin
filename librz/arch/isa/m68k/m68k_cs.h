// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_M68K_CS_H
#define RZ_M68K_CS_H

#include <string.h>
#include <capstone/capstone.h>

#define M68K_LONGEST_INSTRUCTION 22

#ifdef RZ_CAPSTONE_HAS_M68K_CPU32
#define M68K_CPUS "68000,68010,68020,68030,68040,68060,cpu32"
#else
#define M68K_CPUS "68000,68010,68020,68030,68040,68060"
#endif

static inline cs_mode rz_m68k_cs_mode(const char *cpu) {
	if (!cpu) {
		return CS_MODE_M68K_040;
	}
#ifdef RZ_CAPSTONE_HAS_M68K_CPU32
	if (strstr(cpu, "cpu32") || strstr(cpu, "CPU32")) {
		return CS_MODE_M68K_CPU32;
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
