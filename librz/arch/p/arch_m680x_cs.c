// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <deprecated_arch_helper.h>
#include <capstone/capstone.h>

static inline cs_mode m680x_mode(const char *str) {
	if (!str) {
		return CS_MODE_M680X_6800;
	}
	// replace this with the asm.features?
	if (strstr(str, "6800") || strstr(str, "6802") || strstr(str, "6808")) {
		return CS_MODE_M680X_6800;
	} else if (strstr(str, "6801") || strstr(str, "6803")) {
		return CS_MODE_M680X_6801;
	} else if (strstr(str, "6805")) {
		return CS_MODE_M680X_6805;
	} else if (rz_str_casestr(str, "68hc08")) {
		return CS_MODE_M680X_6808;
	} else if (strstr(str, "6809")) {
		return CS_MODE_M680X_6809;
	} else if (strstr(str, "6811")) {
		return CS_MODE_M680X_6811;
	} else if (rz_str_casestr(str, "cpu12")) {
		return CS_MODE_M680X_CPU12;
	} else if (strstr(str, "6301")) {
		return CS_MODE_M680X_6301;
	} else if (strstr(str, "6309")) {
		return CS_MODE_M680X_6309;
	} else if (rz_str_casestr(str, "hcs08")) {
		return CS_MODE_M680X_HCS08;
	}
#ifdef RZ_CAPSTONE_HAS_M680X_HCS12X
	else if (rz_str_casestr(str, "rs08")) {
		return CS_MODE_M680X_RS08;
	} else if (rz_str_casestr(str, "hcs12x")) {
		return CS_MODE_M680X_HCS12X;
	}
#endif
	return CS_MODE_M680X_6800;
}

#include "analysis/analysis_m680x_cs.c"
#include "asm/asm_m680x_cs.c"

RZ_ARCH_PLUGIN_DEFINE_DEPRECATED(m680x_cs);
