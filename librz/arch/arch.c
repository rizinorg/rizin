// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_arch.h>

#include "rz_arch_plugins.h"

RZ_LIB_VERSION(rz_arch);

static RzArchPlugin *arch_static_plugins[] = { RZ_ARCH_STATIC_PLUGINS };

RZ_DEPRECATE RZ_API const size_t rz_arch_get_n_plugins() {
	return RZ_ARRAY_SIZE(arch_static_plugins);
}

RZ_DEPRECATE RZ_API RZ_BORROW RzAsmPlugin *rz_arch_get_asm_plugin(size_t index) {
	if (index >= RZ_ARRAY_SIZE(arch_static_plugins)) {
		return NULL;
	}
	return arch_static_plugins[index]->p_asm;
}

RZ_DEPRECATE RZ_API RZ_BORROW RzAnalysisPlugin *rz_arch_get_analysis_plugin(size_t index) {
	if (index >= RZ_ARRAY_SIZE(arch_static_plugins)) {
		return NULL;
	}
	return arch_static_plugins[index]->p_analysis;
}

RZ_DEPRECATE RZ_API RZ_BORROW RzParsePlugin *rz_arch_get_parse_plugin(size_t index) {
	if (index >= RZ_ARRAY_SIZE(arch_static_plugins)) {
		return NULL;
	}
	return arch_static_plugins[index]->p_parse;
}
