// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ARCH_H
#define RZ_ARCH_H

#include <rz_types.h>
#include <rz_analysis.h>
#include <rz_asm.h>
#include <rz_parse.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_arch);

typedef struct rz_arch_plugin_t {
	RZ_DEPRECATE RzAsmPlugin *p_asm; ///< Assembly Plugin
	RZ_DEPRECATE RzAnalysisPlugin *p_analysis; ///< Analysis Plugin
	RZ_DEPRECATE RzParsePlugin *p_parse; ///< Parse Plugin
} RzArchPlugin;

RZ_DEPRECATE RZ_API const size_t rz_arch_get_n_plugins();
RZ_DEPRECATE RZ_API RZ_BORROW RzAsmPlugin *rz_arch_get_asm_plugin(size_t index);
RZ_DEPRECATE RZ_API RZ_BORROW RzAnalysisPlugin *rz_arch_get_analysis_plugin(size_t index);
RZ_DEPRECATE RZ_API RZ_BORROW RzParsePlugin *rz_arch_get_parse_plugin(size_t index);

#ifdef __cplusplus
}
#endif

#endif /* RZ_ARCH_H */
