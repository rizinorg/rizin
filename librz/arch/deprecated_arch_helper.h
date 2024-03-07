// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef DEPRECATED_ARCH_HELPER_H
#define DEPRECATED_ARCH_HELPER_H

#include <rz_arch.h>

#define DEPRECATED_OLD_ARCH_PLUGIN(name) \
	RzArchPlugin rz_arch_plugin_##name = { \
		.p_asm = &rz_asm_plugin_##name, \
		.p_analysis = &rz_analysis_plugin_##name, \
		.p_parse = &rz_parse_plugin_##name##_pseudo, \
	}

#define DEPRECATED_OLD_ARCH_NO_PARSE_PLUGIN(name) \
	RzArchPlugin rz_arch_plugin_##name = { \
		.p_asm = &rz_asm_plugin_##name, \
		.p_analysis = &rz_analysis_plugin_##name, \
		.p_parse = NULL, \
	}

#define DEPRECATED_OLD_ARCH_ASM_ONLY_PLUGIN(name) \
	RzArchPlugin rz_arch_plugin_##name = { \
		.p_asm = &rz_asm_plugin_##name, \
		.p_analysis = NULL, \
		.p_parse = NULL, \
	}

#ifndef RZ_PLUGIN_INCORE
#define ARCH_PLUGIN_LIB_STRUCT(name) \
	RZ_API RzLibStruct rizin_plugin = { \
		.type = RZ_LIB_TYPE_ARCH, \
		.data = &rz_arch_plugin_##name, \
		.version = RZ_VERSION \
	}
#else
#define ARCH_PLUGIN_LIB_STRUCT(name)
#endif

#define RZ_ARCH_WITH_PARSE_PLUGIN_DEFINE_DEPRECATED(name) \
	DEPRECATED_OLD_ARCH_PLUGIN(name); \
	ARCH_PLUGIN_LIB_STRUCT(name)

#define RZ_ARCH_PLUGIN_DEFINE_DEPRECATED(name) \
	DEPRECATED_OLD_ARCH_NO_PARSE_PLUGIN(name); \
	ARCH_PLUGIN_LIB_STRUCT(name)

#define RZ_ARCH_ASM_ONLY_PLUGIN_DEFINE_DEPRECATED(name) \
	DEPRECATED_OLD_ARCH_ASM_ONLY_PLUGIN(name); \
	ARCH_PLUGIN_LIB_STRUCT(name)

#endif /* DEPRECATED_ARCH_HELPER_H */