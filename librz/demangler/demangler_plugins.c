// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <config.h>

#define DEFINE_DEMANGLER_PLUGIN(name, lang, lic, auth, handler) \
	RZ_API RzDemanglerPlugin rz_demangler_plugin_##name = { \
		.language = lang, \
		.license = lic, \
		.author = auth, \
		.demangle = &handler, \
	}

#if WITH_GPL
DEFINE_DEMANGLER_PLUGIN(cpp, "c++", "GPL-2", "Free Software Foundation", libdemangle_handler_cxx);
// rust demangler requires the cpp one.
DEFINE_DEMANGLER_PLUGIN(rust, "rust", "LGPL3", "pancake", libdemangle_handler_rust);
#endif
#if WITH_SWIFT_DEMANGLER
DEFINE_DEMANGLER_PLUGIN(swift, "swift", "MIT", "pancake", libdemangle_handler_swift);
#endif

DEFINE_DEMANGLER_PLUGIN(java, "java", "LGPL3", "deroad", libdemangle_handler_java);
DEFINE_DEMANGLER_PLUGIN(msvc, "msvc", "LGPL3", "inisider", libdemangle_handler_msvc);
DEFINE_DEMANGLER_PLUGIN(objc, "objc", "LGPL3", "pancake", libdemangle_handler_objc);

static RzDemanglerPlugin *demangler_static_plugins[] = { RZ_DEMANGLER_STATIC_PLUGINS };
