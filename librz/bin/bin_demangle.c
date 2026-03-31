// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_util.h>

#define skip_prefix_s(s, p) \
	do { \
		if (!strncmp(s, p, strlen(p))) { \
			s += strlen(p); \
		} \
	} while (0)

#define skip_prefix_n(s, p, n) \
	do { \
		if (!strncmp(s, p, strlen(p))) { \
			s += n; \
		} \
	} while (0)

static const char *get_mangled_name(const char *mangled) {
	if (!mangled || !strncmp(mangled, "__OBJC_$", strlen("__OBJC_$"))) {
		// this is never a mangled name
		return NULL;
	}

	skip_prefix_n(mangled, "__OBJC_", 1);

	return RZ_STR_ISEMPTY(mangled) ? NULL : mangled;
}
#undef skip_prefix_s
#undef skip_prefix_n

RZ_IPI bool rz_bin_demangle_symbol(RzBinSymbol *bsym, const RzDemanglerPlugin *plugin, RzDemanglerFlag flags, bool force) {
	if (!plugin || (bsym->dname && !force)) {
		return false;
	}

	const char *mangled = get_mangled_name(bsym->name);
	if (!mangled) {
		return false;
	}

	free(bsym->dname);
	bsym->dname = plugin->demangle(mangled, flags);
	return bsym->dname != NULL;
}

RZ_IPI bool rz_bin_demangle_import(RzBinImport *import, const RzDemanglerPlugin *plugin, RzDemanglerFlag flags, bool force) {
	if (!plugin || (import->dname && !force)) {
		return false;
	}

	const char *mangled = get_mangled_name(import->name);
	if (!mangled) {
		return false;
	}

	char *demangled = plugin->demangle(mangled, flags);
	if (!demangled) {
		return false;
	}

	free(import->dname);
	import->dname = demangled;
	return true;
}

/**
 * \brief Demangles a symbol based on the language or by iterating all demanglers.
 *
 * This function demangles a symbol based on the language or by iterating all demanglers.
 * The iteration of all demanglers is available only if the RzBin pointer is not NULL.
 *
 * \param   bin       The RzBin context to used for demangling
 * \param   language  The language to be used for demangling
 * \param   mangled   The mangled string to be demangled
 * \return  On success returns a valid pointer, otherwise NULL.
 */
RZ_API RZ_OWN char *rz_bin_demangle(RZ_NULLABLE RzBin *bin, RZ_NULLABLE const char *language, RZ_NULLABLE const char *mangled) {
	if (RZ_STR_ISEMPTY(mangled)) {
		return NULL;
	}

	RzBinLanguage type = language ? rz_bin_language_to_id(language) : RZ_BIN_LANGUAGE_UNKNOWN;
	type = RZ_BIN_LANGUAGE_MASK(type);
	RzDemanglerFlag flags = bin ? rz_demangler_get_flags(bin->demangler) : RZ_DEMANGLER_FLAG_ENABLE_ALL;

	switch (type) {
	case RZ_BIN_LANGUAGE_KOTLIN:
		/* fall-thru */
	case RZ_BIN_LANGUAGE_GROOVY:
		/* fall-thru */
	case RZ_BIN_LANGUAGE_DART:
		/* fall-thru */
	case RZ_BIN_LANGUAGE_JAVA:
		return rz_demangler_java(mangled, flags);
	case RZ_BIN_LANGUAGE_OBJC:
		return rz_demangler_objc(mangled, flags);
	case RZ_BIN_LANGUAGE_MSVC:
		return rz_demangler_msvc(mangled, flags);
	case RZ_BIN_LANGUAGE_PASCAL:
		return rz_demangler_pascal(mangled, flags);
	case RZ_BIN_LANGUAGE_RUST:
		return rz_demangler_rust(mangled, flags);
	case RZ_BIN_LANGUAGE_CXX:
		return rz_demangler_cxx(mangled, flags);
	default:
		break;
	}

	if (!bin || RZ_STR_ISEMPTY(language)) {
		return NULL;
	}

	char *demangled = NULL;
	bool res = rz_demangler_resolve(bin->demangler, mangled, language, &demangled);
	return res ? demangled : NULL;
}
