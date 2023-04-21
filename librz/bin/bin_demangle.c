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
	if (!strncmp(mangled, "__OBJC_$", strlen("__OBJC_$"))) {
		// this is never a mangled name
		return NULL;
	}

	skip_prefix_s(mangled, "reloc.");
	skip_prefix_s(mangled, "imp.");
	skip_prefix_s(mangled, "target.");
	skip_prefix_n(mangled, "__OBJC_", 1);

	return RZ_STR_ISEMPTY(mangled) ? NULL : mangled;
}
#undef skip_prefix_s
#undef skip_prefix_n

RZ_IPI bool rz_bin_demangle_symbol(RzBinSymbol *bsym, const RzDemanglerPlugin *plugin) {
	if (bsym->dname) {
		return false;
	}

	const char *mangled = get_mangled_name(bsym->name);
	if (!mangled) {
		return false;
	}

	bsym->dname = plugin->demangle(mangled);
	return bsym->dname != NULL;
}

RZ_IPI bool rz_bin_demangle_import(RzBinImport *import, const RzDemanglerPlugin *plugin) {
	if (!import->name) {
		return false;
	}

	const char *mangled = get_mangled_name(import->name);
	if (!mangled) {
		return false;
	}

	char *demangled = plugin->demangle(mangled);
	if (!demangled) {
		return false;
	}

	free(import->name);
	import->name = demangled;
	return true;
}

RZ_IPI bool rz_bin_demangle_reloc(RzBinReloc *reloc, const RzDemanglerPlugin *plugin) {
	bool res = false;
	if (reloc->import) {
		res |= rz_bin_demangle_import(reloc->import, plugin) ? 1 : 0;
	}
	if (reloc->symbol) {
		res |= rz_bin_demangle_symbol(reloc->symbol, plugin) ? 1 : 0;
	}
	return res;
}
