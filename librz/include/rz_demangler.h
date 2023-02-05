// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_DEMANGLER_H
#define RZ_DEMANGLER_H
#include <rz_types.h>
#include <rz_list.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_demangler);

typedef struct rz_demangler_plugin_t {
	const char *language; ///< demangler language
	const char *author; ///< demangler author
	const char *license; ///< demangler license
	RZ_OWN char *(*demangle)(RZ_NONNULL const char *symbol); ///< demangler method to resolve the mangled symbol
} RzDemanglerPlugin;

typedef struct rz_demangler_t {
	RzList /*<RzDemanglerPlugin *>*/ *plugins;
} RzDemangler;

typedef bool (*RzDemanglerIter)(const RzDemanglerPlugin *plugin, void *data);

#define rz_demangler_plugin_demangle(x, y) ((x) && RZ_STR_ISNOTEMPTY(y) ? (x)->demangle(y) : NULL)

RZ_API RZ_OWN char *rz_demangler_java(RZ_NULLABLE const char *symbol);
RZ_API RZ_OWN char *rz_demangler_cxx(RZ_NONNULL const char *symbol);
RZ_API RZ_OWN char *rz_demangler_objc(RZ_NONNULL const char *symbol);
RZ_API RZ_OWN char *rz_demangler_pascal(RZ_NONNULL const char *symbol);
RZ_API RZ_OWN char *rz_demangler_rust(RZ_NONNULL const char *symbol);
RZ_API RZ_OWN char *rz_demangler_msvc(RZ_NONNULL const char *symbol);

RZ_API RZ_OWN RzDemangler *rz_demangler_new(void);
RZ_API void rz_demangler_free(RZ_NULLABLE RzDemangler *demangler);
RZ_API void rz_demangler_plugin_iterate(RZ_NONNULL RzDemangler *demangler, RZ_NONNULL RzDemanglerIter iter, RZ_NULLABLE void *data);
RZ_API bool rz_demangler_plugin_add(RZ_NONNULL RzDemangler *demangler, RZ_NONNULL RzDemanglerPlugin *plugin);
RZ_API bool rz_demangler_plugin_del(RZ_NONNULL RzDemangler *demangler, RZ_NONNULL RzDemanglerPlugin *plugin);
RZ_API RZ_BORROW const RzDemanglerPlugin *rz_demangler_plugin_get(RZ_NONNULL RzDemangler *demangler, RZ_NONNULL const char *language);
RZ_API bool rz_demangler_resolve(RZ_NONNULL RzDemangler *demangler, RZ_NULLABLE const char *symbol, RZ_NONNULL const char *language, RZ_NONNULL RZ_OWN char **output);

#ifdef __cplusplus
}
#endif

#endif /* RZ_DEMANGLER_H */
