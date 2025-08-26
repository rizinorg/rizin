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

typedef enum {
	RZ_DEMANGLER_FLAG_BASE = 0,
	RZ_DEMANGLER_FLAG_SIMPLIFY = (1 << 0),
	RZ_DEMANGLER_FLAG_ENABLE_ALL = (RZ_DEMANGLER_FLAG_BASE | RZ_DEMANGLER_FLAG_SIMPLIFY),
} RzDemanglerFlag;

typedef RZ_OWN char *(*RzDemanglerPluginCb)(RZ_NONNULL const char *symbol, RzDemanglerFlag flags);

typedef struct rz_demangler_plugin_t {
	const char *language; ///< demangler language
	const char *author; ///< demangler author
	const char *license; ///< demangler license
	RzDemanglerPluginCb demangle; ///< demangler method to resolve the mangled symbol
} RzDemanglerPlugin;

typedef struct rz_demangler_t {
	RzDemanglerFlag flags;
	RzList /*<RzDemanglerPlugin *>*/ *plugins;
} RzDemangler;

typedef bool (*RzDemanglerIter)(const RzDemanglerPlugin *plugin, RzDemanglerFlag flags, void *data);

#define rz_demangler_plugin_demangle(x, y, o) ((x) && RZ_STR_ISNOTEMPTY(y) ? (x)->demangle(y, o) : NULL)

RZ_API RZ_OWN char *rz_demangler_java(RZ_NULLABLE const char *symbol, RzDemanglerFlag flags);
RZ_API RZ_OWN char *rz_demangler_cxx(RZ_NONNULL const char *symbol, RzDemanglerFlag flags);
RZ_API RZ_OWN char *rz_demangler_objc(RZ_NONNULL const char *symbol, RzDemanglerFlag flags);
RZ_API RZ_OWN char *rz_demangler_pascal(RZ_NONNULL const char *symbol, RzDemanglerFlag flags);
RZ_API RZ_OWN char *rz_demangler_rust(RZ_NONNULL const char *symbol, RzDemanglerFlag flags);
RZ_API RZ_OWN char *rz_demangler_msvc(RZ_NONNULL const char *symbol, RzDemanglerFlag flags);

RZ_API RZ_OWN RzDemangler *rz_demangler_new(void);
RZ_API void rz_demangler_free(RZ_NULLABLE RzDemangler *demangler);
RZ_API void rz_demangler_set_flags(RZ_NONNULL RzDemangler *demangler, RzDemanglerFlag flags);
RZ_API RzDemanglerFlag rz_demangler_get_flags(RZ_NONNULL RzDemangler *demangler);
RZ_API void rz_demangler_plugin_iterate(RZ_NONNULL RzDemangler *demangler, RZ_NONNULL RzDemanglerIter iter, RZ_NULLABLE void *data);
RZ_API bool rz_demangler_plugin_add(RZ_NONNULL RzDemangler *demangler, RZ_NONNULL RzDemanglerPlugin *plugin);
RZ_API bool rz_demangler_plugin_del(RZ_NONNULL RzDemangler *demangler, RZ_NONNULL RzDemanglerPlugin *plugin);
RZ_API RZ_BORROW const RzDemanglerPlugin *rz_demangler_plugin_get(RZ_NONNULL RzDemangler *demangler, RZ_NONNULL const char *language);
RZ_API bool rz_demangler_resolve(RZ_NONNULL RzDemangler *demangler, RZ_NULLABLE const char *symbol, RZ_NONNULL const char *language, RZ_NONNULL RZ_OWN char **output);

#ifdef __cplusplus
}
#endif

#endif /* RZ_DEMANGLER_H */
