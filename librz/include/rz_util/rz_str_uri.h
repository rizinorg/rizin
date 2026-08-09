// SPDX-FileCopyrightText: 2026 kx7m2qd <kx7m2qd@users.noreply.github.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_STR_URI_H
#define RZ_STR_URI_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Type of a single URI parameter value, as declared in its grammar entry.
 */
typedef enum {
	RZ_STR_URI_PARAM_TYPE_STRING = 0, ///< Value is kept as-is (a copied string).
	RZ_STR_URI_PARAM_TYPE_INT, ///< Value is parsed as a signed 64-bit integer.
	RZ_STR_URI_PARAM_TYPE_BOOL, ///< Value is parsed with \p rz_str_is_true / \p rz_str_is_false rules.
} RzStrUriParamType;

/**
 * \brief Describes a single parameter accepted by a plugin's URI, used to validate
 * and type-check a parameter string before it is handed to the plugin.
 */
typedef struct rz_str_uri_param_spec_t {
	RZ_NONNULL const char *name; ///< Parameter key, as it appears before '=' in the param string.
	RzStrUriParamType type; ///< Expected type of the value.
	bool required; ///< If true, parsing fails when this key is not present in the input.
} RzStrUriParamSpec;

/**
 * \brief Opaque handle to a parsed, type-checked set of URI parameters.
 *
 * \note The \p grammar array passed to \p rz_str_uri_params_parse is borrowed, not
 * copied: it must stay valid for the lifetime of the returned RzStrUriParams. In
 * practice this means grammar tables should be declared `static const`.
 */
typedef struct rz_str_uri_params_t RzStrUriParams;

RZ_API RZ_OWN RzStrUriParams *rz_str_uri_params_parse(
	RZ_NONNULL const char *param_str,
	RZ_NONNULL const RzStrUriParamSpec *grammar,
	size_t grammar_count,
	RZ_NULLABLE RZ_OUT char **error);
RZ_API void rz_str_uri_params_free(RZ_NULLABLE RzStrUriParams *params);

RZ_API bool rz_str_uri_params_has(RZ_NONNULL const RzStrUriParams *params, RZ_NONNULL const char *name);
RZ_API bool rz_str_uri_params_get_string(RZ_NONNULL const RzStrUriParams *params, RZ_NONNULL const char *name, RZ_NONNULL RZ_OUT const char **value);
RZ_API bool rz_str_uri_params_get_int(RZ_NONNULL const RzStrUriParams *params, RZ_NONNULL const char *name, RZ_NONNULL RZ_OUT st64 *value);
RZ_API bool rz_str_uri_params_get_bool(RZ_NONNULL const RzStrUriParams *params, RZ_NONNULL const char *name, RZ_NONNULL RZ_OUT bool *value);

#ifdef __cplusplus
}
#endif

#endif // RZ_STR_URI_H
