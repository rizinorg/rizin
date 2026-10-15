// SPDX-FileCopyrightText: 2026 kx7m2qd <kx7m2qd@users.noreply.github.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_str_uri.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_num.h>
#include <rz_util/rz_assert.h>
#include <rz_vector.h>

typedef struct {
	bool is_set;
	char *value_string;
	st64 value_int;
	bool value_bool;
} UriParamValue;

struct rz_str_uri_params_t {
	const RzPVector /*<RzStrUriParamSpec *>*/ *grammars;
	size_t grammars_count;
	UriParamValue *values;
};

static const RzStrUriParamSpec *find_spec(const RzPVector *grammars, const char *name, size_t *index) {
	size_t count = rz_pvector_len(grammars);
	for (size_t i = 0; i < count; i++) {
		const RzStrUriParamSpec *spec = rz_pvector_at(grammars, i);
		if (RZ_STR_EQ(spec->name, name)) {
			if (index) {
				*index = i;
			}
			return spec;
		}
	}
	return NULL;
}

static bool parse_int(const char *value_string, st64 *out) {
	if (RZ_STR_ISEMPTY(value_string)) {
		return false;
	}
	bool negative = false;
	const char *p = value_string;
	if (*p == '-') {
		negative = true;
		p++;
	} else if (*p == '+') {
		p++;
	}
	if (RZ_STR_ISEMPTY(p)) {
		return false;
	}
	ut64 magnitude = 0;
	bool overflow = false;
	if (!rz_num_is_int_literal(p, &magnitude, &overflow) || overflow) {
		return false;
	}
	if (negative) {
		if (magnitude > (ut64)INT64_MAX + 1) {
			return false;
		}
		*out = -(st64)magnitude;
	} else {
		if (magnitude > (ut64)INT64_MAX) {
			return false;
		}
		*out = (st64)magnitude;
	}
	return true;
}

/**
 * \brief Parse a "key=value,key=value" style URI parameter string against a caller-defined grammar.
 *
 * Splits \\p param_str on commas, then each chunk on the first '=', validates every
 * key against \\p grammars, type-checks the value, and rejects unknown keys, malformed
 * pairs, type mismatches, and missing required parameters. Surrounding whitespace
 * around keys, values, and separators is tolerated.
 *
 * \param param_str Raw parameter string, e.g. "d=32,verbose=true".
 * \param grammars RZ_NONNULL Vector of RZ_BORROW RzStrUriParamSpec entries describing the accepted keys.
 * \param error RZ_NULLABLE RZ_OUT On failure, set to a newly allocated, caller-owned error message.
 * \return RZ_OWN A new RzStrUriParams handle on success, or NULL on failure.
 */
RZ_API RZ_OWN RzStrUriParams *rz_str_uri_params_parse(
	RZ_NONNULL const char *param_str,
	RZ_NONNULL const RzPVector *grammars,
	RZ_NULLABLE RZ_OUT RZ_OWN char **error) {
	rz_return_val_if_fail(param_str && grammars, NULL);

	size_t grammars_count = rz_pvector_len(grammars);
	char *dup = NULL;
	RzList *pairs = NULL;

	RzStrUriParams *params = RZ_NEW0(RzStrUriParams);
	if (!params) {
		return NULL;
	}
	params->grammars = grammars;
	params->grammars_count = grammars_count;
	params->values = RZ_NEWS0(UriParamValue, grammars_count ? grammars_count : 1);
	if (!params->values) {
		goto fail;
	}

	dup = strdup(param_str);
	if (!dup) {
		goto fail;
	}

	pairs = rz_str_split_duplist(dup, ",", true);
	RzListIter *iter;
	char *tok;
	rz_list_foreach (pairs, iter, tok) {
		rz_str_trim(tok);
		if (RZ_STR_ISEMPTY(tok)) {
			continue;
		}
		char *eq = strchr(tok, '=');
		if (!eq) {
			if (error) {
				*error = rz_str_newf("invalid parameter '%s': expected 'key=value'", tok);
			}
			goto fail;
		}
		*eq = 0;
		char *key = tok;
		char *value_string = eq + 1;
		rz_str_trim(key);
		rz_str_trim(value_string);

		if (RZ_STR_ISEMPTY(key)) {
			if (error) {
				*error = rz_str_newf("invalid parameter: empty key");
			}
			goto fail;
		}
		if (strchr(value_string, '=')) {
			if (error) {
				*error = rz_str_newf("invalid parameter '%s': unexpected '=' in value", key);
			}
			goto fail;
		}
		if (RZ_STR_ISEMPTY(value_string)) {
			if (error) {
				*error = rz_str_newf("parameter '%s' has an empty value", key);
			}
			goto fail;
		}

		size_t idx = 0;
		const RzStrUriParamSpec *spec = find_spec(grammars, key, &idx);
		if (!spec) {
			if (error) {
				*error = rz_str_newf("unknown parameter '%s'", key);
			}
			goto fail;
		}

		UriParamValue *slot = &params->values[idx];
		switch (spec->type) {
		case RZ_STR_URI_PARAM_TYPE_STRING:
			free(slot->value_string);
			slot->value_string = strdup(value_string);
			break;
		case RZ_STR_URI_PARAM_TYPE_INT:
			if (!parse_int(value_string, &slot->value_int)) {
				if (error) {
					*error = rz_str_newf("parameter '%s' expects an integer, got '%s'", key, value_string);
				}
				goto fail;
			}
			break;
		case RZ_STR_URI_PARAM_TYPE_BOOL:
			if (!rz_str_is_bool(value_string)) {
				if (error) {
					*error = rz_str_newf("parameter '%s' expects a boolean, got '%s'", key, value_string);
				}
				goto fail;
			}
			slot->value_bool = rz_str_is_true(value_string);
			break;
		}
		slot->is_set = true;
	}
	rz_list_free(pairs);
	free(dup);

	for (size_t i = 0; i < grammars_count; i++) {
		const RzStrUriParamSpec *spec = rz_pvector_at(grammars, i);
		if (spec->required && !params->values[i].is_set) {
			if (error) {
				*error = rz_str_newf("missing required parameter '%s'", spec->name);
			}
			rz_str_uri_params_free(params);
			return NULL;
		}
	}

	return params;

fail:
	rz_list_free(pairs);
	free(dup);
	rz_str_uri_params_free(params);
	return NULL;
}

/**
 * \brief Free an RzStrUriParams handle and any strings it owns.
 * \param params RZ_NULLABLE The handle to free. NULL is a no-op.
 */
RZ_API void rz_str_uri_params_free(RZ_NULLABLE RzStrUriParams *params) {
	if (!params) {
		return;
	}
	for (size_t i = 0; params->values && i < params->grammars_count; i++) {
		const RzStrUriParamSpec *spec = rz_pvector_at(params->grammars, i);
		if (spec->type == RZ_STR_URI_PARAM_TYPE_STRING) {
			free(params->values[i].value_string);
		}
	}
	free(params->values);
	free(params);
}

/**
 * \brief Check whether a parameter was present in the parsed input.
 * \param params RZ_NONNULL Parsed parameters handle.
 * \param name RZ_NONNULL Parameter key to look up.
 * \return true if the key was set during parsing, false otherwise (including if unknown).
 */
RZ_API bool rz_str_uri_params_has(RZ_NONNULL const RzStrUriParams *params, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(params && name, false);
	size_t idx = 0;
	const RzStrUriParamSpec *spec = find_spec(params->grammars, name, &idx);
	if (!spec) {
		return false;
	}
	return params->values[idx].is_set;
}

/**
 * \brief Retrieve a string-typed parameter's value.
 * \param params RZ_NONNULL Parsed parameters handle.
 * \param name RZ_NONNULL Parameter key to look up.
 * \param value RZ_NONNULL RZ_OUT Set to the RZ_BORROW string value on success.
 * \return true if the key exists, is string-typed, and was set; false otherwise.
 */
RZ_API bool rz_str_uri_params_get_string(RZ_NONNULL const RzStrUriParams *params, RZ_NONNULL const char *name, RZ_NONNULL RZ_OUT const char **value) {
	rz_return_val_if_fail(params && name && value, false);
	size_t idx = 0;
	const RzStrUriParamSpec *spec = find_spec(params->grammars, name, &idx);
	if (!spec || spec->type != RZ_STR_URI_PARAM_TYPE_STRING) {
		return false;
	}
	if (!params->values[idx].is_set) {
		return false;
	}
	*value = params->values[idx].value_string;
	return true;
}

/**
 * \brief Retrieve an int-typed parameter's value.
 * \param params RZ_NONNULL Parsed parameters handle.
 * \param name RZ_NONNULL Parameter key to look up.
 * \param value RZ_NONNULL RZ_OUT Set to the integer value on success.
 * \return true if the key exists, is int-typed, and was set; false otherwise.
 */
RZ_API bool rz_str_uri_params_get_int(RZ_NONNULL const RzStrUriParams *params, RZ_NONNULL const char *name, RZ_NONNULL RZ_OUT st64 *value) {
	rz_return_val_if_fail(params && name && value, false);
	size_t idx = 0;
	const RzStrUriParamSpec *spec = find_spec(params->grammars, name, &idx);
	if (!spec || spec->type != RZ_STR_URI_PARAM_TYPE_INT) {
		return false;
	}
	if (!params->values[idx].is_set) {
		return false;
	}
	*value = params->values[idx].value_int;
	return true;
}

/**
 * \brief Retrieve a bool-typed parameter's value.
 * \param params RZ_NONNULL Parsed parameters handle.
 * \param name RZ_NONNULL Parameter key to look up.
 * \param value RZ_NONNULL RZ_OUT Set to the boolean value on success.
 * \return true if the key exists, is bool-typed, and was set; false otherwise.
 */
RZ_API bool rz_str_uri_params_get_bool(RZ_NONNULL const RzStrUriParams *params, RZ_NONNULL const char *name, RZ_NONNULL RZ_OUT bool *value) {
	rz_return_val_if_fail(params && name && value, false);
	size_t idx = 0;
	const RzStrUriParamSpec *spec = find_spec(params->grammars, name, &idx);
	if (!spec || spec->type != RZ_STR_URI_PARAM_TYPE_BOOL) {
		return false;
	}
	if (!params->values[idx].is_set) {
		return false;
	}
	*value = params->values[idx].value_bool;
	return true;
}
