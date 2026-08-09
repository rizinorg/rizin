// SPDX-FileCopyrightText: 2026 kx7m2qd <kx7m2qd@users.noreply.github.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_str_uri.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_assert.h>

typedef struct {
	bool is_set;
	char *s;
	st64 i;
	bool b;
} UriParamValue;

struct rz_str_uri_params_t {
	const RzStrUriParamSpec *grammar;
	size_t grammar_count;
	UriParamValue *values;
};

static const RzStrUriParamSpec *find_spec(const RzStrUriParamSpec *grammar, size_t grammar_count, const char *name) {
	for (size_t i = 0; i < grammar_count; i++) {
		if (!strcmp(grammar[i].name, name)) {
			return &grammar[i];
		}
	}
	return NULL;
}

static size_t spec_index(const RzStrUriParamSpec *grammar, size_t grammar_count, const RzStrUriParamSpec *spec) {
	return (size_t)(spec - grammar);
}

static bool parse_int(const char *value, st64 *out) {
	if (RZ_STR_ISEMPTY(value)) {
		return false;
	}
	char *end = NULL;
	errno = 0;
	long long v = strtoll(value, &end, 0);
	if (errno || !end || *end) {
		return false;
	}
	*out = (st64)v;
	return true;
}

RZ_API RZ_OWN RzStrUriParams *rz_str_uri_params_parse(
	RZ_NONNULL const char *param_str,
	RZ_NONNULL const RzStrUriParamSpec *grammar,
	size_t grammar_count,
	RZ_NULLABLE RZ_OUT char **error) {
	rz_return_val_if_fail(param_str && grammar, NULL);

	RzStrUriParams *params = RZ_NEW0(RzStrUriParams);
	if (!params) {
		return NULL;
	}
	params->grammar = grammar;
	params->grammar_count = grammar_count;
	params->values = RZ_NEWS0(UriParamValue, grammar_count ? grammar_count : 1);
	if (!params->values) {
		free(params);
		return NULL;
	}

	char *dup = strdup(param_str);
	if (!dup) {
		rz_str_uri_params_free(params);
		return NULL;
	}

	char *saveptr = NULL;
	char *tok = strtok_r(dup, ",", &saveptr);
	while (tok) {
		rz_str_trim(tok);
		if (RZ_STR_ISEMPTY(tok)) {
			tok = strtok_r(NULL, ",", &saveptr);
			continue;
		}
		char *eq = strchr(tok, '=');
		if (!eq) {
			if (error) {
				*error = rz_str_newf("invalid parameter '%s': expected 'key=value'", tok);
			}
			free(dup);
			rz_str_uri_params_free(params);
			return NULL;
		}
		*eq = 0;
		char *key = tok;
		char *value = eq + 1;
		rz_str_trim(key);
		rz_str_trim(value);

		const RzStrUriParamSpec *spec = find_spec(grammar, grammar_count, key);
		if (!spec) {
			if (error) {
				*error = rz_str_newf("unknown parameter '%s'", key);
			}
			free(dup);
			rz_str_uri_params_free(params);
			return NULL;
		}

		size_t idx = spec_index(grammar, grammar_count, spec);
		UriParamValue *slot = &params->values[idx];
		switch (spec->type) {
		case RZ_STR_URI_PARAM_TYPE_STRING:
			free(slot->s);
			slot->s = strdup(value);
			break;
		case RZ_STR_URI_PARAM_TYPE_INT:
			if (!parse_int(value, &slot->i)) {
				if (error) {
					*error = rz_str_newf("parameter '%s' expects an integer, got '%s'", key, value);
				}
				free(dup);
				rz_str_uri_params_free(params);
				return NULL;
			}
			break;
		case RZ_STR_URI_PARAM_TYPE_BOOL:
			if (!rz_str_is_bool(value)) {
				if (error) {
					*error = rz_str_newf("parameter '%s' expects a boolean, got '%s'", key, value);
				}
				free(dup);
				rz_str_uri_params_free(params);
				return NULL;
			}
			slot->b = rz_str_is_true(value);
			break;
		}
		slot->is_set = true;
		tok = strtok_r(NULL, ",", &saveptr);
	}
	free(dup);

	for (size_t i = 0; i < grammar_count; i++) {
		if (grammar[i].required && !params->values[i].is_set) {
			if (error) {
				*error = rz_str_newf("missing required parameter '%s'", grammar[i].name);
			}
			rz_str_uri_params_free(params);
			return NULL;
		}
	}

	return params;
}

RZ_API void rz_str_uri_params_free(RZ_NULLABLE RzStrUriParams *params) {
	if (!params) {
		return;
	}
	if (params->values) {
		for (size_t i = 0; i < params->grammar_count; i++) {
			if (params->grammar[i].type == RZ_STR_URI_PARAM_TYPE_STRING) {
				free(params->values[i].s);
			}
		}
		free(params->values);
	}
	free(params);
}

RZ_API bool rz_str_uri_params_has(RZ_NONNULL const RzStrUriParams *params, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(params && name, false);
	const RzStrUriParamSpec *spec = find_spec(params->grammar, params->grammar_count, name);
	if (!spec) {
		return false;
	}
	size_t idx = spec_index(params->grammar, params->grammar_count, spec);
	return params->values[idx].is_set;
}

RZ_API bool rz_str_uri_params_get_string(RZ_NONNULL const RzStrUriParams *params, RZ_NONNULL const char *name, RZ_NONNULL RZ_OUT const char **value) {
	rz_return_val_if_fail(params && name && value, false);
	const RzStrUriParamSpec *spec = find_spec(params->grammar, params->grammar_count, name);
	if (!spec || spec->type != RZ_STR_URI_PARAM_TYPE_STRING) {
		return false;
	}
	size_t idx = spec_index(params->grammar, params->grammar_count, spec);
	if (!params->values[idx].is_set) {
		return false;
	}
	*value = params->values[idx].s;
	return true;
}

RZ_API bool rz_str_uri_params_get_int(RZ_NONNULL const RzStrUriParams *params, RZ_NONNULL const char *name, RZ_NONNULL RZ_OUT st64 *value) {
	rz_return_val_if_fail(params && name && value, false);
	const RzStrUriParamSpec *spec = find_spec(params->grammar, params->grammar_count, name);
	if (!spec || spec->type != RZ_STR_URI_PARAM_TYPE_INT) {
		return false;
	}
	size_t idx = spec_index(params->grammar, params->grammar_count, spec);
	if (!params->values[idx].is_set) {
		return false;
	}
	*value = params->values[idx].i;
	return true;
}

RZ_API bool rz_str_uri_params_get_bool(RZ_NONNULL const RzStrUriParams *params, RZ_NONNULL const char *name, RZ_NONNULL RZ_OUT bool *value) {
	rz_return_val_if_fail(params && name && value, false);
	const RzStrUriParamSpec *spec = find_spec(params->grammar, params->grammar_count, name);
	if (!spec || spec->type != RZ_STR_URI_PARAM_TYPE_BOOL) {
		return false;
	}
	size_t idx = spec_index(params->grammar, params->grammar_count, spec);
	if (!params->values[idx].is_set) {
		return false;
	}
	*value = params->values[idx].b;
	return true;
}
