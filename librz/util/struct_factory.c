// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

#include "struct_factory_json.c"
#include "struct_factory_yaml.c"

typedef enum {
	STRUCT_FACTORY_TYPE_MAP = 0,
	STRUCT_FACTORY_TYPE_ARRAY,
	STRUCT_FACTORY_TYPE_UNSIGNED,
	STRUCT_FACTORY_TYPE_HEXADECIMAL,
	STRUCT_FACTORY_TYPE_SIGNED,
	STRUCT_FACTORY_TYPE_DOUBLE,
	STRUCT_FACTORY_TYPE_BOOL,
	STRUCT_FACTORY_TYPE_STRING,
} StructFactoryType;

struct rz_struct_factory_t {
	StructFactoryType type;
	union {
		ut64 v_unsigned;
		st64 v_signed;
		double v_double;
		bool v_bool;
		char *v_string;
		HtSP /*<RzStructFactory *>*/ *v_map;
	};
	RzPVector /*<void *>*/ *v_array; // used also to keep the map keys in order
};

typedef struct struct_factory_iter_over_t {
	const RzStructFactoryIterator *fit;
	void *user;
} StructFactoryIterOver;

RZ_API void rz_struct_factory_free(RZ_NULLABLE RzStructFactory *sf) {
	if (!sf) {
		return;
	}

	if (sf->type == STRUCT_FACTORY_TYPE_MAP) {
		ht_sp_free(sf->v_map);
		rz_pvector_free(sf->v_array);
	} else if (sf->type == STRUCT_FACTORY_TYPE_ARRAY) {
		rz_pvector_free(sf->v_array);
	} else if (sf->type == STRUCT_FACTORY_TYPE_STRING) {
		free(sf->v_string);
	}
	free(sf);
}

static RzStructFactory *struct_factory_new_map() {
	RzStructFactory *sf = RZ_NEW0(RzStructFactory);
	if (!sf) {
		return NULL;
	}
	sf->type = STRUCT_FACTORY_TYPE_MAP;
	sf->v_map = ht_sp_new(HT_STR_DUP, NULL, (HtSPFreeValue)rz_struct_factory_free);
	sf->v_array = rz_pvector_new((RzPVectorFree)free);
	if (!sf->v_map || !sf->v_array) {
		rz_struct_factory_free(sf);
		return NULL;
	}
	return sf;
}

static RzStructFactory *struct_factory_new_array() {
	RzStructFactory *sf = RZ_NEW0(RzStructFactory);
	if (!sf) {
		return NULL;
	}
	sf->type = STRUCT_FACTORY_TYPE_ARRAY;
	sf->v_array = rz_pvector_new((RzPVectorFree)rz_struct_factory_free);
	if (!sf->v_array) {
		free(sf);
		return NULL;
	}
	return sf;
}

static RzStructFactory *struct_factory_new_unsigned(ut64 v_unsigned, bool hex) {
	RzStructFactory *sf = RZ_NEW0(RzStructFactory);
	if (!sf) {
		return NULL;
	}
	sf->type = hex ? STRUCT_FACTORY_TYPE_HEXADECIMAL : STRUCT_FACTORY_TYPE_UNSIGNED;
	sf->v_unsigned = v_unsigned;
	return sf;
}

static RzStructFactory *struct_factory_new_signed(st64 v_signed) {
	RzStructFactory *sf = RZ_NEW0(RzStructFactory);
	if (!sf) {
		return NULL;
	}
	sf->type = STRUCT_FACTORY_TYPE_SIGNED;
	sf->v_signed = v_signed;
	return sf;
}

static RzStructFactory *struct_factory_new_double(double v_double) {
	RzStructFactory *sf = RZ_NEW0(RzStructFactory);
	if (!sf) {
		return NULL;
	}
	sf->type = STRUCT_FACTORY_TYPE_DOUBLE;
	sf->v_double = v_double;
	return sf;
}

static RzStructFactory *struct_factory_new_bool(bool v_bool) {
	RzStructFactory *sf = RZ_NEW0(RzStructFactory);
	if (!sf) {
		return NULL;
	}
	sf->type = STRUCT_FACTORY_TYPE_BOOL;
	sf->v_bool = v_bool;
	return sf;
}

static RzStructFactory *struct_factory_new_string(char *v_string) {
	RzStructFactory *sf = RZ_NEW0(RzStructFactory);
	if (!sf) {
		return NULL;
	}
	sf->type = STRUCT_FACTORY_TYPE_STRING;
	sf->v_string = v_string;
	return sf;
}

static bool struct_factory_map_add(RzStructFactory *sf, const char *key, RZ_OWN RzStructFactory *value) {
	RzPVector *pvec = sf->v_array;
	HtSP *map = sf->v_map;
	if (!map || !pvec || !value || RZ_STR_ISEMPTY(key)) {
		rz_struct_factory_free(value);
		RZ_LOG_ERROR("struct_factory: invalid key: '%s'\n", key);
		return false;
	}

	bool found = false;
	ht_sp_find(map, key, &found);
	if (found) {
		rz_struct_factory_free(value);
		RZ_LOG_ERROR("struct_factory: found duplicated key: '%s'\n", key);
		return false;
	}

	char *key_copy = rz_str_dup(key);
	if (!key_copy || !ht_sp_insert(map, key_copy, value)) {
		rz_struct_factory_free(value);
		free(key_copy);
		RZ_LOG_ERROR("struct_factory: cannot add value with key: '%s'\n", key);
		return false;
	}

	return rz_pvector_push(pvec, key_copy);
}

static bool struct_factory_array_add(RzStructFactory *sf, RZ_OWN RzStructFactory *value) {
	RzPVector *pvec = sf->v_array;
	if (!pvec || !value) {
		RZ_LOG_ERROR("struct_factory: invalid array value\n");
		return false;
	}
	rz_pvector_push(pvec, value);
	return true;
}

/**
 * \brief      Creates a new RzStructFactory initialized as a map
 *
 * \return     On success returns a valid opaque pointer to a RzStructFactory
 */
RZ_API RZ_OWN RzStructFactory *rz_struct_factory_new_map() {
	return struct_factory_new_map();
}

/**
 * \brief      Creates a new RzStructFactory initialized as an array
 *
 * \return     On success returns a valid opaque pointer to a RzStructFactory
 */
RZ_API RZ_OWN RzStructFactory *rz_struct_factory_new_array() {
	return struct_factory_new_array();
}

RZ_API RZ_BORROW RzStructFactory *rz_struct_factory_map_add_map(RZ_NONNULL RzStructFactory *sf, RZ_NONNULL const char *key) {
	rz_return_val_if_fail(sf && sf->type == STRUCT_FACTORY_TYPE_MAP && key, false);

	RzStructFactory *value = struct_factory_new_map();
	if (!struct_factory_map_add(sf, key, value)) {
		return NULL;
	}

	return value;
}

RZ_API RZ_BORROW RzStructFactory *rz_struct_factory_map_add_array(RZ_NONNULL RzStructFactory *sf, RZ_NONNULL const char *key) {
	rz_return_val_if_fail(sf && sf->type == STRUCT_FACTORY_TYPE_MAP && key, false);

	RzStructFactory *value = struct_factory_new_array();
	if (!struct_factory_map_add(sf, key, value)) {
		return NULL;
	}

	return value;
}

RZ_API bool rz_struct_factory_map_add(RZ_NONNULL RzStructFactory *sf, RZ_NONNULL const char *key, RZ_NONNULL RZ_OWN RzStructFactory *value) {
	rz_return_val_if_fail(sf && sf->type == STRUCT_FACTORY_TYPE_MAP && key && value, false);

	return struct_factory_map_add(sf, key, value);
}

RZ_API bool rz_struct_factory_map_add_unsigned(RZ_NONNULL RzStructFactory *sf, RZ_NONNULL const char *key, ut64 n, bool hex) {
	rz_return_val_if_fail(sf && sf->type == STRUCT_FACTORY_TYPE_MAP && key, false);

	RzStructFactory *value = struct_factory_new_unsigned(n, hex);
	return struct_factory_map_add(sf, key, value);
}

RZ_API bool rz_struct_factory_map_add_signed(RZ_NONNULL RzStructFactory *sf, RZ_NONNULL const char *key, st64 n) {
	rz_return_val_if_fail(sf && sf->type == STRUCT_FACTORY_TYPE_MAP && key, false);

	RzStructFactory *value = struct_factory_new_signed(n);
	return struct_factory_map_add(sf, key, value);
}

RZ_API bool rz_struct_factory_map_add_double(RZ_NONNULL RzStructFactory *sf, RZ_NONNULL const char *key, double d) {
	rz_return_val_if_fail(sf && sf->type == STRUCT_FACTORY_TYPE_MAP && key, false);

	RzStructFactory *value = struct_factory_new_double(d);
	return struct_factory_map_add(sf, key, value);
}

RZ_API bool rz_struct_factory_map_add_boolean(RZ_NONNULL RzStructFactory *sf, RZ_NONNULL const char *key, bool b) {
	rz_return_val_if_fail(sf && sf->type == STRUCT_FACTORY_TYPE_MAP && key, false);

	RzStructFactory *value = struct_factory_new_bool(b);
	return struct_factory_map_add(sf, key, value);
}

RZ_API bool rz_struct_factory_map_add_string(RZ_NONNULL RzStructFactory *sf, RZ_NONNULL const char *key, RZ_NONNULL const char *s) {
	rz_return_val_if_fail(sf && sf->type == STRUCT_FACTORY_TYPE_MAP && key && s, false);

	char *copy = rz_str_dup(s);
	if (!copy) {
		return false;
	}

	RzStructFactory *value = struct_factory_new_string(copy);
	return struct_factory_map_add(sf, key, value);
}

RZ_API RZ_BORROW RzStructFactory *rz_struct_factory_array_add_map(RZ_NONNULL RzStructFactory *sf) {
	rz_return_val_if_fail(sf && sf->type == STRUCT_FACTORY_TYPE_ARRAY, false);

	RzStructFactory *value = struct_factory_new_map();
	if (!struct_factory_array_add(sf, value)) {
		return NULL;
	}

	return value;
}

RZ_API RZ_BORROW RzStructFactory *rz_struct_factory_array_add_array(RZ_NONNULL RzStructFactory *sf) {
	rz_return_val_if_fail(sf && sf->type == STRUCT_FACTORY_TYPE_ARRAY, false);

	RzStructFactory *value = struct_factory_new_array();
	if (!struct_factory_array_add(sf, value)) {
		return NULL;
	}

	return value;
}

RZ_API bool rz_struct_factory_array_add(RZ_NONNULL RzStructFactory *sf, RZ_NONNULL RZ_OWN RzStructFactory *value) {
	rz_return_val_if_fail(sf && sf->type == STRUCT_FACTORY_TYPE_ARRAY && value, false);

	return struct_factory_array_add(sf, value);
}

RZ_API bool rz_struct_factory_array_add_unsigned(RZ_NONNULL RzStructFactory *sf, ut64 n, bool hex) {
	rz_return_val_if_fail(sf && sf->type == STRUCT_FACTORY_TYPE_ARRAY, false);

	RzStructFactory *value = struct_factory_new_unsigned(n, hex);
	return struct_factory_array_add(sf, value);
}

RZ_API bool rz_struct_factory_array_add_signed(RZ_NONNULL RzStructFactory *sf, st64 n) {
	rz_return_val_if_fail(sf && sf->type == STRUCT_FACTORY_TYPE_ARRAY, false);

	RzStructFactory *value = struct_factory_new_signed(n);
	return struct_factory_array_add(sf, value);
}

RZ_API bool rz_struct_factory_array_add_double(RZ_NONNULL RzStructFactory *sf, double d) {
	rz_return_val_if_fail(sf && sf->type == STRUCT_FACTORY_TYPE_ARRAY, false);

	RzStructFactory *value = struct_factory_new_double(d);
	return struct_factory_array_add(sf, value);
}

RZ_API bool rz_struct_factory_array_add_boolean(RZ_NONNULL RzStructFactory *sf, bool b) {
	rz_return_val_if_fail(sf && sf->type == STRUCT_FACTORY_TYPE_ARRAY, false);

	RzStructFactory *value = struct_factory_new_bool(b);
	return struct_factory_array_add(sf, value);
}

RZ_API bool rz_struct_factory_array_add_string(RZ_NONNULL RzStructFactory *sf, RZ_NONNULL const char *s) {
	rz_return_val_if_fail(sf && sf->type == STRUCT_FACTORY_TYPE_ARRAY && s, false);

	char *copy = rz_str_dup(s);
	if (!copy) {
		return false;
	}

	RzStructFactory *value = struct_factory_new_string(copy);
	return struct_factory_array_add(sf, value);
}

static void struct_factory_iterate_over(StructFactoryIterOver *sfio, const RzStructFactory *sf);

static void struct_factory_iterate_over_map(StructFactoryIterOver *sfio, const RzStructFactory *sf) {
	void **pit = NULL;
	sfio->fit->new_struct(sfio->user, RZ_STRUCT_FACTORY_BLOCK_MAP);
	rz_pvector_foreach (sf->v_array, pit) {
		const char *key = *pit;
		const RzStructFactory *elem = (const RzStructFactory *)ht_sp_find(sf->v_map, key, NULL);
		sfio->fit->key(sfio->user, key);
		struct_factory_iterate_over(sfio, elem);
	}
	sfio->fit->end_struct(sfio->user);
}

static void struct_factory_iterate_over_array(StructFactoryIterOver *sfio, const RzStructFactory *sf) {
	void **pit = NULL;
	sfio->fit->new_struct(sfio->user, RZ_STRUCT_FACTORY_BLOCK_ARRAY);
	rz_pvector_foreach (sf->v_array, pit) {
		const RzStructFactory *elem = (const RzStructFactory *)*pit;
		struct_factory_iterate_over(sfio, elem);
	}
	sfio->fit->end_struct(sfio->user);
}

static void struct_factory_iterate_over(StructFactoryIterOver *sfio, const RzStructFactory *sf) {
	if (!sf) {
		return;
	}

	switch (sf->type) {
	case STRUCT_FACTORY_TYPE_MAP:
		struct_factory_iterate_over_map(sfio, sf);
		return;
	case STRUCT_FACTORY_TYPE_ARRAY:
		struct_factory_iterate_over_array(sfio, sf);
		return;
	case STRUCT_FACTORY_TYPE_HEXADECIMAL:
		sfio->fit->val_unsigned(sfio->user, sf->v_unsigned, true);
		return;
	case STRUCT_FACTORY_TYPE_UNSIGNED:
		sfio->fit->val_unsigned(sfio->user, sf->v_unsigned, false);
		return;
	case STRUCT_FACTORY_TYPE_SIGNED:
		sfio->fit->val_signed(sfio->user, sf->v_signed);
		return;
	case STRUCT_FACTORY_TYPE_DOUBLE:
		sfio->fit->val_double(sfio->user, sf->v_double);
		return;
	case STRUCT_FACTORY_TYPE_BOOL:
		sfio->fit->val_bool(sfio->user, sf->v_bool);
		return;
	case STRUCT_FACTORY_TYPE_STRING:
		sfio->fit->val_string(sfio->user, sf->v_string);
		return;
	default:
		rz_warn_if_reached();
		return;
	}
}

RZ_API void rz_struct_factory_iterate(RZ_NONNULL const RzStructFactory *sf, RZ_NONNULL const RzStructFactoryIterator *iterator, RZ_NULLABLE void *user) {
	rz_return_if_fail(sf && iterator && iterator);

	StructFactoryIterOver sfio = {
		.fit = iterator,
		.user = user,
	};

	struct_factory_iterate_over(&sfio, sf);
}

RZ_API RZ_OWN char *rz_struct_factory_to_json(RZ_NONNULL const RzStructFactory *sf) {
	rz_return_val_if_fail(sf, NULL);

	PJ *pj = pj_new();
	if (!pj) {
		return NULL;
	}

	rz_struct_factory_iterate(sf, &factory_iterator_json, pj);

	return pj_drain(pj);
}

RZ_API RZ_OWN char *rz_struct_factory_to_yaml(RZ_NONNULL const RzStructFactory *sf) {
	rz_return_val_if_fail(sf, NULL);
	StructYamlPrinter yaml = { 0 };

	memset(yaml.pad, ' ', sizeof(yaml.pad));

	rz_struct_factory_iterate(sf, &factory_iterator_yaml, &yaml);

	return rz_strbuf_drain_nofree(&yaml.sb);
}
