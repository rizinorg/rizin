// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

/**
 * \file structured_data.c
 *
 * Generates a structured data which can be converted
 * in a human readable output (like json or yaml).
 *
 */

#include "structured_data_json.c"
#include "structured_data_yaml.c"

typedef enum {
	STRUCTURED_DATA_TYPE_MAP = 0,
	STRUCTURED_DATA_TYPE_ARRAY,
	STRUCTURED_DATA_TYPE_UNSIGNED,
	STRUCTURED_DATA_TYPE_HEXADECIMAL,
	STRUCTURED_DATA_TYPE_SIGNED,
	STRUCTURED_DATA_TYPE_DOUBLE,
	STRUCTURED_DATA_TYPE_BOOL,
	STRUCTURED_DATA_TYPE_STRING,
} StructuredDataType;

struct rz_structured_data_t {
	StructuredDataType type;
	union {
		ut64 v_unsigned;
		st64 v_signed;
		double v_double;
		bool v_bool;
		char *v_string;
		HtSP /*<RzStructuredData *>*/ *v_map;
	};
	RzPVector /*<void *>*/ *v_array; // used also to keep the map keys in order
};

typedef struct structured_data_iter_over_t {
	const RzStructuredDataIterator *fit;
	void *user;
} StructuredDataIterOver;

/**
 * \brief      Free a RzStructuredData pointer
 *
 * \param      sd    The RzStructuredData to free.
 */
RZ_API void rz_structured_data_free(RZ_NULLABLE RzStructuredData *sd) {
	if (!sd) {
		return;
	}

	if (sd->type == STRUCTURED_DATA_TYPE_MAP) {
		ht_sp_free(sd->v_map);
		rz_pvector_free(sd->v_array);
	} else if (sd->type == STRUCTURED_DATA_TYPE_ARRAY) {
		rz_pvector_free(sd->v_array);
	} else if (sd->type == STRUCTURED_DATA_TYPE_STRING) {
		free(sd->v_string);
	}
	free(sd);
}

static RzStructuredData *structured_data_new_map() {
	RzStructuredData *sd = RZ_NEW0(RzStructuredData);
	if (!sd) {
		return NULL;
	}
	sd->type = STRUCTURED_DATA_TYPE_MAP;
	sd->v_map = ht_sp_new(HT_STR_DUP, NULL, (HtSPFreeValue)rz_structured_data_free);
	sd->v_array = rz_pvector_new((RzPVectorFree)free);
	if (!sd->v_map || !sd->v_array) {
		rz_structured_data_free(sd);
		return NULL;
	}
	return sd;
}

static RzStructuredData *structured_data_new_array() {
	RzStructuredData *sd = RZ_NEW0(RzStructuredData);
	if (!sd) {
		return NULL;
	}
	sd->type = STRUCTURED_DATA_TYPE_ARRAY;
	sd->v_array = rz_pvector_new((RzPVectorFree)rz_structured_data_free);
	if (!sd->v_array) {
		free(sd);
		return NULL;
	}
	return sd;
}

static RzStructuredData *structured_data_new_unsigned(ut64 v_unsigned, bool hex) {
	RzStructuredData *sd = RZ_NEW0(RzStructuredData);
	if (!sd) {
		return NULL;
	}
	sd->type = hex ? STRUCTURED_DATA_TYPE_HEXADECIMAL : STRUCTURED_DATA_TYPE_UNSIGNED;
	sd->v_unsigned = v_unsigned;
	return sd;
}

static RzStructuredData *structured_data_new_signed(st64 v_signed) {
	RzStructuredData *sd = RZ_NEW0(RzStructuredData);
	if (!sd) {
		return NULL;
	}
	sd->type = STRUCTURED_DATA_TYPE_SIGNED;
	sd->v_signed = v_signed;
	return sd;
}

static RzStructuredData *structured_data_new_double(double v_double) {
	RzStructuredData *sd = RZ_NEW0(RzStructuredData);
	if (!sd) {
		return NULL;
	}
	sd->type = STRUCTURED_DATA_TYPE_DOUBLE;
	sd->v_double = v_double;
	return sd;
}

static RzStructuredData *structured_data_new_bool(bool v_bool) {
	RzStructuredData *sd = RZ_NEW0(RzStructuredData);
	if (!sd) {
		return NULL;
	}
	sd->type = STRUCTURED_DATA_TYPE_BOOL;
	sd->v_bool = v_bool;
	return sd;
}

static RzStructuredData *structured_data_new_string(char *v_string) {
	RzStructuredData *sd = RZ_NEW0(RzStructuredData);
	if (!sd) {
		return NULL;
	}
	sd->type = STRUCTURED_DATA_TYPE_STRING;
	sd->v_string = v_string;
	return sd;
}

static bool structured_data_map_add(RZ_NONNULL RzStructuredData *parent, const char *key, RZ_NONNULL RZ_OWN RzStructuredData *child) {
	RzPVector *pvec = parent->v_array;
	HtSP *map = parent->v_map;
	if (!map || !pvec || !child || RZ_STR_ISEMPTY(key)) {
		rz_structured_data_free(child);
		RZ_LOG_ERROR("struct_factory: invalid key: '%s'\n", key);
		return false;
	}

	bool found = false;
	ht_sp_find(map, key, &found);
	if (found) {
		rz_structured_data_free(child);
		RZ_LOG_ERROR("struct_factory: found duplicated key: '%s'\n", key);
		return false;
	}

	char *key_copy = rz_str_dup(key);
	if (!key_copy || !ht_sp_insert(map, key_copy, child)) {
		rz_structured_data_free(child);
		free(key_copy);
		RZ_LOG_ERROR("struct_factory: cannot add value with key: '%s'\n", key);
		return false;
	}

	return rz_pvector_push(pvec, key_copy);
}

static bool structured_data_array_add(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL RZ_OWN RzStructuredData *child) {
	RzPVector *pvec = parent->v_array;
	if (!pvec || !child) {
		RZ_LOG_ERROR("struct_factory: invalid array value\n");
		rz_structured_data_free(child);
		return false;
	}
	rz_pvector_push(pvec, child);
	return true;
}

static char *structured_data_hexdump_padded(const ut8 *buffer, const size_t length) {
	size_t i = 0, j = 0;
	char readable[20] = { 0 };
	RzStrBuf sb = { 0 };
	rz_strbuf_init(&sb);

	for (i = 0, j = 0; i < length; i++, j++) {
		const ut8 c = buffer[i];
		if (i > 0 && (i % 16) == 0) {
			rz_strbuf_appendf(&sb, "|%-16s|\n", readable);
			memset(readable, 0, sizeof(readable));
			j = 0;
		}
		rz_strbuf_appendf(&sb, "%02x ", c);
		readable[j] = IS_PRINTABLE(c) ? c : '.';
	}

	while ((i % 16) != 0) {
		rz_strbuf_append_n(&sb, "   ", 3);
		i++;
	}

	rz_strbuf_appendf(&sb, "|%-16s|", readable);
	return rz_strbuf_drain_nofree(&sb);
}

static char *structured_data_hex_colon_padded(const ut8 *buffer, size_t length) {
	const char *hex = "0123456789abcdef";
	const size_t size = 3 * length;
	char *output = malloc(size);
	if (!output) {
		return NULL;
	}

	for (size_t i = 0, j = 0; i < length && j < size; i++, j += 3) {
		const ut8 c = buffer[i];
		output[j + 0] = hex[c >> 4];
		output[j + 1] = hex[c & 0xf];
		output[j + 2] = ':';
	}

	// always overwrite the last byte with null char.
	output[size - 1] = '\0';
	return output;
}

static char *structured_data_bytes_to_string(const ut8 *buffer, const size_t length, RzStructuredDataFormat fmt) {
	if (length < 1) {
		return strdup("");
	}

	switch (fmt) {
	case RZ_STRUCTURED_DATA_FORMAT_COLON:
		return structured_data_hex_colon_padded(buffer, length);
	case RZ_STRUCTURED_DATA_FORMAT_HEXDUMP:
		return structured_data_hexdump_padded(buffer, length);
	default /* RZ_STRUCTURED_DATA_FORMAT_DEFAULT */:
		return rz_hex_bin2strdup(buffer, length);
	}
}

/**
 * \brief      Creates a new RzStructuredData initialized as a map
 *
 * \return     On success returns a valid opaque pointer to a RzStructuredData
 */
RZ_API RZ_OWN RzStructuredData *rz_structured_data_new_map() {
	return structured_data_new_map();
}

/**
 * \brief      Creates a new RzStructuredData initialized as an array
 *
 * \return     On success returns a valid opaque pointer to a RzStructuredData
 */
RZ_API RZ_OWN RzStructuredData *rz_structured_data_new_array() {
	return structured_data_new_array();
}

/**
 * \brief      Returns a child, map type, RzStructuredData that has been added to the given parent
 *
 * \param      parent  Where to add the child RzStructuredData
 * \param[in]  key     The key to assign the child RzStructuredData
 *
 * \return     On success returns a valid pointer to the child RzStructuredData, otherwise NULL
 */
RZ_API RZ_BORROW RzStructuredData *rz_structured_data_map_add_map(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *key) {
	rz_return_val_if_fail(parent && parent->type == STRUCTURED_DATA_TYPE_MAP && key, false);

	RzStructuredData *child = structured_data_new_map();
	if (!structured_data_map_add(parent, key, child)) {
		return NULL;
	}

	return child;
}

/**
 * \brief      Returns a child, array type, RzStructuredData that has been added to the given parent
 *
 * \param      parent  Where to add the child RzStructuredData
 * \param[in]  key     The key to assign the child RzStructuredData
 *
 * \return     On success returns a valid pointer to the child RzStructuredData, otherwise NULL
 */
RZ_API RZ_BORROW RzStructuredData *rz_structured_data_map_add_array(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *key) {
	rz_return_val_if_fail(parent && parent->type == STRUCTURED_DATA_TYPE_MAP && key, false);

	RzStructuredData *child = structured_data_new_array();
	if (!structured_data_map_add(parent, key, child)) {
		return NULL;
	}

	return child;
}

/**
 * \brief      Adds an owned RzStructuredData child to a parent and assigns it a map key
 *
 * \param      parent  Where to add the child RzStructuredData
 * \param[in]  key     The key to assign the child RzStructuredData
 * \param      child   The child RzStructuredData
 *
 * \return     On success returns true, otherwise the child gets deallocated by the function and return false.
 */
RZ_API bool rz_structured_data_map_add(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *key, RZ_NONNULL RZ_OWN RzStructuredData *child) {
	rz_return_val_if_fail(parent && parent->type == STRUCTURED_DATA_TYPE_MAP && key && child, false);

	return structured_data_map_add(parent, key, child);
}

/**
 * \brief      Adds unsigned type child to a parent and assigns it a map key
 *
 * \param      parent  Where to add the child RzStructuredData
 * \param[in]  key     The key to assign the child RzStructuredData
 * \param      n       The value to assign to the child
 * \param      hex     When true the type is going to be set as base16 number instead of base10 unsigned number.
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_structured_data_map_add_unsigned(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *key, ut64 n, bool hex) {
	rz_return_val_if_fail(parent && parent->type == STRUCTURED_DATA_TYPE_MAP && key, false);

	RzStructuredData *child = structured_data_new_unsigned(n, hex);
	return structured_data_map_add(parent, key, child);
}

/**
 * \brief      Adds signed type child to a parent and assigns it a map key
 *
 * \param      parent  Where to add the child RzStructuredData
 * \param[in]  key     The key to assign the child RzStructuredData
 * \param      n       The value to assign to the child
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_structured_data_map_add_signed(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *key, st64 n) {
	rz_return_val_if_fail(parent && parent->type == STRUCTURED_DATA_TYPE_MAP && key, false);

	RzStructuredData *child = structured_data_new_signed(n);
	return structured_data_map_add(parent, key, child);
}

/**
 * \brief      Adds double type child to a parent and assigns it a map key
 *
 * \param      parent  Where to add the child RzStructuredData
 * \param[in]  key     The key to assign the child RzStructuredData
 * \param      d       The value to assign to the child
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_structured_data_map_add_double(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *key, double d) {
	rz_return_val_if_fail(parent && parent->type == STRUCTURED_DATA_TYPE_MAP && key, false);

	RzStructuredData *child = structured_data_new_double(d);
	return structured_data_map_add(parent, key, child);
}

/**
 * \brief      Adds boolean type child to a parent and assigns it a map key
 *
 * \param      parent  Where to add the child RzStructuredData
 * \param[in]  key     The key to assign the child RzStructuredData
 * \param      b       The value to assign to the child
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_structured_data_map_add_boolean(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *key, bool b) {
	rz_return_val_if_fail(parent && parent->type == STRUCTURED_DATA_TYPE_MAP && key, false);

	RzStructuredData *child = structured_data_new_bool(b);
	return structured_data_map_add(parent, key, child);
}

/**
 * \brief      Adds a null terminated string type child to a parent and assigns it a map key
 *
 * \param      parent  Where to add the child RzStructuredData
 * \param[in]  key     The key to assign the child RzStructuredData
 * \param      s       The value to assign to the child
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_structured_data_map_add_string(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *key, RZ_NONNULL const char *s) {
	rz_return_val_if_fail(parent && parent->type == STRUCTURED_DATA_TYPE_MAP && key && s, false);

	char *copy = rz_str_dup(s);
	if (!copy) {
		return false;
	}

	RzStructuredData *child = structured_data_new_string(copy);
	return structured_data_map_add(parent, key, child);
}

/**
 * \brief      Adds a null terminated string type child (with a max size of n) to a parent and assigns it a map key
 *
 * \param      parent  Where to add the child RzStructuredData
 * \param[in]  key     The key to assign the child RzStructuredData
 * \param      s       The string value to assign to the child
 * \param      s_len   The max size of the string value
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_structured_data_map_add_string_n(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *key, RZ_NONNULL const char *s, size_t s_len) {
	rz_return_val_if_fail(parent && parent->type == STRUCTURED_DATA_TYPE_MAP && key && s, false);

	char *copy = rz_str_ndup(s, s_len);
	if (!copy) {
		return false;
	}

	RzStructuredData *child = structured_data_new_string(copy);
	return structured_data_map_add(parent, key, child);
}

/**
 * \brief      Generates a hexdump of the bytes and assignes the string type child to a map parent
 *
 * \param      parent  Where to add the child RzStructuredData
 * \param[in]  key     The key to assign the child RzStructuredData
 * \param      v       The bytes value to hexdump and assign to the child
 * \param      v_size  The max size of the bytes value
 * \param      fmt     The format to use when dumping the bytes
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_structured_data_map_add_bytes(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *key, RZ_NONNULL const ut8 *v, size_t v_size, RzStructuredDataFormat fmt) {
	rz_return_val_if_fail(parent && parent->type == STRUCTURED_DATA_TYPE_MAP && key && v && fmt < RZ_STRUCTURED_DATA_FORMAT_ENUM_MAX, false);

	char *copy = structured_data_bytes_to_string(v, v_size, fmt);
	if (!copy) {
		return false;
	}

	RzStructuredData *child = structured_data_new_string(copy);
	return structured_data_map_add(parent, key, child);
}

/**
 * \brief      Returns a child, map type, RzStructuredData that has been added to the given parent
 *
 * \param      parent  Where to add the child RzStructuredData
 *
 * \return     On success returns a valid pointer to the child RzStructuredData, otherwise NULL
 */
RZ_API RZ_BORROW RzStructuredData *rz_structured_data_array_add_map(RZ_NONNULL RzStructuredData *parent) {
	rz_return_val_if_fail(parent && parent->type == STRUCTURED_DATA_TYPE_ARRAY, false);

	RzStructuredData *child = structured_data_new_map();
	if (!structured_data_array_add(parent, child)) {
		return NULL;
	}

	return child;
}

/**
 * \brief      Returns a child, array type, RzStructuredData that has been added to the given parent
 *
 * \param      parent  Where to add the child RzStructuredData
 *
 * \return     On success returns a valid pointer to the child RzStructuredData, otherwise NULL
 */
RZ_API RZ_BORROW RzStructuredData *rz_structured_data_array_add_array(RZ_NONNULL RzStructuredData *parent) {
	rz_return_val_if_fail(parent && parent->type == STRUCTURED_DATA_TYPE_ARRAY, false);

	RzStructuredData *child = structured_data_new_array();
	if (!structured_data_array_add(parent, child)) {
		return NULL;
	}

	return child;
}

/**
 * \brief      Adds an owned RzStructuredData child to an array type parent
 *
 * \param      parent  Where to add the child RzStructuredData
 * \param      child   The child RzStructuredData
 *
 * \return     On success returns true, otherwise the child gets deallocated by the function and return false.
 */
RZ_API bool rz_structured_data_array_add(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL RZ_OWN RzStructuredData *child) {
	rz_return_val_if_fail(parent && parent->type == STRUCTURED_DATA_TYPE_ARRAY && child, false);

	return structured_data_array_add(parent, child);
}

/**
 * \brief      Adds unsigned type child to an array type parent
 *
 * \param      parent  Where to add the child RzStructuredData
 * \param      n       The value to assign to the child
 * \param      hex     When true the type is going to be set as base16 number instead of base10 unsigned number.
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_structured_data_array_add_unsigned(RZ_NONNULL RzStructuredData *parent, ut64 n, bool hex) {
	rz_return_val_if_fail(parent && parent->type == STRUCTURED_DATA_TYPE_ARRAY, false);

	RzStructuredData *child = structured_data_new_unsigned(n, hex);
	return structured_data_array_add(parent, child);
}

/**
 * \brief      Adds signed type child to an array type parent
 *
 * \param      parent  Where to add the child RzStructuredData
 * \param      n       The value to assign to the child
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_structured_data_array_add_signed(RZ_NONNULL RzStructuredData *parent, st64 n) {
	rz_return_val_if_fail(parent && parent->type == STRUCTURED_DATA_TYPE_ARRAY, false);

	RzStructuredData *child = structured_data_new_signed(n);
	return structured_data_array_add(parent, child);
}

/**
 * \brief      Adds double type child to an array type parent
 *
 * \param      parent  Where to add the child RzStructuredData
 * \param      n       The value to assign to the child
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_structured_data_array_add_double(RZ_NONNULL RzStructuredData *parent, double d) {
	rz_return_val_if_fail(parent && parent->type == STRUCTURED_DATA_TYPE_ARRAY, false);

	RzStructuredData *child = structured_data_new_double(d);
	return structured_data_array_add(parent, child);
}

/**
 * \brief      Adds signed type child to an array type parent
 *
 * \param      parent  Where to add the child RzStructuredData
 * \param      n       The value to assign to the child
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_structured_data_array_add_boolean(RZ_NONNULL RzStructuredData *parent, bool b) {
	rz_return_val_if_fail(parent && parent->type == STRUCTURED_DATA_TYPE_ARRAY, false);

	RzStructuredData *child = structured_data_new_bool(b);
	return structured_data_array_add(parent, child);
}

/**
 * \brief      Adds a null terminated string type child to an array type parent
 *
 * \param      parent  Where to add the child RzStructuredData
 * \param      s       The string value to assign to the child
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_structured_data_array_add_string(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *s) {
	rz_return_val_if_fail(parent && parent->type == STRUCTURED_DATA_TYPE_ARRAY && s, false);

	char *copy = rz_str_dup(s);
	if (!copy) {
		return false;
	}

	RzStructuredData *child = structured_data_new_string(copy);
	return structured_data_array_add(parent, child);
}

/**
 * \brief      Adds a null terminated string type child (with a max size of n) to an array type parent
 *
 * \param      parent  Where to add the child RzStructuredData
 * \param      s       The string value to assign to the child
 * \param      s_len   The size of the string value
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_structured_data_array_add_string_n(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *s, size_t s_len) {
	rz_return_val_if_fail(parent && parent->type == STRUCTURED_DATA_TYPE_ARRAY && s, false);

	char *copy = rz_str_ndup(s, s_len);
	if (!copy) {
		return false;
	}

	RzStructuredData *child = structured_data_new_string(copy);
	return structured_data_array_add(parent, child);
}

/**
 * \brief      Generates a hexdump of the bytes and assignes the string type child to an array type parent
 *
 * \param      parent  Where to add the child RzStructuredData
 * \param      v       The bytes value to hexdump and assign to the child
 * \param      v_size  The max size of the bytes value
 * \param      fmt     The format to use when dumping the bytes
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_structured_data_array_add_bytes(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const ut8 *v, size_t v_size, RzStructuredDataFormat fmt) {
	rz_return_val_if_fail(parent && parent->type == STRUCTURED_DATA_TYPE_ARRAY && v && fmt < RZ_STRUCTURED_DATA_FORMAT_ENUM_MAX, false);

	char *copy = structured_data_bytes_to_string(v, v_size, fmt);
	if (!copy) {
		return false;
	}

	RzStructuredData *child = structured_data_new_string(copy);
	return structured_data_array_add(parent, child);
}

static void structured_data_iterate_over(StructuredDataIterOver *sdio, const RzStructuredData *sd);

static void structured_data_iterate_over_map(StructuredDataIterOver *sdio, const RzStructuredData *sd) {
	void **pit = NULL;
	size_t n_keys = rz_pvector_len(sd->v_array);
	sdio->fit->new_struct(sdio->user, RZ_STRUCTURED_DATA_BLOCK_MAP, n_keys);
	rz_pvector_foreach (sd->v_array, pit) {
		const char *key = *pit;
		const RzStructuredData *elem = (const RzStructuredData *)ht_sp_find(sd->v_map, key, NULL);
		sdio->fit->key(sdio->user, key);
		structured_data_iterate_over(sdio, elem);
	}
	sdio->fit->end_struct(sdio->user);
}

static void structured_data_iterate_over_array(StructuredDataIterOver *sdio, const RzStructuredData *sd) {
	void **pit = NULL;
	size_t array_len = rz_pvector_len(sd->v_array);
	sdio->fit->new_struct(sdio->user, RZ_STRUCTURED_DATA_BLOCK_ARRAY, array_len);
	rz_pvector_foreach (sd->v_array, pit) {
		const RzStructuredData *elem = (const RzStructuredData *)*pit;
		structured_data_iterate_over(sdio, elem);
	}
	sdio->fit->end_struct(sdio->user);
}

static void structured_data_iterate_over(StructuredDataIterOver *sdio, const RzStructuredData *sd) {
	if (!sd) {
		return;
	}

	switch (sd->type) {
	case STRUCTURED_DATA_TYPE_MAP:
		structured_data_iterate_over_map(sdio, sd);
		return;
	case STRUCTURED_DATA_TYPE_ARRAY:
		structured_data_iterate_over_array(sdio, sd);
		return;
	case STRUCTURED_DATA_TYPE_HEXADECIMAL:
		sdio->fit->val_unsigned(sdio->user, sd->v_unsigned, true);
		return;
	case STRUCTURED_DATA_TYPE_UNSIGNED:
		sdio->fit->val_unsigned(sdio->user, sd->v_unsigned, false);
		return;
	case STRUCTURED_DATA_TYPE_SIGNED:
		sdio->fit->val_signed(sdio->user, sd->v_signed);
		return;
	case STRUCTURED_DATA_TYPE_DOUBLE:
		sdio->fit->val_double(sdio->user, sd->v_double);
		return;
	case STRUCTURED_DATA_TYPE_BOOL:
		sdio->fit->val_bool(sdio->user, sd->v_bool);
		return;
	case STRUCTURED_DATA_TYPE_STRING:
		sdio->fit->val_string(sdio->user, sd->v_string);
		return;
	default:
		rz_warn_if_reached();
		return;
	}
}

/**
 * \brief      Iterates over a given RzStructuredData using the provided iterator
 *
 * \param[in]  sd        The RzStructuredData to iterate over
 * \param[in]  iterator  The iterator to use
 * \param      user      The user ponter (can be null)
 */
RZ_API void rz_structured_data_iterate(RZ_NONNULL const RzStructuredData *sd, RZ_NONNULL const RzStructuredDataIterator *iterator, RZ_NULLABLE void *user) {
	rz_return_if_fail(sd && iterator && iterator);

	StructuredDataIterOver sdio = {
		.fit = iterator,
		.user = user,
	};

	structured_data_iterate_over(&sdio, sd);
}

/**
 * \brief      Iterates over a given RzStructuredData and generates a json string
 *
 * \param[in]  sd  The RzStructuredData to iterate over
 * \param[in]  pj  The PJ to write into
 */
RZ_API void rz_structured_data_to_pj(RZ_NONNULL const RzStructuredData *sd, RZ_NONNULL PJ *pj) {
	rz_return_if_fail(sd && pj);

	rz_structured_data_iterate(sd, &builder_json_iterator, pj);
}

/**
 * \brief      Iterates over a given RzStructuredData and generates a json string
 *
 * \param[in]  sd  The RzStructuredData to iterate over
 */
RZ_API RZ_OWN char *rz_structured_data_to_json(RZ_NONNULL const RzStructuredData *sd) {
	rz_return_val_if_fail(sd, NULL);

	PJ *pj = pj_new();
	if (!pj) {
		return NULL;
	}

	rz_structured_data_iterate(sd, &builder_json_iterator, pj);

	return pj_drain(pj);
}

/**
 * \brief      Iterates over a given RzStructuredData and generates a yaml string
 *
 * \param[in]  sd  The RzStructuredData to iterate over
 */
RZ_API RZ_OWN char *rz_structured_data_to_yaml(RZ_NONNULL const RzStructuredData *sd) {
	rz_return_val_if_fail(sd, NULL);
	StructYamlPrinter yaml = { 0 };

	builder_yaml_init_printer(&yaml);

	rz_structured_data_iterate(sd, &builder_yaml_iterator, &yaml);

	return builder_yaml_fini_printer(&yaml);
}
