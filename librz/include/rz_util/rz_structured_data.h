// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_STRUCTURED_DATA_H
#define RZ_STRUCTURED_DATA_H

#include <rz_util/rz_strbuf.h>
#include <rz_util/rz_pj.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum rz_structured_data_block_t {
	RZ_STRUCTURED_DATA_BLOCK_MAP = 0,
	RZ_STRUCTURED_DATA_BLOCK_ARRAY = 1,
} RzStructuredDataBlock;

typedef enum rz_structured_data_format_t {
	RZ_STRUCTURED_DATA_FORMAT_DEFAULT = 0, ///< Bytes are printed as hexadecimal one after each other.
	RZ_STRUCTURED_DATA_FORMAT_COLON, ///< Bytes are printed as hexadecimal but separated by colons (`:`)
	RZ_STRUCTURED_DATA_FORMAT_HEXDUMP, ///< Bytes are printed as a hexdump (16 bytes per line)
	/// size
	RZ_STRUCTURED_DATA_FORMAT_ENUM_MAX
} RzStructuredDataFormat;

typedef struct rz_structured_data_t RzStructuredData;

typedef void (*RzStructuredDataIteratorNew)(RZ_NULLABLE void *user, RzStructuredDataBlock block, size_t n_elems);
typedef void (*RzStructuredDataIteratorEnd)(RZ_NULLABLE void *user);
typedef void (*RzStructuredDataIteratorKey)(RZ_NULLABLE void *user, RZ_NONNULL const char *key);
typedef void (*RzStructuredDataIteratorValueUnsigned)(RZ_NULLABLE void *user, ut64 n, bool hex);
typedef void (*RzStructuredDataIteratorValueSigned)(RZ_NULLABLE void *user, st64 n);
typedef void (*RzStructuredDataIteratorValueDouble)(RZ_NULLABLE void *user, double d);
typedef void (*RzStructuredDataIteratorValueBool)(RZ_NULLABLE void *user, bool b);
typedef void (*RzStructuredDataIteratorValueString)(RZ_NULLABLE void *user, RZ_NONNULL const char *v);

typedef struct rz_structured_data_iterator_t {
	RzStructuredDataIteratorNew new_struct; ///< Creates a new structure
	RzStructuredDataIteratorEnd end_struct; ///< Ends the current structure
	RzStructuredDataIteratorKey key; ///< Defines a key, called before a enter() or value_*()
	RzStructuredDataIteratorValueUnsigned val_unsigned; ///< Inserts a value of numeric unsigned type
	RzStructuredDataIteratorValueSigned val_signed; ///< Inserts a value of numeric signed type
	RzStructuredDataIteratorValueDouble val_double; ///< Inserts a value of numeric double type
	RzStructuredDataIteratorValueBool val_bool; ///< Inserts a value of boolean type
	RzStructuredDataIteratorValueString val_string; ///< Inserts a value of string type
} RzStructuredDataIterator;

RZ_API RZ_OWN RzStructuredData *rz_structured_data_new_map();
RZ_API RZ_OWN RzStructuredData *rz_structured_data_new_array();
RZ_API void rz_structured_data_free(RZ_NULLABLE RzStructuredData *sd);

/* primitive types for maps */
RZ_API RZ_BORROW RzStructuredData *rz_structured_data_map_add_map(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *key);
RZ_API RZ_BORROW RzStructuredData *rz_structured_data_map_add_array(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *key);
RZ_API bool rz_structured_data_map_add(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *key, RZ_NONNULL RZ_OWN RzStructuredData *child);
RZ_API bool rz_structured_data_map_add_unsigned(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *key, ut64 n, bool hex);
RZ_API bool rz_structured_data_map_add_signed(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *key, st64 n);
RZ_API bool rz_structured_data_map_add_double(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *key, double d);
RZ_API bool rz_structured_data_map_add_boolean(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *key, bool b);
RZ_API bool rz_structured_data_map_add_string(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *key, RZ_NONNULL const char *v);
RZ_API bool rz_structured_data_map_add_string_n(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *key, RZ_NONNULL const char *v, size_t v_size);
RZ_API bool rz_structured_data_map_add_bytes(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *key, RZ_NONNULL const ut8 *v, size_t v_size, RzStructuredDataFormat fmt);

/* primitive types for arrays */
RZ_API RZ_BORROW RzStructuredData *rz_structured_data_array_add_map(RZ_NONNULL RzStructuredData *parent);
RZ_API RZ_BORROW RzStructuredData *rz_structured_data_array_add_array(RZ_NONNULL RzStructuredData *parent);
RZ_API bool rz_structured_data_array_add(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL RZ_OWN RzStructuredData *child);
RZ_API bool rz_structured_data_array_add_unsigned(RZ_NONNULL RzStructuredData *parent, ut64 n, bool hex);
RZ_API bool rz_structured_data_array_add_signed(RZ_NONNULL RzStructuredData *parent, st64 n);
RZ_API bool rz_structured_data_array_add_double(RZ_NONNULL RzStructuredData *parent, double d);
RZ_API bool rz_structured_data_array_add_boolean(RZ_NONNULL RzStructuredData *parent, bool b);
RZ_API bool rz_structured_data_array_add_string(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *v);
RZ_API bool rz_structured_data_array_add_string_n(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const char *v, size_t v_size);
RZ_API bool rz_structured_data_array_add_bytes(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const ut8 *v, size_t v_size, RzStructuredDataFormat fmt);

RZ_API void rz_structured_data_iterate(RZ_NONNULL const RzStructuredData *sd, RZ_NONNULL const RzStructuredDataIterator *iterator, RZ_NULLABLE void *user);
RZ_API void rz_structured_data_to_pj(RZ_NONNULL const RzStructuredData *sd, RZ_NONNULL PJ *pj);
RZ_API RZ_OWN char *rz_structured_data_to_json(RZ_NONNULL const RzStructuredData *sd);
RZ_API RZ_OWN char *rz_structured_data_to_yaml(RZ_NONNULL const RzStructuredData *sd);

#ifdef __cplusplus
}
#endif

#endif /* RZ_STRUCTURED_DATA_H */
