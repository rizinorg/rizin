// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_STRUCT_FACTORY_H
#define RZ_STRUCT_FACTORY_H

#include <rz_util/rz_strbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum rz_struct_factory_block_t {
	RZ_STRUCT_FACTORY_BLOCK_MAP = 0,
	RZ_STRUCT_FACTORY_BLOCK_ARRAY = 1,
} RzStructFactoryBlock;

typedef struct rz_struct_factory_t RzStructFactory;

typedef void (*RzStructFactoryIteratorNew)(RZ_NULLABLE void *user, RzStructFactoryBlock block);
typedef void (*RzStructFactoryIteratorEnd)(RZ_NULLABLE void *user);
typedef void (*RzStructFactoryIteratorKey)(RZ_NULLABLE void *user, RZ_NONNULL const char *key);
typedef void (*RzStructFactoryIteratorValueUnsigned)(RZ_NULLABLE void *user, ut64 n);
typedef void (*RzStructFactoryIteratorValueSigned)(RZ_NULLABLE void *user, st64 n);
typedef void (*RzStructFactoryIteratorValueDouble)(RZ_NULLABLE void *user, double d);
typedef void (*RzStructFactoryIteratorValueBool)(RZ_NULLABLE void *user, bool b);
typedef void (*RzStructFactoryIteratorValueString)(RZ_NULLABLE void *user, RZ_NONNULL const char *v);

typedef struct rz_struct_factory_iterator_t {
	RzStructFactoryIteratorNew new_struct; ///< Creates a new structure
	RzStructFactoryIteratorEnd end_struct; ///< Ends the current structure
	RzStructFactoryIteratorKey key; ///< Defines a key, called before a enter() or value_*()
	RzStructFactoryIteratorValueUnsigned val_unsigned; ///< Inserts a value of numeric unsigned type
	RzStructFactoryIteratorValueSigned val_signed; ///< Inserts a value of numeric signed type
	RzStructFactoryIteratorValueDouble val_double; ///< Inserts a value of numeric double type
	RzStructFactoryIteratorValueBool val_bool; ///< Inserts a value of boolean type
	RzStructFactoryIteratorValueString val_string; ///< Inserts a value of string type
} RzStructFactoryIterator;

RZ_API RZ_OWN RzStructFactory *rz_struct_factory_new_map();
RZ_API RZ_OWN RzStructFactory *rz_struct_factory_new_array();
RZ_API void rz_struct_factory_free(RZ_NULLABLE RzStructFactory *sf);

/* primitive types for maps */
RZ_API RZ_BORROW RzStructFactory *rz_struct_factory_map_add_map(RZ_NONNULL RzStructFactory *sf, RZ_NONNULL const char *key);
RZ_API RZ_BORROW RzStructFactory *rz_struct_factory_map_add_array(RZ_NONNULL RzStructFactory *sf, RZ_NONNULL const char *key);
RZ_API bool rz_struct_factory_map_add_unsigned(RZ_NONNULL RzStructFactory *sf, RZ_NONNULL const char *key, ut64 n);
RZ_API bool rz_struct_factory_map_add_signed(RZ_NONNULL RzStructFactory *sf, RZ_NONNULL const char *key, st64 n);
RZ_API bool rz_struct_factory_map_add_double(RZ_NONNULL RzStructFactory *sf, RZ_NONNULL const char *key, double d);
RZ_API bool rz_struct_factory_map_add_bool(RZ_NONNULL RzStructFactory *sf, RZ_NONNULL const char *key, bool b);
RZ_API bool rz_struct_factory_map_add_string(RZ_NONNULL RzStructFactory *sf, RZ_NONNULL const char *key, RZ_NONNULL const char *v);

/* primitive types for arrays */
RZ_API RZ_BORROW RzStructFactory *rz_struct_factory_array_add_map(RZ_NONNULL RzStructFactory *sf);
RZ_API RZ_BORROW RzStructFactory *rz_struct_factory_array_add_array(RZ_NONNULL RzStructFactory *sf);
RZ_API bool rz_struct_factory_array_add_unsigned(RZ_NONNULL RzStructFactory *sf, ut64 n);
RZ_API bool rz_struct_factory_array_add_signed(RZ_NONNULL RzStructFactory *sf, st64 n);
RZ_API bool rz_struct_factory_array_add_double(RZ_NONNULL RzStructFactory *sf, double d);
RZ_API bool rz_struct_factory_array_add_bool(RZ_NONNULL RzStructFactory *sf, bool b);
RZ_API bool rz_struct_factory_array_add_string(RZ_NONNULL RzStructFactory *sf, RZ_NONNULL const char *v);

RZ_API void rz_struct_factory_iterate(RZ_NONNULL const RzStructFactory *sf, RZ_NONNULL const RzStructFactoryIterator *iterator, RZ_NULLABLE void *user);
RZ_API RZ_OWN char *rz_struct_factory_to_json(RZ_NONNULL const RzStructFactory *sf);
RZ_API RZ_OWN char *rz_struct_factory_to_yaml(RZ_NONNULL const RzStructFactory *sf);

#ifdef __cplusplus
}
#endif

#endif /* RZ_STRUCT_FACTORY_H */
