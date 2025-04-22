// SPDX-FileCopyrightText: 2021-2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021-2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BIN_JAVA_CLASS_H
#define RZ_BIN_JAVA_CLASS_H
#include <rz_types.h>
#include <rz_util.h>
#include <rz_bin.h>
#include <rz_demangler.h>

#include "class_attribute.h"
#include "class_const_pool.h"
#include "class_field.h"
#include "class_interface.h"
#include "class_method.h"
#include "rz_vector.h"

typedef enum {
	ACCESS_FLAG_PUBLIC /*    */ = 0x0001,
	ACCESS_FLAG_PRIVATE /*   */ = 0x0002,
	ACCESS_FLAG_PROTECTED /* */ = 0x0004,
	ACCESS_FLAG_STATIC /*    */ = 0x0008,
	ACCESS_FLAG_FINAL /*     */ = 0x0010,
	ACCESS_FLAG_SUPER /*     */ = 0x0020,
	ACCESS_FLAG_BRIDGE /*    */ = 0x0040,
	ACCESS_FLAG_VARARGS /*   */ = 0x0080,
	ACCESS_FLAG_NATIVE /*    */ = 0x0100,
	ACCESS_FLAG_INTERFACE /* */ = 0x0200,
	ACCESS_FLAG_ABSTRACT /*  */ = 0x0400,
	ACCESS_FLAG_STRICT /*    */ = 0x0800,
	ACCESS_FLAG_SYNTHETIC /* */ = 0x1000,
	ACCESS_FLAG_ANNOTATION /**/ = 0x2000,
	ACCESS_FLAG_ENUM /*      */ = 0x4000,
	ACCESS_FLAG_MODULE /*    */ = 0x8000
} ClassAccessFlag;

#define ACCESS_FLAG_MASK_ALL          (0xFFFF)
#define ACCESS_FLAG_MASK_ALL_NO_SUPER ((~ACCESS_FLAG_SUPER) & ACCESS_FLAG_MASK_ALL)

typedef struct java_class_t {
	ut32 magic;
	ut16 minor_version;
	ut16 major_version;
	ut16 constant_pool_count;
	ConstPool **constant_pool;
	ut16 access_flags;
	ut16 this_class;
	ut16 super_class;
	ut16 interfaces_count;
	Interface **interfaces;
	ut16 fields_count;
	Field **fields;
	ut16 methods_count;
	Method **methods;
	ut16 attributes_count;
	Attribute **attributes;

	/* extra data not included in the real header */
	ut64 constant_pool_offset;
	ut64 interfaces_offset;
	ut64 fields_offset;
	ut64 methods_offset;
	ut64 attributes_offset;
	ut64 class_end_offset;
} RzBinJavaClass;

RZ_API RZ_OWN RzBinJavaClass *rz_bin_java_class_new(RZ_NONNULL RzBuffer *buf, ut64 offset, RZ_NONNULL Sdb *kv);
RZ_API void rz_bin_java_class_free(RZ_NULLABLE RzBinJavaClass *bin);

RZ_API RZ_OWN char *rz_bin_java_class_version(RZ_NONNULL RzBinJavaClass *bin);
RZ_API ut64 rz_bin_java_class_debug_info(RZ_NONNULL RzBinJavaClass *bin);
RZ_API RZ_BORROW const char *rz_bin_java_class_language(RZ_NONNULL RzBinJavaClass *bin);
RZ_API RZ_OWN char *rz_bin_java_class_name(RZ_NONNULL RzBinJavaClass *bin);
RZ_API RZ_OWN char *rz_bin_java_class_super(RZ_NONNULL RzBinJavaClass *bin);
RZ_API ut32 rz_bin_java_class_access_flags(RZ_NONNULL RzBinJavaClass *bin);
RZ_API RZ_OWN char *rz_bin_java_class_access_flags_readable(RZ_NONNULL RzBinJavaClass *bin, ut16 mask);
RZ_API void rz_bin_java_class_as_json(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL PJ *j);
RZ_API void rz_bin_java_class_as_text(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL RzStrBuf *sb);
RZ_API RZ_OWN char *rz_bin_java_class_const_pool_resolve_index(RZ_NONNULL RzBinJavaClass *bin, st32 index);

/* used in bin_java.c and core_java.c */
RZ_API void rz_bin_java_class_as_source_code(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL RzStrBuf *sb);
RZ_API RZ_OWN RzBinAddr *rz_bin_java_class_resolve_symbol(RZ_NONNULL RzBinJavaClass *bin, RzBinSpecialSymbol resolve);
RZ_API RZ_OWN RzPVector /*<RzBinString *>*/ *rz_bin_java_class_strings(RZ_NONNULL RzBinJavaClass *bin);
RZ_API RZ_OWN RzPVector /*<RzBinAddr *>*/ *rz_bin_java_class_entrypoints(RZ_NONNULL RzBinJavaClass *bin);
RZ_API RZ_OWN RzList /*<RzBinSymbol *>*/ *rz_bin_java_class_methods_as_symbols(RZ_NONNULL RzBinJavaClass *bin);
RZ_API void rz_bin_java_class_methods_as_text(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL RzStrBuf *sb);
RZ_API void rz_bin_java_class_methods_as_json(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL PJ *j);
RZ_API RZ_OWN RzList /*<RzBinSymbol *>*/ *rz_bin_java_class_fields_as_symbols(RZ_NONNULL RzBinJavaClass *bin);
RZ_API RZ_OWN RzList /*<RzBinClassField *>*/ *rz_bin_java_class_fields_as_binfields(RZ_NONNULL RzBinJavaClass *bin);
RZ_API void rz_bin_java_class_fields_as_text(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL RzStrBuf *sb);
RZ_API void rz_bin_java_class_fields_as_json(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL PJ *j);
RZ_API RZ_OWN RzList /*<RzBinSymbol *>*/ *rz_bin_java_class_const_pool_as_symbols(RZ_NONNULL RzBinJavaClass *bin);
RZ_API RZ_OWN RzPVector /*<RzBinImport *>*/ *rz_bin_java_class_const_pool_as_imports(RZ_NONNULL RzBinJavaClass *bin);
RZ_API void rz_bin_java_class_const_pool_as_text(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL RzStrBuf *sb);
RZ_API void rz_bin_java_class_const_pool_as_json(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL PJ *j);
RZ_API RZ_OWN RzPVector /*<RzBinSection *>*/ *rz_bin_java_class_as_sections(RZ_NONNULL RzBinJavaClass *bin);
RZ_API RZ_OWN RzPVector /*<char *>*/ *rz_bin_java_class_as_libraries(RZ_NONNULL RzBinJavaClass *bin);
RZ_API void rz_bin_java_class_interfaces_as_text(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL RzStrBuf *sb);
RZ_API void rz_bin_java_class_interfaces_as_json(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL PJ *j);
RZ_API RZ_OWN RzPVector /*<RzBinClass *>*/ *rz_bin_java_class_as_classes(RZ_NONNULL RzBinJavaClass *bin);

#endif /* RZ_BIN_JAVA_CLASS_H */
