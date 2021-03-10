// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BIN_JAVA_CLASS_H
#define RZ_BIN_JAVA_CLASS_H
#include <rz_types.h>
#include <rz_util.h>
#include <rz_bin.h>

#include "class_attribute.h"
#include "class_const_pool.h"
#include "class_field.h"
#include "class_interface.h"
#include "class_method.h"

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

#define ACCESS_FLAG_MASK_ALL (0xFFFF)

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

RZ_API RzBinJavaClass *rz_bin_java_class_new(RzBuffer *buf, ut64 offset, Sdb *kv);
RZ_API void rz_bin_java_class_free(RzBinJavaClass *bin);

RZ_API char *rz_bin_java_class_version(RzBinJavaClass *bin);
RZ_API ut64 rz_bin_java_class_debug_info(RzBinJavaClass *bin);
RZ_API const char *rz_bin_java_class_language(RzBinJavaClass *bin);
RZ_API char *rz_bin_java_class_name(RzBinJavaClass *bin);
RZ_API char *rz_bin_java_class_super(RzBinJavaClass *bin);
RZ_API ut32 rz_bin_java_class_access_flags(RzBinJavaClass *bin);
RZ_API char *rz_bin_java_class_access_flags_readable(RzBinJavaClass *bin, ut16 mask);
RZ_API void rz_bin_java_class_as_json(RzBinJavaClass *bin, PJ *j);
RZ_API void rz_bin_java_class_as_text(RzBinJavaClass *bin, RzStrBuf *sb);

/* used in bin_java.c and core_java.c */
RZ_API void rz_bin_java_class_as_source_code(RzBinJavaClass *bin, RzStrBuf *sb);
RZ_API RzBinAddr *rz_bin_java_class_resolve_symbol(RzBinJavaClass *bin, int resolve);
RZ_API RzList *rz_bin_java_class_strings(RzBinJavaClass *bin);
RZ_API RzList *rz_bin_java_class_entrypoints(RzBinJavaClass *bin);
RZ_API RzList *rz_bin_java_class_methods_as_symbols(RzBinJavaClass *bin);
RZ_API void rz_bin_java_class_methods_as_text(RzBinJavaClass *bin, RzStrBuf *sb);
RZ_API void rz_bin_java_class_methods_as_json(RzBinJavaClass *bin, PJ *j);
RZ_API RzList *rz_bin_java_class_fields_as_symbols(RzBinJavaClass *bin);
RZ_API RzList *rz_bin_java_class_fields_as_binfields(RzBinJavaClass *bin);
RZ_API void rz_bin_java_class_fields_as_text(RzBinJavaClass *bin, RzStrBuf *sb);
RZ_API void rz_bin_java_class_fields_as_json(RzBinJavaClass *bin, PJ *j);
RZ_API RzList *rz_bin_java_class_const_pool_as_symbols(RzBinJavaClass *bin);
RZ_API RzList *rz_bin_java_class_const_pool_as_imports(RzBinJavaClass *bin);
RZ_API void rz_bin_java_class_const_pool_as_text(RzBinJavaClass *bin, RzStrBuf *sb);
RZ_API void rz_bin_java_class_const_pool_as_json(RzBinJavaClass *bin, PJ *j);
RZ_API RzList *rz_bin_java_class_as_sections(RzBinJavaClass *bin);
RZ_API RzList *rz_bin_java_class_as_libraries(RzBinJavaClass *bin);
RZ_API void rz_bin_java_class_interfaces_as_text(RzBinJavaClass *bin, RzStrBuf *sb);
RZ_API void rz_bin_java_class_interfaces_as_json(RzBinJavaClass *bin, PJ *j);

#endif /* RZ_BIN_JAVA_CLASS_H */
