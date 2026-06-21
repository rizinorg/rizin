// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BIN_JAVA_CLASS_ATTRIBUTE_H
#define RZ_BIN_JAVA_CLASS_ATTRIBUTE_H
#include <rz_types.h>
#include <rz_util.h>
#include <rz_bin.h>
#include "class_exceptions.h"
#include "class_line_number.h"
#include "class_local_variable.h"
#include "class_module.h"
#include "class_const_pool.h"

typedef enum {
	ATTRIBUTE_TYPE_INVALID = 0,
	ATTRIBUTE_TYPE_UNKNOWN, // will be used only when parsing an unknown attribute

	ATTRIBUTE_TYPE_CONSTANTVALUE, /*                        Java SE 1.0.2 */
	ATTRIBUTE_TYPE_CODE, /*                                 Java SE 1.0.2 */
	ATTRIBUTE_TYPE_STACKMAPTABLE, /*                        Java SE 6 */
	ATTRIBUTE_TYPE_EXCEPTIONS, /*                           Java SE 1.0.2 */
	ATTRIBUTE_TYPE_INNERCLASSES, /*                         Java SE 1.1 */
	ATTRIBUTE_TYPE_ENCLOSINGMETHOD, /*                      Java SE 5.0 */
	ATTRIBUTE_TYPE_SYNTHETIC, /*                            Java SE 1.1 */
	ATTRIBUTE_TYPE_SIGNATURE, /*                            Java SE 5.0 */
	ATTRIBUTE_TYPE_SOURCEFILE, /*                           Java SE 1.0.2 */
	ATTRIBUTE_TYPE_SOURCEDEBUGEXTENSION, /*                 Java SE 5.0 */
	ATTRIBUTE_TYPE_LINENUMBERTABLE, /*                      Java SE 1.0.2 */
	ATTRIBUTE_TYPE_LOCALVARIABLETABLE, /*                   Java SE 1.0.2 */
	ATTRIBUTE_TYPE_LOCALVARIABLETYPETABLE, /*               Java SE 5.0 */
	ATTRIBUTE_TYPE_DEPRECATED, /*                           Java SE 1.1 */
	ATTRIBUTE_TYPE_RUNTIMEVISIBLEANNOTATIONS, /*            Java SE 5.0 */
	ATTRIBUTE_TYPE_RUNTIMEINVISIBLEANNOTATIONS, /*          Java SE 5.0 */
	ATTRIBUTE_TYPE_RUNTIMEVISIBLEPARAMETERANNOTATIONS, /*   Java SE 5.0 */
	ATTRIBUTE_TYPE_RUNTIMEINVISIBLEPARAMETERANNOTATIONS, /* Java SE 5.0 */
	ATTRIBUTE_TYPE_RUNTIMEVISIBLETYPEANNOTATIONS, /*        Java SE 8 */
	ATTRIBUTE_TYPE_RUNTIMEINVISIBLETYPEANNOTATIONS, /*      Java SE 8 */
	ATTRIBUTE_TYPE_ANNOTATIONDEFAULT, /*                    Java SE 5.0 */
	ATTRIBUTE_TYPE_BOOTSTRAPMETHODS, /*                     Java SE 7 */
	ATTRIBUTE_TYPE_METHODPARAMETERS, /*                     Java SE 8 */
	ATTRIBUTE_TYPE_MODULE, /*                               Java SE 9 */
	ATTRIBUTE_TYPE_MODULEPACKAGES, /*                       Java SE 9 */
	ATTRIBUTE_TYPE_MODULEMAINCLASS, /*                      Java SE 9 */
	ATTRIBUTE_TYPE_NESTHOST, /*                             Java SE 11 */
	ATTRIBUTE_TYPE_NESTMEMBERS /*                           Java SE 11 */
} AttributeType;

typedef struct java_attribute_t {
	ut64 offset;
	AttributeType type;
	ut16 attribute_name_index;
	ut32 attribute_length;
	void *info;
} Attribute;

typedef struct java_attribute_constant_value_t {
	/*
	 * Must be pointing to one of these types:
	 * CONSTANT_POOL_INTEGER: int, short, char, byte, boolean
	 * CONSTANT_POOL_FLOAT:   float
	 * CONSTANT_POOL_LONG:    long
	 * CONSTANT_POOL_DOUBLE:  double
	 * CONSTANT_POOL_STRING:  String
	 */
	ut16 index;
} AttributeConstantValue;

typedef struct java_attribute_code_t {
	ut16 max_stack;
	ut16 max_locals;
	ut32 code_length;
	ut32 code_offset;
	ut16 exceptions_count;
	ExceptionTable *exceptions;
	ut16 attributes_count;
	Attribute **attributes;
} AttributeCode;

typedef struct java_attribute_source_file_t {
	ut16 index;
} AttributeSourceFile;

typedef struct java_attribute_line_number_table_t {
	ut16 table_length;
	LineNumberTable *table;
} AttributeLineNumberTable;

typedef struct java_attribute_local_variable_table_t {
	ut16 table_length;
	LocalVariableTable *table;
} AttributeLocalVariableTable;

typedef struct java_attribute_local_variable_type_table_t {
	ut16 table_length;
	LocalVariableTypeTable *table;
} AttributeLocalVariableTypeTable;

typedef struct java_attribute_module_t {
	ut16 module_name_index;
	ut16 module_flags;
	ut16 module_version_index;

	ut16 requires_count;
	ModuleRequire * requires;

	ut16 exports_count;
	ModuleExport *exports;

	ut16 opens_count;
	ModuleOpen *opens;

	ut16 uses_count;
	ut16 *uses_index;

	ut16 provides_count;
	ModuleProvide *provides;
} AttributeModule;

typedef struct java_attribute_module_packages_t {
	ut16 package_count;
	ut16 *package_index;
} AttributeModulePackages;

typedef struct java_attribute_module_main_class_t {
	ut16 main_class_index;
} AttributeModuleMainClass;

Attribute *java_attribute_new(RzBuffer *buf, ut64 offset);
void java_attribute_free(Attribute *attr);
bool java_attribute_resolve(ConstPool **pool, ut32 poolsize, Attribute *attr, RzBuffer *buf, bool is_oak);

#endif /* RZ_BIN_JAVA_CLASS_ATTRIBUTE_H */
