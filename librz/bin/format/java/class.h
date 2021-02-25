// SPDX-License-Identifier: Apache-2.0

#ifndef _INCLUDE_JAVA_CLASS_H_
#define _INCLUDE_JAVA_CLASS_H_

#include <rz_types.h>
#include <rz_list.h>
#include <rz_bin.h>
#include <sdb.h>
#include <rz_util.h>

#define raw_to_float(x, y) ((float)rz_read_at_be32(x, y))
double raw_to_double(const ut8 *raw, ut64 offset);

#if defined(_MSC_VER) && !defined(RZ_API_BIN_ONLY)
#undef RZ_API
#define RZ_API
#endif

#define RZ_BIN_JAVA_MAXSTR 256

typedef enum {
	RZ_BIN_JAVA_METHOD_ACC_PUBLIC = 0x0001,
	RZ_BIN_JAVA_METHOD_ACC_PRIVATE = 0x0002,
	RZ_BIN_JAVA_METHOD_ACC_PROTECTED = 0x0004,
	RZ_BIN_JAVA_METHOD_ACC_STATIC = 0x0008,

	RZ_BIN_JAVA_METHOD_ACC_FINAL = 0x0010,
	RZ_BIN_JAVA_METHOD_ACC_SYNCHRONIZED = 0x0020,
	RZ_BIN_JAVA_METHOD_ACC_BRIDGE = 0x0040,
	RZ_BIN_JAVA_METHOD_ACC_VARARGS = 0x0080,

	RZ_BIN_JAVA_METHOD_ACC_NATIVE = 0x0100,
	RZ_BIN_JAVA_METHOD_ACC_INTERFACE = 0x0200,
	RZ_BIN_JAVA_METHOD_ACC_ABSTRACT = 0x0400,
	RZ_BIN_JAVA_METHOD_ACC_STRICT = 0x0800,

	RZ_BIN_JAVA_METHOD_ACC_SYNTHETIC = 0x1000,
	RZ_BIN_JAVA_METHOD_ACC_ANNOTATION = 0x2000,
	RZ_BIN_JAVA_METHOD_ACC_ENUM = 0x4000
} RzBinJavaMethodAccess;

typedef enum {
	RZ_BIN_JAVA_FIELD_ACC_PUBLIC = 0x0001,
	RZ_BIN_JAVA_FIELD_ACC_PRIVATE = 0x0002,
	RZ_BIN_JAVA_FIELD_ACC_PROTECTED = 0x0004,
	RZ_BIN_JAVA_FIELD_ACC_STATIC = 0x0008,

	RZ_BIN_JAVA_FIELD_ACC_FINAL = 0x0010,
	RZ_BIN_JAVA_FIELD_ACC_VOLATILE = 0x0040,
	RZ_BIN_JAVA_FIELD_ACC_TRANSIENT = 0x0080,

	RZ_BIN_JAVA_FIELD_ACC_SYNTHETIC = 0x1000,
	RZ_BIN_JAVA_FIELD_ACC_ENUM = 0x4000
} RzBinJavaFieldAccess;

typedef enum {
	RZ_BIN_JAVA_CLASS_ACC_PUBLIC = 0x0001,
	RZ_BIN_JAVA_CLASS_ACC_PRIVATE = 0x0002,
	RZ_BIN_JAVA_CLASS_ACC_PROTECTED = 0x0004,
	RZ_BIN_JAVA_CLASS_ACC_STATIC = 0x0008,

	RZ_BIN_JAVA_CLASS_ACC_FINAL = 0x0010,
	RZ_BIN_JAVA_CLASS_ACC_SUPER = 0x0020,
	RZ_BIN_JAVA_CLASS_ACC_BRIDGE = 0x0040,
	RZ_BIN_JAVA_CLASS_ACC_VARARGS = 0x0080,

	RZ_BIN_JAVA_CLASS_ACC_NATIVE = 0x0100,
	RZ_BIN_JAVA_CLASS_ACC_INTERFACE = 0x0200,
	RZ_BIN_JAVA_CLASS_ACC_ABSTRACT = 0x0400,
	RZ_BIN_JAVA_CLASS_ACC_STRICT = 0x0800,

	RZ_BIN_JAVA_CLASS_ACC_SYNTHETIC = 0x1000,
	RZ_BIN_JAVA_CLASS_ACC_ANNOTATION = 0x2000,
	RZ_BIN_JAVA_CLASS_ACC_ENUM = 0x4000
} RzBinJavaClassAccess;

typedef struct {
	char *str;
	ut16 value;
	ut8 len;
} RzBinJavaAccessFlags;

typedef enum {
	RZ_BIN_JAVA_REF_UNKNOWN = 0,
	RZ_BIN_JAVA_REF_GETFIELD = 1,
	RZ_BIN_JAVA_REF_GETSTATIC = 2,
	RZ_BIN_JAVA_REF_PUTFIELD = 3,
	RZ_BIN_JAVA_REF_PUTSTATIC = 4,
	RZ_BIN_JAVA_REF_INVOKEVIRTUAL = 5,
	RZ_BIN_JAVA_REF_INVOKESTATIC = 6,
	RZ_BIN_JAVA_REF_INVOKESPECIAL = 7,
	RZ_BIN_JAVA_REF_NEWINVOKESPECIAL = 8,
	RZ_BIN_JAVA_REF_INVOKEINTERFACE = 9
} RzBinJavaRefType;

typedef enum {
	RZ_BIN_JAVA_CP_NULL = 0,
	RZ_BIN_JAVA_CP_UTF8 = 1,
	RZ_BIN_JAVA_CP_UNKNOWN = 2,
	RZ_BIN_JAVA_CP_INTEGER = 3,
	RZ_BIN_JAVA_CP_FLOAT = 4,
	RZ_BIN_JAVA_CP_LONG = 5,
	RZ_BIN_JAVA_CP_DOUBLE = 6,
	RZ_BIN_JAVA_CP_CLASS = 7,
	RZ_BIN_JAVA_CP_STRING = 8,
	RZ_BIN_JAVA_CP_FIELDREF = 9,
	RZ_BIN_JAVA_CP_METHODREF = 10,
	RZ_BIN_JAVA_CP_INTERFACEMETHOD_REF = 11,
	RZ_BIN_JAVA_CP_NAMEANDTYPE = 12,
	RZ_BIN_JAVA_CP_NOTHIN_13 = 13,
	RZ_BIN_JAVA_CP_NOTHIN_14 = 14,
	RZ_BIN_JAVA_CP_METHODHANDLE = 15,
	RZ_BIN_JAVA_CP_METHODTYPE = 16,
	RZ_BIN_JAVA_CP_NOTHIN_17 = 17,
	RZ_BIN_JAVA_CP_INVOKEDYNAMIC = 18,
} RzBinJavaCPType;

typedef enum {
	RZ_BIN_JAVA_STACK_FRAME_IMPLICIT = 0,
	RZ_BIN_JAVA_STACK_FRAME_SAME,
	RZ_BIN_JAVA_STACK_FRAME_SAME_LOCALS_1,
	RZ_BIN_JAVA_STACK_FRAME_CHOP,
	RZ_BIN_JAVA_STACK_FRAME_SAME_FRAME_EXTENDED,
	RZ_BIN_JAVA_STACK_FRAME_APPEND,
	RZ_BIN_JAVA_STACK_FRAME_FULL_FRAME,
	RZ_BIN_JAVA_STACK_FRAME_RESERVED
} RzBinJavaStackFrameType;

typedef enum {
	RZ_BIN_JAVA_ATTRIBUTE_ANNOTATION_DEFAULT_ATTR = 0,
	RZ_BIN_JAVA_ATTRIBUTE_BOOTSTRAP_METHODS_ATTR,
	RZ_BIN_JAVA_ATTRIBUTE_CODE_ATTR,
	RZ_BIN_JAVA_ATTRIBUTE_CONST_VALUE_ATTR,
	RZ_BIN_JAVA_ATTRIBUTE_DEPRECATED_ATTR,
	RZ_BIN_JAVA_ATTRIBUTE_ENCLOSING_METHOD_ATTR,
	RZ_BIN_JAVA_ATTRIBUTE_EXCEPTIONS_ATTR,
	RZ_BIN_JAVA_ATTRIBUTE_INNER_CLASSES_ATTR,
	RZ_BIN_JAVA_ATTRIBUTE_LINE_NUMBER_TABLE_ATTR,
	RZ_BIN_JAVA_ATTRIBUTE_LOCAL_VARIABLE_TABLE_ATTR,
	RZ_BIN_JAVA_ATTRIBUTE_LOCAL_VARIABLE_TYPE_TABLE_ATTR,
	RZ_BIN_JAVA_ATTRIBUTE_RUNTIME_INVISIBLE_ANNOTATION_ATTR,
	RZ_BIN_JAVA_ATTRIBUTE_RUNTIME_INVISIBLE_PARAMETER_ANNOTATION_ATTR,
	RZ_BIN_JAVA_ATTRIBUTE_RUNTIME_VISIBLE_ANNOTATION_ATTR,
	RZ_BIN_JAVA_ATTRIBUTE_RUNTIME_VISIBLE_PARAMETER_ANNOTATION_ATTR,
	RZ_BIN_JAVA_ATTRIBUTE_SIGNATURE_ATTR,
	RZ_BIN_JAVA_ATTRIBUTE_SOURCE_DEBUG_EXTENTSION_ATTR,
	RZ_BIN_JAVA_ATTRIBUTE_SOURCE_FILE_ATTR,
	RZ_BIN_JAVA_ATTRIBUTE_STACK_MAP_TABLE_ATTR,
	RZ_BIN_JAVA_ATTRIBUTE_SYNTHETIC_ATTR,
	RZ_BIN_JAVA_ATTRIBUTE_UNKNOWN_ATTR,
	RZ_BIN_JAVA_ATTRIBUTE_FAILED_ATTR
} RzBinJavaAttributeType;

typedef enum {
	RZ_BIN_JAVA_STACKMAP_TOP = 0,
	RZ_BIN_JAVA_STACKMAP_INTEGER,
	RZ_BIN_JAVA_STACKMAP_FLOAT,
	RZ_BIN_JAVA_STACKMAP_DOUBLE,
	RZ_BIN_JAVA_STACKMAP_LONG,
	RZ_BIN_JAVA_STACKMAP_NULL,
	RZ_BIN_JAVA_STACKMAP_THIS,
	RZ_BIN_JAVA_STACKMAP_OBJECT,
	RZ_BIN_JAVA_STACKMAP_UNINIT,
	RZ_BIN_JAVA_STACKMAP_UNKNOWN
} RzBinJavaStackmapType;

typedef enum {
	RZ_BIN_JAVA_FIELD_TYPE_FIELD = 0,
	RZ_BIN_JAVA_FIELD_TYPE_METHOD,
	RZ_BIN_JAVA_FIELD_TYPE_INTERFACE
} RzBinJavaFieldType;

typedef struct {
	ut64 file_offset;
	void *type_info;
	ut32 ord;
} RzBinJavaMetaInfo;

/* Class Reference Informations */

typedef struct {
	ut16 name_idx;
} RzBinJavaCPTypeClass;

typedef struct {
	ut16 class_idx;
	ut16 name_and_type_idx;
} RzBinJavaCPTypeFieldRef;

typedef struct {
	ut16 class_idx;
	ut16 name_and_type_idx;
} RzBinJavaCPTypeMethodRef;

typedef struct {
	ut16 class_idx;
	ut16 name_and_type_idx;
} RzBinJavaCPTypeInterfaceMethodRef;

typedef struct {
	ut8 reference_kind;
	ut16 reference_index;
} RzBinJavaCPTypeMethodHandle;

typedef struct {
	ut16 descriptor_index;
} RzBinJavaCPTypeMethodType;

typedef struct {
	ut16 bootstrap_method_attr_index;
	ut16 name_and_type_index;
} RzBinJavaCPTypeInvokeDynamic;

/* Primitive Type Informations */

typedef struct {
	ut16 string_idx;
} RzBinJavaCPTypeString;

typedef struct {
	union {
		ut8 raw[4];
		ut32 dword;
	} bytes;

} RzBinJavaCPTypeInteger;

typedef struct {
	union {
		ut8 raw[4];
		ut32 dword;
	} bytes;
} RzBinJavaCPTypeFloat;

typedef struct {
	union {
		ut8 raw[8];
		ut64 qword;
		struct {
			ut32 high;
			ut32 low;
		} dwords;
	} bytes;
} RzBinJavaCPTypeLong;

typedef struct {
	union {
		ut8 raw[8];
		struct {
			ut32 high;
			ut32 low;
		} dwords;
	} bytes;
} RzBinJavaCPTypeDouble;

/* Meta-data Info */

typedef struct {
	ut16 name_idx;
	ut16 descriptor_idx;
} RzBinJavaCPTypeNameAndType;

typedef struct {
	ut16 length;
	ut8 *bytes;
} RzBinJavaCPTypeUtf8;

typedef struct {
	RzBinJavaMetaInfo *metas;
	ut64 file_offset;
	ut8 tag;
	union {
		RzBinJavaCPTypeClass cp_class;
		RzBinJavaCPTypeMethodRef cp_method;
		RzBinJavaCPTypeFieldRef cp_field;
		RzBinJavaCPTypeInterfaceMethodRef cp_interface;

		RzBinJavaCPTypeString cp_string;
		RzBinJavaCPTypeInteger cp_integer;
		RzBinJavaCPTypeFloat cp_float;
		RzBinJavaCPTypeLong cp_long;
		RzBinJavaCPTypeDouble cp_double;
		RzBinJavaCPTypeNameAndType cp_name_and_type;
		RzBinJavaCPTypeUtf8 cp_utf8;

		RzBinJavaCPTypeMethodHandle cp_method_handle;
		RzBinJavaCPTypeMethodType cp_method_type;
		RzBinJavaCPTypeInvokeDynamic cp_invoke_dynamic;
	} info;
	char *name;
	ut8 *value;
	ut64 loadaddr;
	ut16 idx;
} RzBinJavaCPTypeObj;

typedef struct _stackmap_frame { // attribute StackMap
	ut64 file_offset;
	ut64 size;
	ut32 code_offset;
	ut8 tag;
	ut8 type;

	struct _stackmap_frame *p_stack_frame;

	RzBinJavaMetaInfo *metas;
	ut32 offset_delta;
	ut32 number_of_locals;
	// list of verification objects;
	RzList *local_items;
	ut32 number_of_stack_items;
	// list of verification objects;
	RzList *stack_items;

} RzBinJavaStackMapFrame;

typedef struct {
	ut8 *debug_extension;
} RzBinJavaSourceDebugExtensionAttr;

typedef struct {
	ut16 class_idx;
	ut16 method_idx;
	char *class_name;
	char *method_name;
	char *method_descriptor;
} RzBinJavaEnclosingMethodAttr;

typedef struct {
	ut64 file_offset;
	ut64 size;
	ut16 argument_info_idx;
	// additional informations?
	RzBinJavaCPTypeObj *argument_info_cp_obj;
} RzBinJavaBootStrapArgument;

typedef struct {
	ut64 file_offset;
	ut64 size;
	ut16 bootstrap_method_ref;
	ut16 num_bootstrap_arguments;
	// List of RzBinJavaCodeAttribute
	RzList *bootstrap_arguments;
} RzBinJavaBootStrapMethod;

typedef struct {
	ut16 num_bootstrap_methods;
	RzList *bootstrap_methods;
} RzBinJavaBootstrapMethodsAttr;

typedef struct {
	ut16 type_name_idx;
	ut16 const_name_idx;
	RzBinJavaCPTypeObj *const_name_cp_obj;
	RzBinJavaCPTypeObj *type_name_cp_obj;
} RzBinJavaEnumConstValue;

typedef struct {
	ut16 const_value_idx;
	RzBinJavaCPTypeObj *const_value_cp_obj;
} RzBinJavaConstValue;

typedef struct {
	ut16 class_info_idx;
	RzBinJavaCPTypeObj *class_info_cp_obj;
} RzBinJavaClassInfoValue;

typedef struct {
	ut64 size;
	ut32 num_values;
	RzList *values;
} RzBinJavaElementValueArray;

typedef struct {
	ut64 size;
	ut16 type_idx;
	ut16 num_element_value_pairs;
	RzList *element_value_pairs;
} RzBinJavaAnnotation;

typedef enum {
	// Primitive Types
	RZ_BIN_JAVA_EV_TAG_BYTE = 'B',
	RZ_BIN_JAVA_EV_TAG_CHAR = 'C',
	RZ_BIN_JAVA_EV_TAG_DOUBLE = 'D',
	RZ_BIN_JAVA_EV_TAG_FLOAT = 'F',
	RZ_BIN_JAVA_EV_TAG_INT = 'I',
	RZ_BIN_JAVA_EV_TAG_LONG = 'J',
	RZ_BIN_JAVA_EV_TAG_SHORT = 'S',
	RZ_BIN_JAVA_EV_TAG_BOOLEAN = 'Z',
	// Other tags
	RZ_BIN_JAVA_EV_TAG_ARRAY = '[',
	RZ_BIN_JAVA_EV_TAG_STRING = 's',
	RZ_BIN_JAVA_EV_TAG_ENUM = 'e',
	RZ_BIN_JAVA_EV_TAG_CLASS = 'c',
	RZ_BIN_JAVA_EV_TAG_ANNOTATION = '@',
	//	RZ_BIN_JAVA_EV_TAG_CLASSNAME = 'L',
	RZ_BIN_JAVA_EV_TAG_UNKNOWN = 0xff,
} RzBinJavaEVTag;

typedef struct {
	RzBinJavaMetaInfo *metas;
	ut64 size;
	ut8 tag;
	ut64 file_offset;
	union {
		RzBinJavaConstValue const_value;
		RzBinJavaEnumConstValue enum_const_value;
		RzBinJavaClassInfoValue class_value;
		RzBinJavaAnnotation annotation_value;
		RzBinJavaElementValueArray array_value;
	} value;
} RzBinJavaElementValue;

typedef struct {
	ut64 file_offset;
	ut64 size;
	ut16 element_name_idx;
	char *name;
	RzBinJavaElementValue *value;
} RzBinJavaElementValuePair;

typedef struct {
	ut64 size;
	ut16 num_annotations;
	RzList *annotations;
} RzBinJavaAnnotationsArray;

typedef RzBinJavaAnnotationsArray RzBinJavaRuntimeVisibleAnnotationsAttr;
typedef RzBinJavaAnnotationsArray RzBinJavaRuntimeInvisibleAnnotationsAttr;
typedef RzBinJavaAnnotationsArray RzBinJavaRuntimeParameterAnnotationsArray;

typedef struct {
	ut8 num_parameters;
	// RzBinJavaRuntimeParameterAnnotationsArray
	RzList *parameter_annotations;
} RzBinJavaRuntimeVisibleParameterAnnotationsAttr;

typedef RzBinJavaRuntimeVisibleParameterAnnotationsAttr RzBinJavaRuntimeInvisibleParameterAnnotationsAttr;

typedef struct {
	RzBinJavaElementValue *default_value;
} RzBinJavaAnnotationDefaultAttr;

typedef struct { // attribute StackMap
	ut32 code_size;
	ut32 number_of_entries;
	RzList *stack_map_frame_entries;
} RzBinJavaStackMapTableAttr;

typedef struct {
	ut16 signature_idx;
	char *signature;
} RzBinJavaSignatureAttr;

typedef struct {
	ut64 file_offset;
	ut64 size;
	ut8 tag;
	char *name;
	union {
		ut16 obj_val_cp_idx;
		ut16 uninit_offset;
	} info;
} RzBinJavaVerificationObj;

typedef struct {
	RzBinJavaMetaInfo *metas;
	ut64 size;
	char *name;
	char *descriptor;
	char *class_name;
	char *flags_str;

	ut64 file_offset;
	RzBinJavaFieldType type;
	ut16 flags;
	ut16 name_idx;
	ut16 descriptor_idx;

	RzBinJavaCPTypeObj *field_ref_cp_obj;
	ut64 attr_offset;
	ut16 attr_count;
	RzList *attributes;
	ut64 method_number;
} RzBinJavaField;

typedef struct {
	char *name;
	ut64 size;
	ut64 file_offset;
	ut16 class_info_idx;
	RzBinJavaCPTypeObj *cp_class;
} RzBinJavaInterfaceInfo;

typedef struct {
	ut16 constantvalue_idx;
} RzBinJavaConstantValueAttr;

typedef struct {
	ut16 number_of_exceptions;
	ut16 *exception_idx_table;
} RzBinJavaExceptionsAttr;

typedef struct {
	ut64 file_offset;
	ut16 start_pc;
	ut16 end_pc;
	ut16 handler_pc;
	ut16 catch_type;
	ut64 size;
} RzBinJavaExceptionEntry;

typedef struct {
	ut64 file_offset;
	ut32 code_offset;
	ut16 max_stack;
	ut16 max_locals;
	ut16 code_length;
	ut8 *code;

	ut32 exception_table_length;
	RzList *exception_table; // RzBinJavaExceptionTableEntry *

	ut16 attributes_count;
	RzList *attributes;
	RzBinJavaStackMapFrame *implicit_frame;
} RzBinJavaCodeAttr;

typedef struct {
	ut16 number_of_classes;
	RzList *classes;
} RzBinJavaInnerClassesAttribute;

typedef struct {
	ut16 sourcefile_idx;
} RzBinJavaSourceFileAttribute;

typedef struct {
	ut64 file_offset;
	ut16 start_pc;
	ut16 line_number;
	ut64 size;
} RzBinJavaLineNumberAttribute;

typedef struct {
	ut64 file_offset;
	ut16 line_number_table_length;
	RzList *line_number_table; // RzBinJavaLineNumberTable*
} RzBinJavaLineNumberTableAttribute;

typedef struct {
	char *name;
	char *signature;

	ut64 file_offset;
	ut16 start_pc;
	ut16 length;
	ut16 name_idx;
	ut16 signature_idx;
	ut16 index;
	ut64 size;
} RzBinJavaLocalVariableTypeAttribute;

typedef struct {
	ut16 table_length;
	RzList *local_variable_table; // RzBinJavaLocalVariable
} RzBinJavaLocalVariableTypeTableAttribute;

typedef struct {
	char *name;
	char *descriptor;

	ut64 file_offset;
	ut16 start_pc;
	ut16 length;
	ut16 name_idx;
	ut16 descriptor_idx;
	ut16 index;
	ut64 size;
} RzBinJavaLocalVariableAttribute;

typedef struct {
	ut16 table_length;
	RzList *local_variable_table; // RzBinJavaLocalVariable
} RzBinJavaLocalVariableTableAttribute;

typedef struct {
	ut8 *bytes;
	ut64 pos;
	ut64 size;
	char *name;
	ut64 file_offset;
	RzBinJavaMetaInfo *metas;
	int type;
	ut16 name_idx; //	ut16 attribute_name_idx;
	ut32 length; //ut16 attribute_length;
	ut64 loadaddr;
	bool is_attr_in_old_format;
	union {
		RzBinJavaAnnotationDefaultAttr annotation_default_attr;
		RzBinJavaBootstrapMethodsAttr bootstrap_methods_attr;
		RzBinJavaCodeAttr code_attr;
		RzBinJavaConstantValueAttr constant_value_attr;
		RzBinJavaEnclosingMethodAttr enclosing_method_attr;
		RzBinJavaExceptionsAttr exceptions_attr;
		RzBinJavaLineNumberTableAttribute line_number_table_attr;
		RzBinJavaLocalVariableTableAttribute local_variable_table_attr;
		RzBinJavaLocalVariableTypeTableAttribute local_variable_type_table_attr;
		RzBinJavaInnerClassesAttribute inner_classes_attr;

		RzBinJavaAnnotationsArray annotation_array;
		RzBinJavaRuntimeVisibleAnnotationsAttr rtv_annotations_attr;
		RzBinJavaRuntimeInvisibleAnnotationsAttr rti_annotations_attr;

		RzBinJavaRuntimeVisibleParameterAnnotationsAttr rtvp_annotations_attr;
		RzBinJavaRuntimeInvisibleParameterAnnotationsAttr rtip_annotations_attr;
		RzBinJavaSourceDebugExtensionAttr debug_extensions;
		RzBinJavaSourceFileAttribute source_file_attr;
		RzBinJavaStackMapTableAttr stack_map_table_attr;
		RzBinJavaSignatureAttr signature_attr;

	} info;

} RzBinJavaAttrInfo;

typedef struct {
	char *name;
	char *flags_str;
	ut64 file_offset;
	RzBinJavaAttrInfo *clint_attr;
	RzBinJavaField *clint_field;
	ut16 inner_class_info_idx;
	ut16 outer_class_info_idx;
	ut16 inner_name_idx;
	ut16 inner_class_access_flags;
	ut64 size;
} RzBinJavaClassesAttribute;

typedef struct {
	ut8 cafebabe[4];
	ut8 minor[2];
	ut8 major[2];
	ut16 cp_count;
} RzBinJavaClass;

typedef struct {
	ut16 access_flags;
	char *flags_str;
	char *this_class_name;
	ut16 this_class;
	ut16 super_class;
	ut16 cf2_size;
	RzBinJavaField *this_class_entrypoint;
	RzBinJavaAttrInfo *this_class_entrypoint_code_attr;
} RzBinJavaClass2;

typedef struct {
	int count;
	int *addr;
	int *line;
} RzBinJavaLines;

typedef struct {
	RzBinJavaClass cf;
	RzBinJavaClass2 cf2;
	const char *lang;

	ut64 cp_offset, fields_offset, interfaces_offset;
	ut64 classes_offset, methods_offset, attrs_offset;
	ut32 cp_size, cp_count;
	ut32 fields_size, fields_count;
	ut32 interfaces_size, interfaces_count;
	ut32 methods_size, methods_count;
	ut32 classes_size, classes_count;
	ut32 attrs_size, attrs_count;

	// load address that is used to calc actual offset
	// when multiple bins are loaded at once
	ut64 loadaddr;

	int size;
	int calc_size;
	char *file;
	RzBinJavaLines lines;

	// These state variables are used for parsing the appropriate number of bytes
	// when readin uoffset, ustack, ulocalvar values
	ut8 ulocalvar_sz;
	ut8 ustack_sz;
	ut8 offset_sz;
	ut32 cur_method_code_length;
	RzBinJavaAttrInfo *current_code_attr;

	ut32 attr_idx;
	ut32 method_idx;
	ut32 field_idx;
	ut32 cp_idx;
	ut32 interface_idx;
	ut32 attributes_idx;

	int fsym;
	int fsymsz;

	RzBinJavaField *main;
	RzBinJavaAttrInfo *main_code_attr;

	RzBinJavaField *entrypoint;
	RzBinJavaAttrInfo *entrypoint_code_attr;

	RzList *fields_list;
	RzList *methods_list;
	RzList *cp_list;
	RzList *interfaces_list;
	RzList *attrs_list;
	RzList *imports_list;

	RzList *functions;
	RzList *disassembly;

	Sdb *kv;
	Sdb *AllJavaBinObjs;
	ut32 id;

	RzStrConstPool constpool;
} RzBinJavaObj;

RZ_API RzList *rz_bin_java_get_interface_names(RzBinJavaObj *bin);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_get_item_from_cp(RzBinJavaObj *bin, int i);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_get_item_from_bin_cp_list(RzBinJavaObj *bin, ut64 idx);
RZ_API ut8 *rz_bin_java_cp_get_idx_bytes(RzBinJavaObj *bin, ut16 idx, ut32 *out_sz);
RZ_API RzList *rz_bin_java_get_lib_names(RzBinJavaObj *bin);
RZ_API RzList *rz_bin_java_get_sections(RzBinJavaObj *bin);
RZ_API RzList *rz_bin_java_get_fields(RzBinJavaObj *bin);
RZ_API char *rz_bin_java_get_version(RzBinJavaObj *bin);
RZ_API RzBinAddr *rz_bin_java_get_entrypoint(RzBinJavaObj *bin, int sym);
RZ_API RzList *rz_bin_java_get_entrypoints(RzBinJavaObj *bin);
RZ_API ut64 rz_bin_java_get_main(RzBinJavaObj *bin);
RZ_API RzList *rz_bin_java_get_symbols(RzBinJavaObj *bin);
RZ_API RzList *rz_bin_java_get_strings(RzBinJavaObj *bin);
RZ_API void *rz_bin_java_free(RzBinJavaObj *bin);
RZ_API RzBinJavaObj *rz_bin_java_new(const char *file, ut64 baddr, Sdb *kv);
RZ_API RzBinJavaObj *rz_bin_java_new_buf(RzBuffer *buf, ut64 baddr, Sdb *kv);
RZ_API int rz_bin_java_valid_class(const ut8 *buf, ut64 buf_sz);

// Stuff used to manage Java Class File Constant Information
typedef struct {
	RzBinJavaCPTypeObj *(*new_obj)(RzBinJavaObj *bin, ut8 *buffer, ut64 offset);
	void (*delete_obj)(void /*RzBinJavaCPTypeObj*/ *obj);
	void (*print_summary)(RzBinJavaCPTypeObj *obj);
	ut64 (*calc_size)(RzBinJavaCPTypeObj *obj);
	char *(*stringify_obj)(RzBinJavaCPTypeObj *obj);
} RzBinJavaCPTypeObjectAllocs;

typedef struct {
	RzBinJavaAttrInfo *(*new_obj)(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset);
	void (*delete_obj)(void /*RzBinJavaAttrInfo*/ *obj);
	void (*print_summary)(RzBinJavaAttrInfo *obj);
	ut64 (*calc_size)(RzBinJavaAttrInfo *obj);
} RzBinJavaAttrInfoObjectAllocs;

typedef struct {
	void (*new_obj)(RzBinJavaObj *bin, ut32 code_length, ut64 offset);
	void (*delete_obj)(void /*RzBinJavaAttrInfo*/ *obj);
	void (*print_summary)(RzBinJavaAttrInfo *obj);
} RzBinJavaVerInfoObjectAllocs;

typedef struct {
	RzBinJavaStackMapFrame *(*new_obj)(RzBinJavaObj *bin, ut64 offset);
	void (*delete_obj)(void /* RzBinJavaStackMapFrame*/ *obj);
	void (*print_summary)(RzBinJavaStackMapFrame *obj);
} RzBinJavaStackMapFrameObjectAllocs;

typedef struct {
	RzBinJavaElementValue *(*new_obj)(RzBinJavaObj *bin, ut64 offset);
	void (*delete_obj)(void /*RzBinJavaElementValue*/ *obj);
	void (*print_summary)(RzBinJavaElementValue *obj);
} RzBinJavaElementValueObjectAllocs;

typedef struct {
	char *name;
	ut8 tag;
	ut32 len;
	RzBinJavaCPTypeObjectAllocs *allocs;
} RzBinJavaCPTypeMetas;

typedef struct {
	char *name;
	ut8 type;
	RzBinJavaAttrInfoObjectAllocs *allocs;
} RzBinJavaAttrMetas;

typedef struct {
	char *name;
	ut8 type;
} RzBinJavaVerificationMetas;

typedef struct {
	char *name;
	ut8 type;
	RzBinJavaStackMapFrameObjectAllocs *allocs;
} RzBinJavaStackMapFrameMetas;

typedef struct {
	char *name;
	ut8 tag;
	RzBinJavaElementValueObjectAllocs *allocs;
} RzBinJavaElementValueMetas;

typedef struct {
	char *name;
	ut8 tag;
} RzBinJavaRefMetas;

typedef struct {
	ut32 len;
	char *str;
} _JavaStr;

typedef struct {
	char *class_name;
	char *name;
	char *desc;
	ut8 is_method;
	ut8 is_field;
} _JavaRef;

typedef struct {
	const char *type;
	union {
		ut8 _null;
		ut8 _char;
		ut8 _byte;
		ut64 _long;
		double _double;
		ut32 _int;
		float _float;
		ut16 _short;
		ut8 _bool;
		_JavaStr *_str;
		_JavaRef *_ref;
	} value;
} _ConstJavaValue;

RZ_API ut8 *rz_bin_java_get_attr_buf(RzBinJavaObj *bin, ut64 sz, const ut64 offset, const ut8 *buf, const ut64 len);
RZ_API char *rz_bin_java_get_name_from_cp_item_list(RzList *cp_list, ut64 idx);
RZ_API char *rz_bin_java_get_utf8_from_cp_item_list(RzList *cp_list, ut64 idx);
RZ_API ut32 rz_bin_java_get_utf8_len_from_cp_item_list(RzList *cp_list, ut64 idx);
RZ_API char *rz_bin_java_get_desc_from_cp_item_list(RzList *cp_list, ut64 idx);
RZ_API char *rz_bin_java_get_item_name_from_cp_item_list(RzList *cp_list, RzBinJavaCPTypeObj *obj, int depth);
RZ_API char *rz_bin_java_get_item_desc_from_cp_item_list(RzList *cp_list, RzBinJavaCPTypeObj *obj, int depth);

RZ_API char *rz_bin_java_get_name_from_bin_cp_list(RzBinJavaObj *bin, ut64 idx);
RZ_API char *rz_bin_java_get_utf8_from_bin_cp_list(RzBinJavaObj *bin, ut64 idx);
RZ_API ut32 rz_bin_java_get_utf8_len_from_bin_cp_list(RzBinJavaObj *bin, ut64 idx);
RZ_API char *rz_bin_java_get_desc_from_bin_cp_list(RzBinJavaObj *bin, ut64 idx);
RZ_API char *rz_bin_java_get_item_name_from_bin_cp_list(RzBinJavaObj *bin, RzBinJavaCPTypeObj *obj);
RZ_API char *rz_bin_java_get_item_desc_from_bin_cp_list(RzBinJavaObj *bin, RzBinJavaCPTypeObj *obj);

// free bin lists

RZ_API char *rz_bin_java_stringify_cp_utf8(RzBinJavaCPTypeObj *obj);
RZ_API char *rz_bin_java_stringify_cp_name_and_type(RzBinJavaCPTypeObj *obj);
RZ_API char *rz_bin_java_stringify_cp_double(RzBinJavaCPTypeObj *obj);
RZ_API char *rz_bin_java_stringify_cp_long(RzBinJavaCPTypeObj *obj);
RZ_API char *rz_bin_java_stringify_cp_float(RzBinJavaCPTypeObj *obj);
RZ_API char *rz_bin_java_stringify_cp_integer(RzBinJavaCPTypeObj *obj);
RZ_API char *rz_bin_java_stringify_cp_string(RzBinJavaCPTypeObj *obj);
RZ_API char *rz_bin_java_stringify_cp_classref(RzBinJavaCPTypeObj *obj);
RZ_API char *rz_bin_java_stringify_cp_fieldref(RzBinJavaCPTypeObj *obj);
RZ_API char *rz_bin_java_stringify_cp_methodref(RzBinJavaCPTypeObj *obj);
RZ_API char *rz_bin_java_stringify_cp_interfacemethodref(RzBinJavaCPTypeObj *obj);
RZ_API char *rz_bin_java_stringify_cp_unknown(RzBinJavaCPTypeObj *obj);
RZ_API char *rz_bin_java_stringify_cp_null(RzBinJavaCPTypeObj *obj);
RZ_API char *rz_bin_java_stringify_cp_methodtype(RzBinJavaCPTypeObj *obj);
RZ_API char *rz_bin_java_stringify_cp_invokedynamic(RzBinJavaCPTypeObj *obj);
RZ_API char *rz_bin_java_stringify_cp_methodhandle(RzBinJavaCPTypeObj *obj);
RZ_API char *rz_bin_java_stringify_cp_class(RzBinJavaCPTypeObj *obj);

RZ_API RzBinSymbol *rz_bin_java_create_new_symbol_from_field_with_access_flags(RzBinJavaField *fm_type);
RZ_API RzBinSymbol *rz_bin_java_create_new_symbol_from_cp_idx(ut32 cp_idx, ut64 baddr);
RZ_API RzBinSymbol *rz_bin_java_create_new_symbol_from_invoke_dynamic(RzBinJavaCPTypeObj *obj, ut64 baddr);
RZ_API RzBinSymbol *rz_bin_java_create_new_symbol_from_ref(RzBinJavaObj *bin, RzBinJavaCPTypeObj *obj, ut64 baddr);
RZ_API RzBinSymbol *rz_bin_java_create_new_symbol_from_method(RzBinJavaField *fm_type);

RZ_API ut64 rz_bin_java_get_method_code_offset(RzBinJavaField *fm_type);
RZ_API ut64 rz_bin_java_get_method_code_size(RzBinJavaField *fm_type);
RZ_API ut64 rz_bin_java_get_class_entrypoint(RzBinJavaObj *bin);

RZ_API RzBinJavaCPTypeObj *rz_bin_java_find_cp_ref_info(RzBinJavaObj *bin, ut16 name_and_typeidx);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_find_cp_ref_info_from_name_and_type(RzBinJavaObj *bin, ut16 name_idx, ut16 descriptor_idx);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_find_cp_name_and_type_info(RzBinJavaObj *bin, ut16 name_idx, ut16 descriptor_idx);

RZ_API RzBinClass *rz_bin_java_allocate_r_bin_class(void);
RZ_API RzList *rz_bin_java_get_classes(RzBinJavaObj *bin);
RZ_API RzList *rz_bin_java_enum_class_methods(RzBinJavaObj *bin, ut16 class_idx);
RZ_API RzList *rz_bin_java_enum_class_fields(RzBinJavaObj *bin, ut16 class_idx);
RZ_API ut64 rz_bin_java_find_method_offset(RzBinJavaObj *bin, const char *method_name);

RZ_API RzBinJavaField *rz_bin_java_get_method_code_attribute_with_addr(RzBinJavaObj *bin, ut64 addr);
RZ_API RzList *rz_bin_java_get_method_exception_table_with_addr(RzBinJavaObj *bin, ut64 addr);

RZ_API const RzList *rz_bin_java_get_methods_list(RzBinJavaObj *bin);
RZ_API const RzBinJavaObj *rz_bin_java_get_bin_obj(const char *name);
RZ_API int rz_bin_java_update_file(const char *key, RzBinJavaObj *bin_obj);
RZ_API RzBinJavaObj *rz_bin_java_get_sdb_bin_obj(const char *filename);
RZ_API RzList *rz_bin_java_get_bin_obj_list(void);
RZ_API RzList *rz_bin_java_get_bin_obj_list_thru_obj(RzBinJavaObj *bin_obj);
RZ_API char *rz_bin_java_get_this_class_name(RzBinJavaObj *bin_obj);
RZ_API char *rz_bin_java_build_obj_key(RzBinJavaObj *bin);

RZ_API RzList *rz_bin_java_extract_type_values(const char *arg_str);
RZ_API int rz_bin_java_extract_reference_name(const char *input_str, char **ref_str, ut8 array_cnt);
RZ_API RzList *rz_bin_java_extract_all_bin_type_values(RzBinJavaObj *bin_obj);

RZ_API RzList *rz_bin_java_get_method_definitions(RzBinJavaObj *bin);
RZ_API char *rz_bin_java_get_method_definition(RzBinJavaField *fm_type);
RZ_API RzList *rz_bin_java_get_field_definitions(RzBinJavaObj *bin);
RZ_API char *rz_bin_java_get_field_definition(RzBinJavaField *fm_type);
RZ_API RzList *rz_bin_java_get_import_definitions(RzBinJavaObj *bin);
RZ_API RzList *rz_bin_java_get_field_offsets(RzBinJavaObj *bin);
RZ_API RzList *rz_bin_java_get_method_offsets(RzBinJavaObj *bin);

RZ_API ut16 rz_bin_java_calculate_method_access_value(const char *access_flags_str);
RZ_API ut16 rz_bin_java_calculate_field_access_value(const char *access_flags_str);
RZ_API ut16 rz_bin_java_calculate_class_access_value(const char *access_flags_str);

RZ_API RzList *retrieve_all_method_access_string_and_value(void);
RZ_API RzList *retrieve_all_field_access_string_and_value(void);
RZ_API RzList *retrieve_all_class_access_string_and_value(void);
RZ_API char *retrieve_method_access_string(ut16 flags);
RZ_API char *retrieve_field_access_string(ut16 flags);
RZ_API char *retrieve_class_method_access_string(ut16 flags);

RZ_API char *rz_bin_java_resolve(RzBinJavaObj *obj, int idx, ut8 space_bn_name_type);
RZ_API char *rz_bin_java_resolve_with_space(RzBinJavaObj *obj, int idx);
RZ_API char *rz_bin_java_resolve_without_space(RzBinJavaObj *BIN_OBJ, int idx);
RZ_API char *rz_bin_java_resolve_cp_idx_type(RzBinJavaObj *BIN_OBJ, int idx);
RZ_API char *rz_bin_java_resolve_b64_encode(RzBinJavaObj *BIN_OBJ, ut16 idx);
RZ_API ut64 rz_bin_java_resolve_cp_idx_address(RzBinJavaObj *BIN_OBJ, int idx);
RZ_API char *rz_bin_java_resolve_cp_idx_to_string(RzBinJavaObj *BIN_OBJ, int idx);
RZ_API int rz_bin_java_summary_resolve_cp_idx_print(RzBinJavaObj *BIN_OBJ, int idx);

RZ_API _ConstJavaValue *rz_bin_java_resolve_to_const_value(RzBinJavaObj *BIN_OBJ, int idx);
RZ_API void rz_bin_java_free_const_value(_ConstJavaValue *cp_value);

RZ_API char *rz_bin_java_get_fcn_name(RzBinJavaField *fm_type);
RZ_API RzList *rz_bin_java_get_args(RzBinJavaField *fm_type);
RZ_API RzList *rz_bin_java_get_ret(RzBinJavaField *fm_type);

RZ_API RzList *rz_bin_java_get_args_from_bin(RzBinJavaObj *bin_obj, ut64 addr);
RZ_API RzList *rz_bin_java_get_ret_from_bin(RzBinJavaObj *bin_obj, ut64 addr);
RZ_API char *rz_bin_java_get_fcn_name_from_bin(RzBinJavaObj *bin_obj, ut64 addr);
RZ_API int rz_bin_java_is_method_static(RzBinJavaObj *bin_obj, ut64 addr);

RZ_API ut8 rz_bin_java_does_cp_idx_ref_method(RzBinJavaObj *BIN_OBJ, int idx);
RZ_API ut8 rz_bin_java_does_cp_idx_ref_field(RzBinJavaObj *BIN_OBJ, int idx);
RZ_API int rz_bin_java_is_method_protected(RzBinJavaObj *bin_obj, ut64 addr);
RZ_API int rz_bin_java_is_method_private(RzBinJavaObj *bin_obj, ut64 addr);
RZ_API RzBinJavaAttrInfo *rz_bin_java_get_method_code_attribute(const RzBinJavaField *method);

RZ_API char *rz_bin_java_get_method_name(RzBinJavaObj *bin_obj, ut32 idx);
RZ_API bool rz_bin_java_summary_print_method_idx(RzBinJavaObj *bin_obj, ut32 idx);
RZ_API ut32 rz_bin_java_get_method_count(RzBinJavaObj *bin_obj);
RZ_API RzList *rz_bin_java_get_method_num_name(RzBinJavaObj *bin_obj);

RZ_API char *rz_bin_java_get_field_name(RzBinJavaObj *bin_obj, ut32 idx);
RZ_API int rz_bin_java_summary_print_field_idx(RzBinJavaObj *bin_obj, ut32 idx);
RZ_API ut32 rz_bin_java_get_field_count(RzBinJavaObj *bin_obj);
RZ_API RzList *rz_bin_java_get_field_num_name(RzBinJavaObj *bin_obj);

RZ_API RzList *rz_bin_java_find_cp_const_by_val(RzBinJavaObj *bin_obj, const ut8 *bytes, ut32 len, const char t);
RZ_API char rz_bin_java_resolve_cp_idx_tag(RzBinJavaObj *BIN_OBJ, int idx);

RZ_API int rz_bin_java_integer_cp_set(RzBinJavaObj *bin, ut16 idx, ut32 val);
RZ_API int rz_bin_java_float_cp_set(RzBinJavaObj *bin, ut16 idx, float val);
RZ_API int rz_bin_java_long_cp_set(RzBinJavaObj *bin, ut16 idx, ut64 val);
RZ_API int rz_bin_java_double_cp_set(RzBinJavaObj *bin, ut16 idx, ut32 val);
RZ_API int rz_bin_java_utf8_cp_set(RzBinJavaObj *bin, ut16 idx, const ut8 *buffer, ut32 len);
RZ_API ut8 *rz_bin_java_cp_get_bytes(ut8 tag, ut32 *out_sz, const ut8 *buf, const ut64 len);
RZ_API ut8 *rz_bin_java_cp_idx_get_bytes(RzBinJavaObj *bin, ut16 idx, ut32 *out_sz);
RZ_API ut32 rz_bin_java_cp_get_size(RzBinJavaObj *bin, ut16 idx);

RZ_API ut64 rz_bin_java_parse_cp_pool(RzBinJavaObj *bin, const ut64 offset, const ut8 *buf, const ut64 len);
RZ_API ut64 rz_bin_java_parse_interfaces(RzBinJavaObj *bin, const ut64 offset, const ut8 *buf, const ut64 len);
RZ_API ut64 rz_bin_java_parse_fields(RzBinJavaObj *bin, const ut64 offset, const ut8 *buf, const ut64 len);
RZ_API ut64 rz_bin_java_parse_methods(RzBinJavaObj *bin, const ut64 offset, const ut8 *buf, const ut64 len);
RZ_API ut64 rz_bin_java_parse_attrs(RzBinJavaObj *bin, const ut64 offset, const ut8 *buf, const ut64 len);
RZ_API int rz_bin_java_load_bin(RzBinJavaObj *bin, const ut8 *buf, ut64 len);
RZ_API void rz_bin_add_import(RzBinJavaObj *bin, RzBinJavaCPTypeObj *cp_obj, const char *type);
RZ_API void rz_bin_java_set_imports(RzBinJavaObj *bin);
RZ_API RzList *rz_bin_java_get_imports(RzBinJavaObj *bin);

RZ_API ut64 rz_bin_java_get_method_start(RzBinJavaObj *bin, RzBinJavaField *method);
RZ_API ut64 rz_bin_java_get_method_end(RzBinJavaObj *bin, RzBinJavaField *method);

RZ_API ut8 *rz_bin_java_cp_get_fref_bytes(RzBinJavaObj *bin, ut32 *out_sz, ut8 tag, ut16 cn_idx, ut16 fn_idx, ut16 ft_idx);
RZ_API ut8 *rz_bin_java_cp_append_method_ref(RzBinJavaObj *bin, ut32 *out_sz, ut16 cn_idx, ut16 fn_idx, ut16 ft_idx);
RZ_API ut8 *rz_bin_java_cp_append_field_ref(RzBinJavaObj *bin, ut32 *out_sz, ut16 cn_idx, ut16 fn_idx, ut16 ft_idx);
RZ_API char *rz_bin_java_unmangle_without_flags(const char *name, const char *descriptor);
RZ_API char *rz_bin_java_unmangle(const char *flags, const char *name, const char *descriptor);

RZ_API ut64 rz_bin_java_calc_class_size(ut8 *bytes, ut64 size);
RZ_API int rz_bin_java_valid_class(const ut8 *buf, ut64 buf_sz);
#endif
