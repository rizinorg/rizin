// SPDX-License-Identifier: Apache-2.0
#ifndef JAVA_PRINT_H
#define JAVA_PRINT_H

#include "class.h"

RZ_API void rz_bin_java_print_utf8_cp_summary(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_print_name_and_type_cp_summary(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_print_double_cp_summary(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_print_long_cp_summary(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_print_float_cp_summary(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_print_integer_cp_summary(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_print_string_cp_summary(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_print_classref_cp_summary(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_print_fieldref_cp_summary(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_print_methodref_cp_summary(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_print_interfacemethodref_cp_summary(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_print_unknown_cp_summary(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_print_null_cp_summary(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_print_unknown_attr_summary(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_print_methodhandle_cp_summary(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_print_methodtype_cp_summary(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_print_invokedynamic_cp_summary(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_print_stack_map_table_attr_summary(RzBinJavaAttrInfo *obj);
RZ_API void rz_bin_java_print_stack_map_frame_summary(RzBinJavaStackMapFrame *obj);
RZ_API void rz_bin_java_print_verification_info_summary(RzBinJavaVerificationObj *obj);
RZ_API void rz_bin_java_print_stack_map_append_frame_summary(RzBinJavaStackMapFrame *obj);
RZ_API void rz_bin_java_print_annotation_default_attr_summary(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_print_enclosing_methods_attr_summary(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_print_local_variable_type_attr_summary(RzBinJavaLocalVariableTypeAttribute *lvattr);
RZ_API void rz_bin_java_print_local_variable_type_table_attr_summary(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_print_signature_attr_summary(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_print_source_debug_attr_summary(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_print_element_value_summary(RzBinJavaElementValue *element_value);
RZ_API void rz_bin_java_print_annotation_summary(RzBinJavaAnnotation *annotation);
RZ_API void rz_bin_java_print_element_pair_summary(RzBinJavaElementValuePair *evp);
RZ_API void rz_bin_java_print_bootstrap_methods_attr_summary(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_print_rtv_annotations_attr_summary(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_print_rti_annotations_attr_summary(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_print_annotation_array_summary(RzBinJavaAnnotationsArray *annotation_array);
RZ_API void rz_bin_java_print_rtvp_annotations_attr_summary(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_print_rtip_annotations_attr_summary(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_print_field_summary(RzBinJavaField *field);
RZ_API void rz_bin_java_print_method_summary(RzBinJavaField *field);
RZ_API void rz_bin_java_print_code_exceptions_attr_summary(RzBinJavaExceptionEntry *exc_entry);
RZ_API void rz_bin_java_print_code_attr_summary(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_print_constant_value_attr_summary(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_print_deprecated_attr_summary(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_print_exceptions_attr_summary(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_print_classes_attr_summary(RzBinJavaClassesAttribute *icattr);
RZ_API void rz_bin_java_print_inner_classes_attr_summary(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_print_line_number_table_attr_summary(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_print_local_variable_attr_summary(RzBinJavaLocalVariableAttribute *lvattr);
RZ_API void rz_bin_java_print_local_variable_table_attr_summary(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_print_source_code_file_attr_summary(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_print_synthetic_attr_summary(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_print_attr_summary(RzBinJavaAttrInfo *attr);

#endif /* JAVA_PRINT_H */
