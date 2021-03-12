// SPDX-License-Identifier: Apache-2.0
#ifndef JAVA_PRINT_H
#define JAVA_PRINT_H

#include "class.h"

RZ_API void rz_bin_java_summary_cp_print_utf8(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_summary_cp_print_name_and_type(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_summary_cp_print_double(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_summary_cp_print_long(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_summary_cp_print_float(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_summary_cp_print_integer(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_summary_cp_print_string(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_summary_cp_print_classref(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_summary_cp_print_fieldref(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_summary_cp_print_methodref(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_summary_cp_print_interfacemethodref(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_summary_cp_print_unknown(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_summary_cp_print_null(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_summary_print_unknown_attr(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_summary_cp_print_methodhandle(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_summary_cp_print_methodtype(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_summary_cp_print_invokedynamic(RzBinJavaCPTypeObj *obj);
RZ_API void rz_bin_java_summary_print_stack_map_table_attr(RzBinJavaAttrInfo *obj);
RZ_API void rz_bin_java_summary_print_stack_map_frame(RzBinJavaStackMapFrame *obj);
RZ_API void rz_bin_java_summary_print_verification_info(RzBinJavaVerificationObj *obj);
RZ_API void rz_bin_java_summary_print_stack_map_append_frame(RzBinJavaStackMapFrame *obj);
RZ_API void rz_bin_java_summary_print_annotation_default_attr(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_summary_print_enclosing_methods_attr(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_summary_print_local_variable_type_attr(RzBinJavaLocalVariableTypeAttribute *lvattr);
RZ_API void rz_bin_java_summary_print_local_variable_type_table_attr(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_summary_print_signature_attr(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_summary_print_source_debug_attr(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_summary_print_element_value(RzBinJavaElementValue *element_value);
RZ_API void rz_bin_java_summary_print_annotation(RzBinJavaAnnotation *annotation);
RZ_API void rz_bin_java_summary_print_element_pair(RzBinJavaElementValuePair *evp);
RZ_API void rz_bin_java_summary_print_bootstrap_methods_attr(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_summary_print_rtv_annotations_attr(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_summary_print_rti_annotations_attr(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_summary_print_annotation_array(RzBinJavaAnnotationsArray *annotation_array);
RZ_API void rz_bin_java_summary_print_rtvp_annotations_attr(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_summary_print_rtip_annotations_attr(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_summary_print_field(RzBinJavaField *field);
RZ_API void rz_bin_java_summary_print_method(RzBinJavaField *field);
RZ_API void rz_bin_java_summary_print_code_exceptions_attr(RzBinJavaExceptionEntry *exc_entry);
RZ_API void rz_bin_java_summary_print_code_attr(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_summary_print_constant_value_attr(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_summary_print_deprecated_attr(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_summary_print_exceptions_attr(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_summary_print_classes_attr(RzBinJavaClassesAttribute *icattr);
RZ_API void rz_bin_java_summary_print_inner_classes_attr(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_summary_print_line_number_table_attr(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_summary_print_local_variable_attr(RzBinJavaLocalVariableAttribute *lvattr);
RZ_API void rz_bin_java_summary_print_local_variable_table_attr(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_summary_print_source_code_file_attr(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_summary_print_synthetic_attr(RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_summary_print_attr(RzBinJavaAttrInfo *attr);

#endif /* JAVA_PRINT_H */
