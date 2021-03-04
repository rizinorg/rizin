// SPDX-FileCopyrightText: 2007-2018 pancake
// SPDX-FileCopyrightText: 2007-2018 dso
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_bin.h>
#include <math.h>
#include <sdb.h>

#include "class.h"
#include "print.h"

#define MAX_CPITEMS 8192

RZ_API char *rz_bin_java_unmangle_method(const char *flags, const char *name, const char *params, const char *rz_value);
RZ_API int rz_bin_java_is_fm_type_private(RzBinJavaField *fm_type);
RZ_API int rz_bin_java_is_fm_type_protected(RzBinJavaField *fm_type);
RZ_API ut32 rz_bin_java_swap_uint(ut32 x);

// RZ_API const char * rz_bin_java_get_this_class_name(RzBinJavaObj *bin);
RZ_API void add_cp_objs_to_sdb(RzBinJavaObj *bin);
RZ_API void add_field_infos_to_sdb(RzBinJavaObj *bin);
RZ_API void add_method_infos_to_sdb(RzBinJavaObj *bin);
RZ_API RzList *retrieve_all_access_string_and_value(RzBinJavaAccessFlags *access_flags);
RZ_API char *retrieve_access_string(ut16 flags, RzBinJavaAccessFlags *access_flags);
RZ_API ut16 calculate_access_value(const char *access_flags_str, RzBinJavaAccessFlags *access_flags);
RZ_API int rz_bin_java_new_bin(RzBinJavaObj *bin, ut64 loadaddr, Sdb *kv, const ut8 *buf, ut64 len);
RZ_API int extract_type_value(const char *arg_str, char **output);
RZ_API int rz_bin_java_check_reset_cp_obj(RzBinJavaCPTypeObj *cp_obj, ut8 tag);
RZ_API ut8 *rz_bin_java_cp_get_4bytes(ut8 tag, ut32 *out_sz, const ut8 *buf, const ut64 len);
RZ_API ut8 *rz_bin_java_cp_get_8bytes(ut8 tag, ut32 *out_sz, const ut8 *buf, const ut64 len);
RZ_API ut8 *rz_bin_java_cp_get_utf8(ut8 tag, ut32 *out_sz, const ut8 *buf, const ut64 len);

RZ_API RzBinJavaCPTypeObj *rz_bin_java_get_item_from_bin_cp_list(RzBinJavaObj *bin, ut64 idx);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_get_item_from_cp_item_list(RzList *cp_list, ut64 idx);
// Allocs for objects
RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_class_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 offset);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_fieldref_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 offset);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_methodref_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 offset);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_interfacemethodref_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 offset);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_name_and_type_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 offset);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_string_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 offset);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_integer_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 offset);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_float_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 offset);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_long_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 offset);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_double_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 offset);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_utf8_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 offset);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_do_nothing(RzBinJavaObj *bin, ut8 *buffer, ut64 sz);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_clone_cp_item(RzBinJavaCPTypeObj *obj);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_clone_cp_idx(RzBinJavaObj *bin, ut32 idx);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_methodhandle_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 sz);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_methodtype_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 sz);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_invokedynamic_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 sz);
// Deallocs for type objects
RZ_API void rz_bin_java_free_default(void /*RzBinJavaCPTypeObj*/ *obj);
RZ_API void rz_bin_java_free_obj(void /*RzBinJavaCPTypeObj*/ *obj);
RZ_API void rz_bin_java_free_utf8_info(void /*RzBinJavaCPTypeObj*/ *obj);
RZ_API void rz_bin_java_free_do_nothing(void /*RzBinJavaCPTypeObj*/ *obj);
RZ_API void rz_bin_java_free_fmtype(void /*RzBinJavaField*/ *fm_type);
// handle freeing the lists
// handle the reading of the various field
RZ_API RzBinJavaAttrInfo *rz_bin_java_read_next_attr(RzBinJavaObj *bin, const ut64 offset, const ut8 *buf, const ut64 len);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_read_next_constant_pool_item(RzBinJavaObj *bin, const ut64 offset, const ut8 *buf, ut64 len);
RZ_API RzBinJavaAttrMetas *rz_bin_java_get_attr_type_by_name(const char *name);
RZ_API RzBinJavaCPTypeObj *rz_bin_java_get_java_null_cp(void);
RZ_API ut64 rz_bin_java_read_class_file2(RzBinJavaObj *bin, const ut64 offset, const ut8 *buf, ut64 len);
RZ_API RzBinJavaAttrInfo *rz_bin_java_get_attr_from_field(RzBinJavaField *field, RzBinJavaAttributeType attr_type, ut32 pos);
RZ_API RzBinJavaField *rz_bin_java_read_next_field(RzBinJavaObj *bin, const ut64 offset, const ut8 *buffer, const ut64 len);
RZ_API RzBinJavaField *rz_bin_java_read_next_method(RzBinJavaObj *bin, const ut64 offset, const ut8 *buffer, const ut64 len);

RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_unknown_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 sz);
RZ_API RzBinJavaInterfaceInfo *rz_bin_java_new_interface(RzBinJavaObj *bin, const ut8 *buf, ut64 sz);
RZ_API RzBinJavaInterfaceInfo *rz_bin_java_read_next_interface_item(RzBinJavaObj *bin, const ut64 offset, const ut8 *buf, ut64 len);
RZ_API void rz_bin_java_free_interface(void /*RzBinJavaInterfaceInfo*/ *obj);
RZ_API void rz_bin_java_free_stack_frame(void /*RzBinJavaStackMapFrame*/ *obj);
RZ_API void rz_bin_java_free_stack_map_table_attr(void /*RzBinJavaAttrInfo*/ *attr);
RZ_API void rz_bin_java_free_verification_info(void /*RzBinJavaVerificationObj*/ *obj);

RZ_API RzBinJavaStackMapFrame *rz_bin_java_build_stack_frame_from_local_variable_table(RzBinJavaObj *bin, RzBinJavaAttrInfo *attr);
RZ_API void rz_bin_java_free_stack_frame_default(void /*RzBinJavaStackMapFrame*/ *stack_frame);
RZ_API void rz_bin_java_free_stack_frame_do_nothing(void /*RzBinJavaStackMapFrame*/ *stack_frame);
RZ_API void rz_bin_java_new_stack_frame_do_nothing(RzBinJavaObj *bin, RzBinJavaStackMapFrame *stack_frame, ut64 offset);
RZ_API RzBinJavaStackMapFrame *rz_bin_java_new_stack_map_frame(ut8 *buffer, ut64 sz, RzBinJavaStackMapFrame *p_frame, ut64 buf_offset);
// RZ_API RzBinJavaStackMapFrame* rz_bin_java_new_stack_map_frame (ut8* buffer, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaElementValue *rz_bin_java_new_element_value(ut8 *buffer, ut64 sz, ut64 buf_offset);
// RZ_API RzBinJavaVerificationObj* rz_bin_java_new_read_next_verification_info(ut8* buffer, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAnnotation *rz_bin_java_new_annotation(ut8 *buffer, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaElementValuePair *rz_bin_java_new_element_pair(ut8 *buffer, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaElementValue *rz_bin_java_new_element_value(ut8 *buffer, ut64 sz, ut64 buf_offset);
// RZ_API RzBinJavaBootStrapArgument* rz_bin_java_new_bootstrap_method_argument(ut8* buffer, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaBootStrapMethod *rz_bin_java_new_bootstrap_method(ut8 *buffer, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAnnotationsArray *rz_bin_java_new_annotation_array(ut8 *buffer, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaElementValueMetas *rz_bin_java_get_ev_meta_from_tag(ut8 tag);
RZ_API RzBinJavaCPTypeMetas *rz_bin_java_get_cp_meta_from_tag(ut8 tag);
RZ_API void rz_bin_java_free_inner_classes_attr_entry(void /*RzBinJavaClassesAttribute*/ *attr);
RZ_API void rz_bin_java_free_annotation_default_attr(void /*RzBinJavaAttrInfo*/ *attr);
RZ_API void rz_bin_java_free_enclosing_methods_attr(void /*RzBinJavaAttrInfo*/ *attr);
RZ_API void rz_bin_java_free_local_variable_type_table_attr_entry(void /*RzBinJavaLocalVariableTypeAttribute*/ *lvattr);
RZ_API void rz_bin_java_free_local_variable_type_table_attr(void /*RzBinJavaAttrInfo*/ *attr);
RZ_API void rz_bin_java_free_signature_attr(void /*RzBinJavaAttrInfo*/ *attr);
RZ_API void rz_bin_java_free_source_debug_attr(void /*RzBinJavaAttrInfo*/ *attr);
RZ_API void rz_bin_java_free_element_value(void /*RzBinJavaElementValue*/ *element_value);
RZ_API void rz_bin_java_free_element_pair(void /*RzBinJavaElementValuePair*/ *evp);
RZ_API void rz_bin_java_free_annotation(void /*RzBinJavaAnnotation*/ *annotation);
RZ_API void rz_bin_java_free_rtv_annotations_attr(void /*RzBinJavaAttrInfo*/ *attr);
RZ_API void rz_bin_java_free_rti_annotations_attr(void /*RzBinJavaAttrInfo*/ *attr);
RZ_API void rz_bin_java_free_annotation_array(void /*RzBinJavaAnnotationsArray*/ *annotation_array);
RZ_API void rz_bin_java_free_bootstrap_methods_attr(void /*RzBinJavaAttrInfo*/ *attr);
RZ_API void rz_bin_java_free_bootstrap_method(void /*RzBinJavaBootStrapMethod*/ *bsm);
RZ_API void rz_bin_java_free_bootstrap_method_argument(void /*RzBinJavaBootStrapArgument*/ *bsm_arg);
RZ_API void rz_bin_java_free_rtvp_annotations_attr(void /*RzBinJavaAttrInfo*/ *attr);
RZ_API void rz_bin_java_free_rtip_annotations_attr(void /*RzBinJavaAttrInfo*/ *attr);
RZ_API void rz_bin_java_free_unknown_attr(void /*RzBinJavaAttrInfo*/ *attr);
RZ_API void rz_bin_java_free_code_attr(void /*RzBinJavaAttrInfo*/ *attr);
RZ_API void rz_bin_java_free_constant_value_attr(void /*RzBinJavaAttrInfo*/ *attr);
RZ_API void rz_bin_java_free_deprecated_attr(void /*RzBinJavaAttrInfo*/ *attr);
RZ_API void rz_bin_java_free_exceptions_attr(void /*RzBinJavaAttrInfo*/ *attr);
RZ_API void rz_bin_java_free_inner_classes_attr(void /*RzBinJavaAttrInfo*/ *attr);
RZ_API void rz_bin_java_free_line_number_table_attr(void /*RzBinJavaAttrInfo*/ *attr);
RZ_API void rz_bin_java_free_local_variable_table_attr(void /*RzBinJavaAttrInfo*/ *attr);
RZ_API void rz_bin_java_free_source_code_file_attr(void /*RzBinJavaAttrInfo*/ *attr);
RZ_API void rz_bin_java_free_synthetic_attr(void /*RzBinJavaAttrInfo*/ *attr);

RZ_API void rz_bin_java_free_attribute(void /*RzBinJavaAttrInfo*/ *attr);
RZ_API void rz_bin_java_constant_pool(void /*RzBinJavaCPTypeObj*/ *obj);
RZ_API RzBinJavaAttrInfo *rz_bin_java_read_next_attr_from_buffer(RzBinJavaObj *bin, ut8 *buffer, st64 sz, st64 buf_offset);
RZ_API RzBinJavaAttrInfo *rz_bin_java_new_unknown_attr(RzBinJavaObj *bin, ut8 *buf, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAttrInfo *rz_bin_java_new_annotation_default_attr(RzBinJavaObj *bin, ut8 *buf, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAttrInfo *rz_bin_java_new_enclosing_methods_attr(RzBinJavaObj *bin, ut8 *buf, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAttrInfo *rz_bin_java_new_local_variable_type_table_attr(RzBinJavaObj *bin, ut8 *buf, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAttrInfo *rz_bin_java_new_signature_attr(RzBinJavaObj *bin, ut8 *buf, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAttrInfo *rz_bin_java_new_source_debug_attr(RzBinJavaObj *bin, ut8 *buf, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAttrInfo *rz_bin_java_new_bootstrap_methods_attr(RzBinJavaObj *bin, ut8 *buf, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAttrInfo *rz_bin_java_new_rtv_annotations_attr(RzBinJavaObj *bin, ut8 *buf, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAttrInfo *rz_bin_java_new_rti_annotations_attr(RzBinJavaObj *bin, ut8 *buf, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAttrInfo *rz_bin_java_new_rtvp_annotations_attr(RzBinJavaObj *bin, ut8 *buf, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAttrInfo *rz_bin_java_new_rtip_annotations_attr(RzBinJavaObj *bin, ut8 *buf, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAttrInfo *rz_bin_java_new_code_attr(RzBinJavaObj *bin, ut8 *buf, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAttrInfo *rz_bin_java_new_constant_value_attr(RzBinJavaObj *bin, ut8 *buf, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAttrInfo *rz_bin_java_new_deprecated_attr(RzBinJavaObj *bin, ut8 *buf, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAttrInfo *rz_bin_java_new_exceptions_attr(RzBinJavaObj *bin, ut8 *buf, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAttrInfo *rz_bin_java_new_inner_classes_attr(RzBinJavaObj *bin, ut8 *buf, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAttrInfo *rz_bin_java_new_line_number_table_attr(RzBinJavaObj *bin, ut8 *buf, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAttrInfo *rz_bin_java_new_local_variable_table_attr(RzBinJavaObj *bin, ut8 *buf, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAttrInfo *rz_bin_java_new_source_code_file_attr(RzBinJavaObj *bin, ut8 *buf, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAttrInfo *rz_bin_java_new_stack_map_table_attr(RzBinJavaObj *bin, ut8 *buf, ut64 sz, ut64 buf_offset);
RZ_API RzBinJavaAttrInfo *rz_bin_java_new_synthetic_attr(RzBinJavaObj *bin, ut8 *buf, ut64 sz, ut64 buf_offset);
RZ_API ut64 rz_bin_java_calc_size_unknown_attr(RzBinJavaAttrInfo *attr);
RZ_API ut64 rz_bin_java_calc_size_annotation_default_attr(RzBinJavaAttrInfo *attr);
RZ_API ut64 rz_bin_java_calc_size_enclosing_methods_attr(RzBinJavaAttrInfo *attr);
RZ_API ut64 rz_bin_java_calc_size_local_variable_type_table_attr(RzBinJavaAttrInfo *attr);
RZ_API ut64 rz_bin_java_calc_size_signature_attr(RzBinJavaAttrInfo *attr);
RZ_API ut64 rz_bin_java_calc_size_source_debug_attr(RzBinJavaAttrInfo *attr);
RZ_API ut64 rz_bin_java_calc_size_bootstrap_methods_attr(RzBinJavaAttrInfo *attr);
RZ_API ut64 rz_bin_java_calc_size_rtv_annotations_attr(RzBinJavaAttrInfo *attr);
RZ_API ut64 rz_bin_java_calc_size_rti_annotations_attr(RzBinJavaAttrInfo *attr);
RZ_API ut64 rz_bin_java_calc_size_rtvp_annotations_attr(RzBinJavaAttrInfo *attr);
RZ_API ut64 rz_bin_java_calc_size_rtip_annotations_attr(RzBinJavaAttrInfo *attr);
RZ_API ut64 rz_bin_java_calc_size_code_attr(RzBinJavaAttrInfo *attr);
RZ_API ut64 rz_bin_java_calc_size_constant_value_attr(RzBinJavaAttrInfo *attr);
RZ_API ut64 rz_bin_java_calc_size_deprecated_attr(RzBinJavaAttrInfo *attr);
RZ_API ut64 rz_bin_java_calc_size_exceptions_attr(RzBinJavaAttrInfo *attr);
RZ_API ut64 rz_bin_java_calc_size_inner_classes_attr(RzBinJavaAttrInfo *attr);
RZ_API ut64 rz_bin_java_calc_size_line_number_table_attr(RzBinJavaAttrInfo *attr);
RZ_API ut64 rz_bin_java_calc_size_local_variable_table_attr(RzBinJavaAttrInfo *attr);
RZ_API ut64 rz_bin_java_calc_size_source_code_file_attr(RzBinJavaAttrInfo *attr);
RZ_API ut64 rz_bin_java_calc_size_stack_map_table_attr(RzBinJavaAttrInfo *attr);
RZ_API ut64 rz_bin_java_calc_size_synthetic_attr(RzBinJavaAttrInfo *attr);
RZ_API ut64 rz_bin_java_calc_size_bootstrap_method(RzBinJavaBootStrapMethod *bsm);
RZ_API ut64 rz_bin_java_calc_size_element_pair(RzBinJavaElementValuePair *evp);
RZ_API ut64 rz_bin_java_calc_size_element_value(RzBinJavaElementValue *element_value);

RZ_API ut64 rz_bin_java_calc_size_unknown_cp(RzBinJavaCPTypeObj *obj);
RZ_API ut64 rz_bin_java_calc_size_class_cp(RzBinJavaCPTypeObj *obj);
RZ_API ut64 rz_bin_java_calc_size_fieldref_cp(RzBinJavaCPTypeObj *obj);
RZ_API ut64 rz_bin_java_calc_size_methodref_cp(RzBinJavaCPTypeObj *obj);
RZ_API ut64 rz_bin_java_calc_size_interfacemethodref_cp(RzBinJavaCPTypeObj *obj);
RZ_API ut64 rz_bin_java_calc_size_name_and_type_cp(RzBinJavaCPTypeObj *obj);
RZ_API ut64 rz_bin_java_calc_size_string_cp(RzBinJavaCPTypeObj *obj);
RZ_API ut64 rz_bin_java_calc_size_integer_cp(RzBinJavaCPTypeObj *obj);
RZ_API ut64 rz_bin_java_calc_size_float_cp(RzBinJavaCPTypeObj *obj);
RZ_API ut64 rz_bin_java_calc_size_long_cp(RzBinJavaCPTypeObj *obj);
RZ_API ut64 rz_bin_java_calc_size_double_cp(RzBinJavaCPTypeObj *obj);
RZ_API ut64 rz_bin_java_calc_size_utf8_cp(RzBinJavaCPTypeObj *obj);
RZ_API ut64 rz_bin_java_calc_size_do_nothing(RzBinJavaCPTypeObj *obj);
RZ_API ut64 rz_bin_java_calc_size_methodhandle_cp(RzBinJavaCPTypeObj *obj);
RZ_API ut64 rz_bin_java_calc_size_methodtype_cp(RzBinJavaCPTypeObj *obj);
RZ_API ut64 rz_bin_java_calc_size_invokedynamic_cp(RzBinJavaCPTypeObj *obj);
RZ_API RzBinJavaStackMapFrame *rz_bin_java_default_stack_frame(void);

RZ_API RzList *rz_bin_java_find_cp_const_by_val_float(RzBinJavaObj *bin_obj, const ut8 *bytes, ut32 len);
RZ_API RzList *rz_bin_java_find_cp_const_by_val_double(RzBinJavaObj *bin_obj, const ut8 *bytes, ut32 len);
RZ_API RzList *rz_bin_java_find_cp_const_by_val_int(RzBinJavaObj *bin_obj, const ut8 *bytes, ut32 len);
RZ_API RzList *rz_bin_java_find_cp_const_by_val_long(RzBinJavaObj *bin_obj, const ut8 *bytes, ut32 len);
RZ_API RzList *rz_bin_java_find_cp_const_by_val_utf8(RzBinJavaObj *bin_obj, const ut8 *bytes, ut32 len);
RZ_API ut8 *rz_bin_java_cp_append_classref_and_name(RzBinJavaObj *bin, ut32 *out_sz, const char *classname, const ut32 classname_len);
RZ_API ut8 *rz_bin_java_cp_append_ref_cname_fname_ftype(RzBinJavaObj *bin, ut32 *out_sz, ut8 tag, const char *cname, const ut32 c_len, const char *fname, const ut32 f_len, const char *tname, const ut32 t_len);
RZ_API ut8 *rz_bin_java_cp_get_classref(RzBinJavaObj *bin, ut32 *out_sz, const char *classname, const ut32 classname_len, const ut16 name_idx);
RZ_API ut8 *rz_bin_java_cp_get_method_ref(RzBinJavaObj *bin, ut32 *out_sz, ut16 class_idx, ut16 name_and_type_idx);
RZ_API ut8 *rz_bin_java_cp_get_field_ref(RzBinJavaObj *bin, ut32 *out_sz, ut16 class_idx, ut16 name_and_type_idx);
RZ_API ut8 *rz_bin_java_cp_get_fm_ref(RzBinJavaObj *bin, ut32 *out_sz, ut8 tag, ut16 class_idx, ut16 name_and_type_idx);
RZ_API ut8 *rz_bin_java_cp_get_2_ut16(RzBinJavaObj *bin, ut32 *out_sz, ut8 tag, ut16 ut16_one, ut16 ut16_two);
RZ_API ut8 *rz_bin_java_cp_get_name_type(RzBinJavaObj *bin, ut32 *out_sz, ut16 name_idx, ut16 type_idx);

char *sanitize_string(const char *bytes, ut32 len) {
	char *buffer;
	rz_return_val_if_fail(bytes && len > 0 && (buffer = malloc(len + 1)), NULL);
	for (ut32 idx = 0; idx < len; idx++) {
		if (IS_PRINTABLE(bytes[idx])) {
			buffer[idx] = bytes[idx];
		} else {
			buffer[idx] = '?';
		}
	}
	buffer[len] = 0;
	return buffer;
}

// taken from LLVM Code Byte Swap
// TODO: move into rz_util
RZ_API ut32 rz_bin_java_swap_uint(ut32 x) {
	const ut32 Byte0 = x & 0x000000FF;
	const ut32 Byte1 = x & 0x0000FF00;
	const ut32 Byte2 = x & 0x00FF0000;
	const ut32 Byte3 = x & 0xFF000000;
	return (Byte0 << 24) | (Byte1 << 8) | (Byte2 >> 8) | (Byte3 >> 24);
}

static bool RZ_BIN_JAVA_NULL_TYPE_INITTED = false;
// XXX - this is a global variable used while parsing the class file
// this variable should DIE.
static RzBinJavaObj *RZ_BIN_JAVA_GLOBAL_BIN = NULL;
RzBinJavaAccessFlags FIELD_ACCESS_FLAGS[] = {
	{ "public", RZ_BIN_JAVA_FIELD_ACC_PUBLIC, 6 },
	{ "private", RZ_BIN_JAVA_FIELD_ACC_PRIVATE, 7 },
	{ "protected", RZ_BIN_JAVA_FIELD_ACC_PROTECTED, 9 },
	{ "static", RZ_BIN_JAVA_FIELD_ACC_STATIC, 6 },
	{ "final", RZ_BIN_JAVA_FIELD_ACC_FINAL, 5 },
	{ "undefined.0x0020", 0x0020, 16 },
	{ "volatile", RZ_BIN_JAVA_FIELD_ACC_VOLATILE, 8 },
	{ "transient", RZ_BIN_JAVA_FIELD_ACC_TRANSIENT, 9 },
	{ "undefined.0x0100", 0x0100, 16 },
	{ "undefined.0x0200", 0x0200, 16 },
	{ "undefined.0x0400", 0x0400, 16 },
	{ "undefined.0x0800", 0x0800, 16 },
	{ "synthetic", RZ_BIN_JAVA_FIELD_ACC_SYNTHETIC, 9 },
	{ "undefined.0x2000", 0x2000, 16 },
	{ "enum", RZ_BIN_JAVA_FIELD_ACC_ENUM, 16 },
	{ "undefined.0x8000", 0x8000, 16 },
	{ NULL, 0, 0 }
};
RzBinJavaAccessFlags METHOD_ACCESS_FLAGS[] = {
	{ "public", RZ_BIN_JAVA_METHOD_ACC_PUBLIC, 6 },
	{ "private", RZ_BIN_JAVA_METHOD_ACC_PRIVATE, 7 },
	{ "protected", RZ_BIN_JAVA_METHOD_ACC_PROTECTED, 9 },
	{ "static", RZ_BIN_JAVA_METHOD_ACC_STATIC, 6 },
	{ "final", RZ_BIN_JAVA_METHOD_ACC_FINAL, 5 },
	{ "synchronized", RZ_BIN_JAVA_METHOD_ACC_SYNCHRONIZED, 12 },
	{ "bridge", RZ_BIN_JAVA_METHOD_ACC_BRIDGE, 6 },
	{ "varargs", RZ_BIN_JAVA_METHOD_ACC_VARARGS, 7 },
	{ "native", RZ_BIN_JAVA_METHOD_ACC_NATIVE, 6 },
	{ "interface", RZ_BIN_JAVA_METHOD_ACC_INTERFACE, 9 },
	{ "abstract", RZ_BIN_JAVA_METHOD_ACC_ABSTRACT, 8 },
	{ "strict", RZ_BIN_JAVA_METHOD_ACC_STRICT, 6 },
	{ "synthetic", RZ_BIN_JAVA_METHOD_ACC_SYNTHETIC, 9 },
	{ "annotation", RZ_BIN_JAVA_METHOD_ACC_ANNOTATION, 10 },
	{ "enum", RZ_BIN_JAVA_METHOD_ACC_ENUM, 4 },
	{ "undefined.0x8000", 0x8000, 16 },
	{ NULL, 0, 0 }
};
// XXX - Fix these there are some incorrect ongs
RzBinJavaAccessFlags CLASS_ACCESS_FLAGS[] = {
	{ "public", RZ_BIN_JAVA_CLASS_ACC_PUBLIC, 6 },
	{ "undefined.0x0002", 0x0002, 16 },
	{ "undefined.0x0004", 0x0004, 16 },
	{ "undefined.0x0008", 0x0008, 16 },
	{ "final", RZ_BIN_JAVA_CLASS_ACC_FINAL, 5 },
	{ "super", RZ_BIN_JAVA_CLASS_ACC_SUPER, 5 },
	{ "undefined.0x0040", 0x0040, 16 },
	{ "undefined.0x0080", 0x0080, 16 },
	{ "undefined.0x0100", 0x0100, 16 },
	{ "interface", RZ_BIN_JAVA_CLASS_ACC_INTERFACE, 9 },
	{ "abstract", RZ_BIN_JAVA_CLASS_ACC_ABSTRACT, 8 },
	{ "undefined.0x0800", 0x0800, 16 },
	{ "synthetic", RZ_BIN_JAVA_CLASS_ACC_SYNTHETIC, 9 },
	{ "annotation", RZ_BIN_JAVA_CLASS_ACC_ANNOTATION, 10 },
	{ "enum", RZ_BIN_JAVA_CLASS_ACC_ENUM, 4 },
	{ "undefined.0x8000", 0x8000, 16 },
	{ NULL, 0, 0 }
};
RzBinJavaRefMetas RZ_BIN_JAVA_REF_METAS[] = {
	{ "Unknown", RZ_BIN_JAVA_REF_UNKNOWN },
	{ "GetField", RZ_BIN_JAVA_REF_GETFIELD },
	{ "GetStatic", RZ_BIN_JAVA_REF_GETSTATIC },
	{ "PutField", RZ_BIN_JAVA_REF_PUTFIELD },
	{ "PutStatic", RZ_BIN_JAVA_REF_PUTSTATIC },
	{ "InvokeVirtual", RZ_BIN_JAVA_REF_INVOKEVIRTUAL },
	{ "InvokeStatic", RZ_BIN_JAVA_REF_INVOKESTATIC },
	{ "InvokeSpecial", RZ_BIN_JAVA_REF_INVOKESPECIAL },
	{ "NewInvokeSpecial", RZ_BIN_JAVA_REF_NEWINVOKESPECIAL },
	{ "InvokeInterface", RZ_BIN_JAVA_REF_INVOKEINTERFACE }
};
static ut16 RZ_BIN_JAVA_ELEMENT_VALUE_METAS_SZ = 14;
RzBinJavaElementValueMetas RZ_BIN_JAVA_ELEMENT_VALUE_METAS[] = {
	{ "Byte", RZ_BIN_JAVA_EV_TAG_BYTE, NULL },
	{ "Char", RZ_BIN_JAVA_EV_TAG_CHAR, NULL },
	{ "Double", RZ_BIN_JAVA_EV_TAG_DOUBLE, NULL },
	{ "Float", RZ_BIN_JAVA_EV_TAG_FLOAT, NULL },
	{ "Integer", RZ_BIN_JAVA_EV_TAG_INT, NULL },
	{ "Long", RZ_BIN_JAVA_EV_TAG_LONG, NULL },
	{ "Short", RZ_BIN_JAVA_EV_TAG_SHORT, NULL },
	{ "Boolean", RZ_BIN_JAVA_EV_TAG_BOOLEAN, NULL },
	{ "Array of ", RZ_BIN_JAVA_EV_TAG_ARRAY, NULL },
	{ "String", RZ_BIN_JAVA_EV_TAG_STRING, NULL },
	{ "Enum", RZ_BIN_JAVA_EV_TAG_ENUM, NULL },
	{ "Class", RZ_BIN_JAVA_EV_TAG_CLASS, NULL },
	{ "Annotation", RZ_BIN_JAVA_EV_TAG_ANNOTATION, NULL },
	{ "Unknown", RZ_BIN_JAVA_EV_TAG_UNKNOWN, NULL },
};
RzBinJavaVerificationMetas RZ_BIN_JAVA_VERIFICATION_METAS[] = {
	{ "Top", RZ_BIN_JAVA_STACKMAP_TOP },
	{ "Integer", RZ_BIN_JAVA_STACKMAP_INTEGER },
	{ "Float", RZ_BIN_JAVA_STACKMAP_FLOAT },
	{ "Double", RZ_BIN_JAVA_STACKMAP_DOUBLE },
	{ "Long", RZ_BIN_JAVA_STACKMAP_LONG },
	{ "NULL", RZ_BIN_JAVA_STACKMAP_NULL },
	{ "This", RZ_BIN_JAVA_STACKMAP_THIS },
	{ "Object", RZ_BIN_JAVA_STACKMAP_OBJECT },
	{ "Uninitialized", RZ_BIN_JAVA_STACKMAP_UNINIT },
	{ "Unknown", RZ_BIN_JAVA_STACKMAP_UNKNOWN }
};
RzBinJavaStackMapFrameMetas RZ_BIN_JAVA_STACK_MAP_FRAME_METAS[] = {
	{ "ImplicitStackFrame", RZ_BIN_JAVA_STACK_FRAME_IMPLICIT, NULL },
	{ "Same", RZ_BIN_JAVA_STACK_FRAME_SAME, NULL },
	{ "SameLocals1StackItem", RZ_BIN_JAVA_STACK_FRAME_SAME_LOCALS_1, NULL },
	{ "Chop", RZ_BIN_JAVA_STACK_FRAME_CHOP, NULL },
	{ "SameFrameExtended", RZ_BIN_JAVA_STACK_FRAME_SAME_FRAME_EXTENDED, NULL },
	{ "Append", RZ_BIN_JAVA_STACK_FRAME_APPEND, NULL },
	{ "FullFrame", RZ_BIN_JAVA_STACK_FRAME_FULL_FRAME, NULL },
	{ "Reserved", RZ_BIN_JAVA_STACK_FRAME_RESERVED, NULL }
};

static RzBinJavaCPTypeObjectAllocs RZ_BIN_ALLOCS_CONSTANTS[] = {
	{ rz_bin_java_new_do_nothing, rz_bin_java_free_do_nothing, rz_bin_java_summary_cp_print_null, rz_bin_java_calc_size_do_nothing, rz_bin_java_stringify_cp_null },
	{ rz_bin_java_new_utf8_cp, rz_bin_java_free_utf8_info, rz_bin_java_summary_cp_print_utf8, rz_bin_java_calc_size_utf8_cp, rz_bin_java_stringify_cp_utf8 },
	{ rz_bin_java_new_unknown_cp, rz_bin_java_free_default, rz_bin_java_summary_cp_print_unknown, rz_bin_java_calc_size_unknown_cp, rz_bin_java_stringify_cp_unknown },
	{ rz_bin_java_new_integer_cp, rz_bin_java_free_default, rz_bin_java_summary_cp_print_integer, rz_bin_java_calc_size_integer_cp, rz_bin_java_stringify_cp_integer },
	{ rz_bin_java_new_float_cp, rz_bin_java_free_default, rz_bin_java_summary_cp_print_float, rz_bin_java_calc_size_float_cp, rz_bin_java_stringify_cp_float },
	{ rz_bin_java_new_long_cp, rz_bin_java_free_default, rz_bin_java_summary_cp_print_long, rz_bin_java_calc_size_long_cp, rz_bin_java_stringify_cp_long },
	{ rz_bin_java_new_double_cp, rz_bin_java_free_default, rz_bin_java_summary_cp_print_double, rz_bin_java_calc_size_double_cp, rz_bin_java_stringify_cp_double },
	{ rz_bin_java_new_class_cp, rz_bin_java_free_default, rz_bin_java_summary_cp_print_classref, rz_bin_java_calc_size_class_cp, rz_bin_java_stringify_cp_classref },
	{ rz_bin_java_new_string_cp, rz_bin_java_free_default, rz_bin_java_summary_cp_print_string, rz_bin_java_calc_size_string_cp, rz_bin_java_stringify_cp_string },
	{ rz_bin_java_new_fieldref_cp, rz_bin_java_free_default, rz_bin_java_summary_cp_print_fieldref, rz_bin_java_calc_size_fieldref_cp, rz_bin_java_stringify_cp_fieldref },
	{ rz_bin_java_new_methodref_cp, rz_bin_java_free_default, rz_bin_java_summary_cp_print_methodref, rz_bin_java_calc_size_methodref_cp, rz_bin_java_stringify_cp_methodref },
	{ rz_bin_java_new_interfacemethodref_cp, rz_bin_java_free_default, rz_bin_java_summary_cp_print_interfacemethodref, rz_bin_java_calc_size_interfacemethodref_cp, rz_bin_java_stringify_cp_interfacemethodref },
	{ rz_bin_java_new_name_and_type_cp, rz_bin_java_free_default, rz_bin_java_summary_cp_print_name_and_type, rz_bin_java_calc_size_name_and_type_cp, rz_bin_java_stringify_cp_name_and_type },
	{ NULL, NULL, NULL, NULL, NULL },
	{ NULL, NULL, NULL, NULL, NULL },
	{ rz_bin_java_new_methodhandle_cp, rz_bin_java_free_default, rz_bin_java_summary_cp_print_methodhandle, rz_bin_java_calc_size_methodhandle_cp, rz_bin_java_stringify_cp_methodhandle },
	{ rz_bin_java_new_methodtype_cp, rz_bin_java_free_default, rz_bin_java_summary_cp_print_methodtype, rz_bin_java_calc_size_methodtype_cp, rz_bin_java_stringify_cp_methodtype },
	{ NULL, NULL, NULL, NULL, NULL },
	{ rz_bin_java_new_invokedynamic_cp, rz_bin_java_free_default, rz_bin_java_summary_cp_print_invokedynamic, rz_bin_java_calc_size_invokedynamic_cp, rz_bin_java_stringify_cp_invokedynamic },
};
static RzBinJavaCPTypeObj RZ_BIN_JAVA_NULL_TYPE;
static ut8 RZ_BIN_JAVA_CP_METAS_SZ = 12;
static RzBinJavaCPTypeMetas RZ_BIN_JAVA_CP_METAS[] = {
	// Each field has a name pointer and a tag field
	{ "NULL", RZ_BIN_JAVA_CP_NULL, 0, &RZ_BIN_ALLOCS_CONSTANTS[0] },
	{ "Utf8", RZ_BIN_JAVA_CP_UTF8, 3, &RZ_BIN_ALLOCS_CONSTANTS[1] }, // 2 bytes = length, N bytes string (containts a pointer in the field)
	{ "Unknown", RZ_BIN_JAVA_CP_UNKNOWN, 0, &RZ_BIN_ALLOCS_CONSTANTS[2] },
	{ "Integer", RZ_BIN_JAVA_CP_INTEGER, 5, &RZ_BIN_ALLOCS_CONSTANTS[3] }, // 4 bytes
	{ "Float", RZ_BIN_JAVA_CP_FLOAT, 5, &RZ_BIN_ALLOCS_CONSTANTS[4] }, // 4 bytes
	{ "Long", RZ_BIN_JAVA_CP_LONG, 9, &RZ_BIN_ALLOCS_CONSTANTS[5] }, // 4 high 4 low
	{ "Double", RZ_BIN_JAVA_CP_DOUBLE, 9, &RZ_BIN_ALLOCS_CONSTANTS[6] }, // 4 high 4 low
	{ "Class", RZ_BIN_JAVA_CP_CLASS, 3, &RZ_BIN_ALLOCS_CONSTANTS[7] }, // 2 name_idx
	{ "String", RZ_BIN_JAVA_CP_STRING, 3, &RZ_BIN_ALLOCS_CONSTANTS[8] }, // 2 string_idx
	{ "FieldRef", RZ_BIN_JAVA_CP_FIELDREF, 5, &RZ_BIN_ALLOCS_CONSTANTS[9] }, // 2 class idx, 2 name/type_idx
	{ "MethodRef", RZ_BIN_JAVA_CP_METHODREF, 5, &RZ_BIN_ALLOCS_CONSTANTS[10] }, // 2 class idx, 2 name/type_idx
	{ "InterfaceMethodRef", RZ_BIN_JAVA_CP_INTERFACEMETHOD_REF, 5, &RZ_BIN_ALLOCS_CONSTANTS[11] }, // 2 class idx, 2 name/type_idx
	{ "NameAndType", RZ_BIN_JAVA_CP_NAMEANDTYPE, 5, &RZ_BIN_ALLOCS_CONSTANTS[12] }, // 4 high 4 low
	{ "Unknown", RZ_BIN_JAVA_CP_UNKNOWN, 0, &RZ_BIN_ALLOCS_CONSTANTS[2] },
	{ "Unknown", RZ_BIN_JAVA_CP_UNKNOWN, 0, &RZ_BIN_ALLOCS_CONSTANTS[2] },
	{ "MethodHandle", RZ_BIN_JAVA_CP_METHODHANDLE, 4, &RZ_BIN_ALLOCS_CONSTANTS[15] }, // 4 high 4 low
	{ "MethodType", RZ_BIN_JAVA_CP_METHODTYPE, 3, &RZ_BIN_ALLOCS_CONSTANTS[16] }, // 4 high 4 low
	{ "Unknown", RZ_BIN_JAVA_CP_UNKNOWN, 0, &RZ_BIN_ALLOCS_CONSTANTS[2] },
	{ "InvokeDynamic", RZ_BIN_JAVA_CP_INVOKEDYNAMIC, 5, &RZ_BIN_ALLOCS_CONSTANTS[18] }, // 4 high 4 low
};
static RzBinJavaAttrInfoObjectAllocs RBIN_JAVA_ATTRS_ALLOCS[] = {
	{ rz_bin_java_new_annotation_default_attr, rz_bin_java_free_annotation_default_attr, rz_bin_java_summary_print_annotation_default_attr, rz_bin_java_calc_size_annotation_default_attr },
	{ rz_bin_java_new_bootstrap_methods_attr, rz_bin_java_free_bootstrap_methods_attr, rz_bin_java_summary_print_bootstrap_methods_attr, rz_bin_java_calc_size_bootstrap_methods_attr },
	{ rz_bin_java_new_code_attr, rz_bin_java_free_code_attr, rz_bin_java_summary_print_code_attr, rz_bin_java_calc_size_code_attr },
	{ rz_bin_java_new_constant_value_attr, rz_bin_java_free_constant_value_attr, rz_bin_java_summary_print_constant_value_attr, rz_bin_java_calc_size_constant_value_attr },
	{ rz_bin_java_new_deprecated_attr, rz_bin_java_free_deprecated_attr, rz_bin_java_summary_print_deprecated_attr, rz_bin_java_calc_size_deprecated_attr },
	{ rz_bin_java_new_enclosing_methods_attr, rz_bin_java_free_enclosing_methods_attr, rz_bin_java_summary_print_enclosing_methods_attr, rz_bin_java_calc_size_enclosing_methods_attr },
	{ rz_bin_java_new_exceptions_attr, rz_bin_java_free_exceptions_attr, rz_bin_java_summary_print_exceptions_attr, rz_bin_java_calc_size_exceptions_attr },
	{ rz_bin_java_new_inner_classes_attr, rz_bin_java_free_inner_classes_attr, rz_bin_java_summary_print_inner_classes_attr, rz_bin_java_calc_size_inner_classes_attr },
	{ rz_bin_java_new_line_number_table_attr, rz_bin_java_free_line_number_table_attr, rz_bin_java_summary_print_line_number_table_attr, rz_bin_java_calc_size_line_number_table_attr },
	{ rz_bin_java_new_local_variable_table_attr, rz_bin_java_free_local_variable_table_attr, rz_bin_java_summary_print_local_variable_table_attr, rz_bin_java_calc_size_local_variable_table_attr },
	{ rz_bin_java_new_local_variable_type_table_attr, rz_bin_java_free_local_variable_type_table_attr, rz_bin_java_summary_print_local_variable_type_table_attr, rz_bin_java_calc_size_local_variable_type_table_attr },
	{ rz_bin_java_new_rti_annotations_attr, rz_bin_java_free_rti_annotations_attr, rz_bin_java_summary_print_rti_annotations_attr, rz_bin_java_calc_size_rti_annotations_attr },
	{ rz_bin_java_new_rtip_annotations_attr, rz_bin_java_free_rtip_annotations_attr, rz_bin_java_summary_print_rtip_annotations_attr, rz_bin_java_calc_size_rtip_annotations_attr },
	{ rz_bin_java_new_rtv_annotations_attr, rz_bin_java_free_rtv_annotations_attr, rz_bin_java_summary_print_rtv_annotations_attr, rz_bin_java_calc_size_rtv_annotations_attr },
	{ rz_bin_java_new_rtvp_annotations_attr, rz_bin_java_free_rtvp_annotations_attr, rz_bin_java_summary_print_rtvp_annotations_attr, rz_bin_java_calc_size_rtvp_annotations_attr },
	{ rz_bin_java_new_signature_attr, rz_bin_java_free_signature_attr, rz_bin_java_summary_print_signature_attr, rz_bin_java_calc_size_signature_attr },
	{ rz_bin_java_new_source_debug_attr, rz_bin_java_free_source_debug_attr, rz_bin_java_summary_print_source_debug_attr, rz_bin_java_calc_size_source_debug_attr },
	{ rz_bin_java_new_source_code_file_attr, rz_bin_java_free_source_code_file_attr, rz_bin_java_summary_print_source_code_file_attr, rz_bin_java_calc_size_source_code_file_attr },
	{ rz_bin_java_new_stack_map_table_attr, rz_bin_java_free_stack_map_table_attr, rz_bin_java_summary_print_stack_map_table_attr, rz_bin_java_calc_size_stack_map_table_attr },
	{ rz_bin_java_new_synthetic_attr, rz_bin_java_free_synthetic_attr, rz_bin_java_summary_print_synthetic_attr, rz_bin_java_calc_size_synthetic_attr },
	{ rz_bin_java_new_unknown_attr, rz_bin_java_free_unknown_attr, rz_bin_java_summary_print_unknown_attr, rz_bin_java_calc_size_unknown_attr }
};
// RZ_API ut32 RBIN_JAVA_ATTRS_METAS_SZ = 21;
static ut32 RBIN_JAVA_ATTRS_METAS_SZ = 20;
static RzBinJavaAttrMetas RBIN_JAVA_ATTRS_METAS[] = {
	{ "AnnotationDefault", RZ_BIN_JAVA_ATTRIBUTE_ANNOTATION_DEFAULT_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[0] },
	{ "BootstrapMethods", RZ_BIN_JAVA_ATTRIBUTE_BOOTSTRAP_METHODS_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[1] },
	{ "Code", RZ_BIN_JAVA_ATTRIBUTE_CODE_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[2] },
	{ "ConstantValue", RZ_BIN_JAVA_ATTRIBUTE_CONST_VALUE_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[3] },
	{ "Deperecated", RZ_BIN_JAVA_ATTRIBUTE_DEPRECATED_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[4] },
	{ "EnclosingMethod", RZ_BIN_JAVA_ATTRIBUTE_ENCLOSING_METHOD_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[5] },
	{ "Exceptions", RZ_BIN_JAVA_ATTRIBUTE_EXCEPTIONS_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[6] },
	{ "InnerClasses", RZ_BIN_JAVA_ATTRIBUTE_INNER_CLASSES_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[7] },
	{ "LineNumberTable", RZ_BIN_JAVA_ATTRIBUTE_LINE_NUMBER_TABLE_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[8] },
	{ "LocalVariableTable", RZ_BIN_JAVA_ATTRIBUTE_LOCAL_VARIABLE_TABLE_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[9] },
	{ "LocalVariableTypeTable", RZ_BIN_JAVA_ATTRIBUTE_LOCAL_VARIABLE_TYPE_TABLE_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[10] },
	{ "RuntimeInvisibleAnnotations", RZ_BIN_JAVA_ATTRIBUTE_RUNTIME_INVISIBLE_ANNOTATION_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[11] },
	{ "RuntimeInvisibleParameterAnnotations", RZ_BIN_JAVA_ATTRIBUTE_RUNTIME_INVISIBLE_PARAMETER_ANNOTATION_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[12] },
	{ "RuntimeVisibleAnnotations", RZ_BIN_JAVA_ATTRIBUTE_RUNTIME_VISIBLE_ANNOTATION_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[13] },
	{ "RuntimeVisibleParameterAnnotations", RZ_BIN_JAVA_ATTRIBUTE_RUNTIME_VISIBLE_PARAMETER_ANNOTATION_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[14] },
	{ "Signature", RZ_BIN_JAVA_ATTRIBUTE_SIGNATURE_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[15] },
	{ "SourceDebugExtension", RZ_BIN_JAVA_ATTRIBUTE_SOURCE_DEBUG_EXTENTSION_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[16] },
	{ "SourceFile", RZ_BIN_JAVA_ATTRIBUTE_SOURCE_FILE_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[17] },
	{ "StackMapTable", RZ_BIN_JAVA_ATTRIBUTE_STACK_MAP_TABLE_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[18] },
	// { "StackMap", RZ_BIN_JAVA_ATTRIBUTE_STACK_MAP_TABLE_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[18]},
	{ "Synthetic", RZ_BIN_JAVA_ATTRIBUTE_SYNTHETIC_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[19] },
	{ "Unknown", RZ_BIN_JAVA_ATTRIBUTE_UNKNOWN_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[20] }
};

RZ_API bool rz_bin_java_is_old_format(RzBinJavaObj *bin) {
	return bin->cf.major[1] == 45 && bin->cf.minor[1] <= 2;
}

RZ_API void rz_bin_java_reset_bin_info(RzBinJavaObj *bin) {
	free(bin->cf2.flags_str);
	free(bin->cf2.this_class_name);
	rz_list_free(bin->imports_list);
	rz_list_free(bin->methods_list);
	rz_list_free(bin->fields_list);
	rz_list_free(bin->attrs_list);
	rz_list_free(bin->cp_list);
	rz_list_free(bin->interfaces_list);
	rz_str_constpool_fini(&bin->constpool);
	memset(bin, 0, sizeof(RzBinJavaObj));
	rz_str_constpool_init(&bin->constpool);
	bin->cf2.flags_str = strdup("unknown");
	bin->cf2.this_class_name = strdup("unknown");
	bin->imports_list = rz_list_newf(free);
	bin->methods_list = rz_list_newf(rz_bin_java_free_fmtype);
	bin->fields_list = rz_list_newf(rz_bin_java_free_fmtype);
	bin->attrs_list = rz_list_newf(rz_bin_java_free_attribute);
	bin->cp_list = rz_list_newf(rz_bin_java_constant_pool);
	bin->interfaces_list = rz_list_newf(rz_bin_java_free_interface);
}

RZ_API char *rz_bin_java_unmangle_method(const char *flags, const char *name, const char *params, const char *rz_value) {
	RzList *the_list = params ? rz_bin_java_extract_type_values(params) : rz_list_new();
	RzListIter *iter = NULL;
	// second case removes leading space if no flags are given
	const char *fmt = flags ? "%s %s %s (%s)" : "%s%s %s (%s)";
	char *str = NULL, *f_val_str = NULL, *rz_val_str = NULL, *prototype = NULL, *p_val_str = NULL;
	ut32 params_idx = 0, params_len = 0, prototype_len = 0;
	if (!extract_type_value(rz_value, &rz_val_str)) {
		rz_list_free(the_list);
		return NULL;
	}
	if (!rz_val_str) {
		rz_val_str = strdup("UNKNOWN");
	}
	f_val_str = strdup(flags ? flags : "");
	rz_list_foreach (the_list, iter, str) {
		params_len += strlen(str);
		if (params_idx > 0) {
			params_len += 2;
		}
		params_idx++;
	}
	if (params_len > 0) {
		ut32 offset = 0;
		params_len += 1;
		p_val_str = malloc(params_len);
		rz_list_foreach (the_list, iter, str) {
			if (offset != 0) {
				offset += snprintf(p_val_str + offset, params_len - offset, ", %s", str);
			} else {
				offset += snprintf(p_val_str + offset, params_len - offset, "%s", str);
			}
		}
	} else {
		p_val_str = strdup("");
	}

	prototype_len += (flags ? strlen(flags) + 1 : 0); // space vs no space
	prototype_len += strlen(name) + 1; // name + space
	prototype_len += strlen(rz_val_str) + 1; // rz_value + space
	prototype_len += strlen(p_val_str) + 3; // space + l_paren + params + rz_paren
	prototype_len += 1; // null
	prototype = malloc(prototype_len);
	/// TODO enable this function and start using it to demangle strings
	snprintf(prototype, prototype_len, fmt, f_val_str, rz_val_str, name, p_val_str);
	free(f_val_str);
	free(rz_val_str);
	free(p_val_str);
	rz_list_free(the_list);
	return prototype;
}

RZ_API char *rz_bin_java_unmangle(const char *flags, const char *name, const char *descriptor) {
	ut32 l_paren_pos = -1, rz_paren_pos = -1;
	char *result = NULL;
	ut32 desc_len = descriptor && *descriptor ? strlen(descriptor) : 0,
	     name_len = name && *name ? strlen(name) : 0,
	     flags_len = flags && *flags ? strlen(flags) : 0,
	     i = 0;
	if (desc_len == 0 || name == 0) {
		return NULL;
	}
	for (i = 0; i < desc_len; i++) {
		if (descriptor[i] == '(') {
			l_paren_pos = i;
		} else if (l_paren_pos != (ut32)-1 && descriptor[i] == ')') {
			rz_paren_pos = i;
			break;
		}
	}
	// handle field case;
	if (l_paren_pos == (ut32)-1 && rz_paren_pos == (ut32)-1) {
		char *unmangle_field_desc = NULL;
		ut32 len = extract_type_value(descriptor, &unmangle_field_desc);
		if (len == 0) {
			eprintf("Warning: attempting to unmangle invalid type descriptor.\n");
			free(unmangle_field_desc);
			return result;
		}
		if (flags_len > 0) {
			len += (flags_len + name_len + 5); // space and null
			result = malloc(len);
			snprintf(result, len, "%s %s %s", flags, unmangle_field_desc, name);
		} else {
			len += (name_len + 5); // space and null
			result = malloc(len);
			snprintf(result, len, "%s %s", unmangle_field_desc, name);
		}
		free(unmangle_field_desc);
	} else if (l_paren_pos != (ut32)-1 &&
		rz_paren_pos != (ut32)-1 &&
		l_paren_pos < rz_paren_pos) {
		// params_len account for l_paren + 1 and null
		ut32 params_len = rz_paren_pos - (l_paren_pos + 1) != 0 ? rz_paren_pos - (l_paren_pos + 1) + 1 : 0;
		char *params = params_len ? malloc(params_len) : NULL;
		const char *rvalue = descriptor + rz_paren_pos + 1;
		if (params) {
			snprintf(params, params_len, "%s", descriptor + l_paren_pos + 1);
		}
		result = rz_bin_java_unmangle_method(flags, name, params, rvalue);
		free(params);
	}
	return result;
}

RZ_API char *rz_bin_java_create_method_fq_str(const char *klass, const char *name, const char *signature) {
	if (!klass) {
		klass = "null_class";
	}
	if (!name) {
		name = "null_name";
	}
	if (!signature) {
		signature = "null_signature";
	}
	return rz_str_newf("%s.%s.%s", klass, name, signature);
}

RZ_API char *rz_bin_java_create_field_fq_str(const char *klass, const char *name, const char *signature) {
	if (!klass) {
		klass = "null_class";
	}
	if (!name) {
		name = "null_name";
	}
	if (!signature) {
		signature = "null_signature";
	}
	return rz_str_newf("%s %s.%s", signature, klass, name);
}

RZ_API bool rz_bin_java_get_fm_type_definition_json(RzBinJavaObj *bin, RzBinJavaField *fm_type, int is_method, PJ *j) {
	rz_return_val_if_fail(bin && fm_type && j, false);

	ut64 addr = UT64_MAX;
	ut64 load = UT64_MAX;
	char *prototype = NULL, *fq_name = NULL;
	const char *class_name, *signature, *name;
	bool is_native = ((fm_type->flags & RZ_BIN_JAVA_METHOD_ACC_NATIVE) != 0);
	bool is_static = ((fm_type->flags & RZ_BIN_JAVA_METHOD_ACC_STATIC) != 0);
	bool is_synthetic = ((fm_type->flags & RZ_BIN_JAVA_METHOD_ACC_SYNTHETIC) != 0);
	bool is_private = ((fm_type->flags & RZ_BIN_JAVA_METHOD_ACC_PRIVATE) != 0);
	bool is_public = ((fm_type->flags & RZ_BIN_JAVA_METHOD_ACC_PUBLIC) != 0);
	bool is_protected = ((fm_type->flags & RZ_BIN_JAVA_METHOD_ACC_PROTECTED) != 0);
	bool is_super = ((fm_type->flags & RZ_BIN_JAVA_CLASS_ACC_SUPER) != 0);

	pj_o(j);
	pj_kN(j, "access_flags", fm_type->flags);
	pj_kb(j, "is_method", is_method);
	pj_kb(j, "is_native", is_native);
	pj_kb(j, "is_synthetic", is_synthetic);
	pj_kb(j, "is_private", is_private);
	pj_kb(j, "is_public", is_public);
	pj_kb(j, "is_static", is_static);
	pj_kb(j, "is_protected", is_protected);
	pj_kb(j, "is_super", is_super);

	addr = rz_bin_java_get_method_code_offset(fm_type);
	if (addr == 0) {
		addr = fm_type->file_offset;
	}
	addr += bin->loadaddr;
	load = fm_type->file_offset + bin->loadaddr;

	class_name = fm_type->class_name ? fm_type->class_name : "";
	signature = fm_type->descriptor ? fm_type->descriptor : "";
	name = fm_type->name ? fm_type->name : "";

	pj_kn(j, "addr", addr);
	pj_kn(j, "offset", load);
	pj_ks(j, "class_name", class_name);
	pj_ks(j, "signature", signature);
	pj_ks(j, "name", name);

	if (is_method) {
		fq_name = rz_bin_java_create_method_fq_str(class_name, name, signature);
	} else {
		fq_name = rz_bin_java_create_field_fq_str(class_name, name, signature);
	}
	pj_ks(j, "fq_name", fq_name);
	free(fq_name);

	prototype = rz_bin_java_unmangle(fm_type->flags_str, name, signature);
	pj_ks(j, "prototype", prototype);
	free(prototype);
	pj_end(j);
	return true;
}

RZ_API char *rz_bin_java_get_method_definition(RzBinJavaField *fm_type) {
	return rz_bin_java_unmangle(fm_type->flags_str, fm_type->name, fm_type->descriptor);
}

RZ_API char *rz_bin_java_get_field_definition(RzBinJavaField *fm_type) {
	return rz_bin_java_unmangle(fm_type->flags_str, fm_type->name, fm_type->descriptor);
}

RZ_API bool rz_bin_java_get_method_json_definition(RzBinJavaObj *bin, RzBinJavaField *fm_type, PJ *j) {
	return rz_bin_java_get_fm_type_definition_json(bin, fm_type, 1, j);
}

RZ_API bool rz_bin_java_get_field_json_definition(RzBinJavaObj *bin, RzBinJavaField *fm_type, PJ *j) {
	return rz_bin_java_get_fm_type_definition_json(bin, fm_type, 0, j);
}

RZ_API int rz_bin_java_extract_reference_name(const char *input_str, char **ref_str, ut8 array_cnt) {
	char *new_str = NULL;
	ut32 str_len = array_cnt ? (array_cnt + 1) * 2 : 0;
	const char *str_pos = input_str;
	int consumed = 0, len = 0;
	if (!str_pos || *str_pos != 'L' || !*str_pos) {
		return -1;
	}
	consumed++;
	str_pos++;
	while (*str_pos && *str_pos != ';') {
		str_pos++;
		len++;
		consumed++;
	}
	str_pos = input_str + 1;
	free(*ref_str);
	str_len += len;
	*ref_str = malloc(str_len + 1);
	new_str = *ref_str;
	memcpy(new_str, str_pos, str_len);
	new_str[str_len] = 0;
	while (*new_str) {
		if (*new_str == '/') {
			*new_str = '.';
		}
		new_str++;
	}
	return len + 2;
}

RZ_API void UNUSED_FUNCTION(rz_bin_java_print_prototypes)(RzBinJavaObj *bin) {
	RzList *the_list = rz_bin_java_get_method_definitions(bin);
	RzListIter *iter;
	char *str;
	rz_list_foreach (the_list, iter, str) {
		eprintf("%s;\n", str);
	}
	rz_list_free(the_list);
}

RZ_API char *get_type_value_str(const char *arg_str, ut8 array_cnt) {
	ut32 str_len = array_cnt ? (array_cnt + 1) * 2 + strlen(arg_str) : strlen(arg_str);
	char *str = malloc(str_len + 1);
	ut32 bytes_written = snprintf(str, str_len + 1, "%s", arg_str);
	while (array_cnt > 0) {
		strcpy(str + bytes_written, "[]");
		bytes_written += 2;
		array_cnt--;
	}
	return str;
}

RZ_API int extract_type_value(const char *arg_str, char **output) {
	ut8 found_one = 0, array_cnt = 0;
	ut32 len = 0, consumed = 0;
	char *str = NULL;
	if (!arg_str || !output) {
		return 0;
	}
	if (output && *output && *output != NULL) {
		RZ_FREE(*output);
	}
	while (arg_str && *arg_str && !found_one) {
		len = 1;
		// handle the end of an object
		switch (*arg_str) {
		case 'V':
			str = get_type_value_str("void", array_cnt);
			break;
		case 'J':
			str = get_type_value_str("long", array_cnt);
			array_cnt = 0;
			break;
		case 'I':
			str = get_type_value_str("int", array_cnt);
			array_cnt = 0;
			break;
		case 'D':
			str = get_type_value_str("double", array_cnt);
			array_cnt = 0;
			break;
		case 'F':
			str = get_type_value_str("float", array_cnt);
			array_cnt = 0;
			break;
		case 'B':
			str = get_type_value_str("byte", array_cnt);
			array_cnt = 0;
			break;
		case 'C':
			str = get_type_value_str("char", array_cnt);
			array_cnt = 0;
			break;
		case 'Z':
			str = get_type_value_str("boolean", array_cnt);
			array_cnt = 0;
			break;
		case 'S':
			str = get_type_value_str("short", array_cnt);
			array_cnt = 0;
			break;
		case '[':
			array_cnt++;
			break;
		case 'L':
			len = rz_bin_java_extract_reference_name(arg_str, &str, array_cnt);
			array_cnt = 0;
			break;
		case '(':
			str = strdup("(");
			break;
		case ')':
			str = strdup(")");
			break;
		default:
			return 0;
		}
		if (len < 1) {
			break;
		}
		consumed += len;
		arg_str += len;
		if (str) {
			*output = str;
			break;
		}
	}
	return consumed;
}

RZ_API RzList *rz_bin_java_extract_type_values(const char *arg_str) {
	RzList *list_args = rz_list_new();
	if (!list_args) {
		return NULL;
	}
	char *str = NULL;
	const char *str_cur_pos = NULL;
	ut32 len = 0;
	if (!arg_str) {
		return list_args;
	}
	str_cur_pos = arg_str;
	list_args->free = free;
	while (str_cur_pos && *str_cur_pos) {
		// handle the end of an object
		len = extract_type_value(str_cur_pos, &str);
		if (len < 1) {
			rz_list_free(list_args);
			return NULL;
		}
		str_cur_pos += len;
		rz_list_append(list_args, str);
		str = NULL;
	}
	return list_args;
}

RZ_API int rz_bin_java_is_fm_type_private(RzBinJavaField *fm_type) {
	if (fm_type && fm_type->type == RZ_BIN_JAVA_FIELD_TYPE_METHOD) {
		return fm_type->flags & RZ_BIN_JAVA_METHOD_ACC_PRIVATE;
	}
	if (fm_type && fm_type->type == RZ_BIN_JAVA_FIELD_TYPE_FIELD) {
		return fm_type->flags & RZ_BIN_JAVA_FIELD_ACC_PRIVATE;
	}
	return 0;
}

RZ_API int rz_bin_java_is_fm_type_protected(RzBinJavaField *fm_type) {
	if (fm_type && fm_type->type == RZ_BIN_JAVA_FIELD_TYPE_METHOD) {
		return fm_type->flags & RZ_BIN_JAVA_METHOD_ACC_PROTECTED;
	}
	if (fm_type && fm_type->type == RZ_BIN_JAVA_FIELD_TYPE_FIELD) {
		return fm_type->flags & RZ_BIN_JAVA_FIELD_ACC_PROTECTED;
	}
	return 0;
}

RZ_API RzList *rz_bin_java_get_args(RzBinJavaField *fm_type) {
	RzList *the_list = rz_bin_java_extract_type_values(fm_type->descriptor);
	RzList *arg_list = rz_list_new();
	ut8 in_args = 0;
	RzListIter *desc_iter;
	char *str;
	rz_list_foreach (the_list, desc_iter, str) {
		if (str && *str == '(') {
			in_args = 1;
			continue;
		}
		if (str && *str == ')') {
			break;
		}
		if (in_args && str) {
			rz_list_append(arg_list, strdup(str));
		}
	}
	rz_list_free(the_list);
	return arg_list;
}

RZ_API RzList *rz_bin_java_get_ret(RzBinJavaField *fm_type) {
	RzList *the_list = rz_bin_java_extract_type_values(fm_type->descriptor);
	RzList *ret_list = rz_list_new();
	ut8 in_ret = 0;
	RzListIter *desc_iter;
	char *str;
	rz_list_foreach (the_list, desc_iter, str) {
		if (str && *str != ')') {
			in_ret = 0;
		}
		if (in_ret) {
			rz_list_append(ret_list, strdup(str));
		}
	}
	rz_list_free(the_list);
	return ret_list;
}

RZ_API char *rz_bin_java_get_this_class_name(RzBinJavaObj *bin) {
	return (bin->cf2.this_class_name ? strdup(bin->cf2.this_class_name) : strdup("unknown"));
}

RZ_API ut16 calculate_access_value(const char *access_flags_str, RzBinJavaAccessFlags *access_flags) {
	ut16 result = 0;
	ut16 size = strlen(access_flags_str) + 1;
	char *p_flags, *my_flags = malloc(size);
	RzBinJavaAccessFlags *iter = NULL;
	if (size < 5 || !my_flags) {
		free(my_flags);
		return result;
	}
	memcpy(my_flags, access_flags_str, size);
	p_flags = strtok(my_flags, " ");
	while (p_flags && access_flags) {
		int idx = 0;
		do {
			iter = &access_flags[idx];
			if (!iter || !iter->str) {
				continue;
			}
			if (iter->len > 0 && iter->len != 16) {
				if (!strncmp(iter->str, p_flags, iter->len)) {
					result |= iter->value;
				}
			}
			idx++;
		} while (access_flags[idx].str != NULL);
		p_flags = strtok(NULL, " ");
	}
	free(my_flags);
	return result;
}

RZ_API RzList *retrieve_all_access_string_and_value(RzBinJavaAccessFlags *access_flags) {
	const char *fmt = "%s = 0x%04x";
	RzList *result = rz_list_new();
	if (!result) {
		return NULL;
	}
	result->free = free;
	int i = 0;
	for (i = 0; access_flags[i].str != NULL; i++) {
		char *str = malloc(50);
		if (!str) {
			rz_list_free(result);
			return NULL;
		}
		snprintf(str, 49, fmt, access_flags[i].str, access_flags[i].value);
		rz_list_append(result, str);
	}
	return result;
}

RZ_API char *retrieve_access_string(ut16 flags, RzBinJavaAccessFlags *access_flags) {
	char *outbuffer = NULL, *cur_pos = NULL;
	ut16 i;
	ut16 max_str_len = 0;
	for (i = 0; access_flags[i].str != NULL; i++) {
		if (flags & access_flags[i].value) {
			max_str_len += (strlen(access_flags[i].str) + 1);
			if (max_str_len < strlen(access_flags[i].str)) {
				return NULL;
			}
		}
	}
	max_str_len++;
	outbuffer = (char *)malloc(max_str_len);
	if (outbuffer) {
		memset(outbuffer, 0, max_str_len);
		cur_pos = outbuffer;
		for (i = 0; access_flags[i].str != NULL; i++) {
			if (flags & access_flags[i].value) {
				ut8 len = strlen(access_flags[i].str);
				const char *the_string = access_flags[i].str;
				memcpy(cur_pos, the_string, len);
				memcpy(cur_pos + len, " ", 1);
				cur_pos += len + 1;
			}
		}
		if (cur_pos != outbuffer) {
			*(cur_pos - 1) = 0;
		}
	}
	return outbuffer;
}

RZ_API char *retrieve_method_access_string(ut16 flags) {
	return retrieve_access_string(flags, METHOD_ACCESS_FLAGS);
}

RZ_API char *retrieve_field_access_string(ut16 flags) {
	return retrieve_access_string(flags, FIELD_ACCESS_FLAGS);
}

RZ_API char *retrieve_class_method_access_string(ut16 flags) {
	return retrieve_access_string(flags, CLASS_ACCESS_FLAGS);
}

RZ_API char *rz_bin_java_build_obj_key(RzBinJavaObj *bin) {
	char *jvcname = NULL;
	char *cname = rz_bin_java_get_this_class_name(bin);
	ut32 class_name_len = cname ? strlen(cname) : strlen("_unknown_");
	jvcname = malloc(class_name_len + 8 + 30);
	if (cname) {
		snprintf(jvcname, class_name_len + 30, "%d.%s.class", bin->id, cname);
		free(cname);
	} else {
		snprintf(jvcname, class_name_len + 30, "%d._unknown_.class", bin->id);
	}
	return jvcname;
}

RZ_API bool sdb_iterate_build_list(void *user, const char *k, const char *v) {
	RzList *bin_objs_list = (RzList *)user;
	size_t value = (size_t)sdb_atoi(v);
	RzBinJavaObj *bin_obj = NULL;
	// eprintf("Found %s == %" PFMT64x " bin_objs db\n", k, (ut64)value);
	if (value != 0 && value != (size_t)-1) {
		bin_obj = (RzBinJavaObj *)value;
		rz_list_append(bin_objs_list, bin_obj);
	}
	return true;
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_get_java_null_cp(void) {
	if (RZ_BIN_JAVA_NULL_TYPE_INITTED) {
		return &RZ_BIN_JAVA_NULL_TYPE;
	}
	memset(&RZ_BIN_JAVA_NULL_TYPE, 0, sizeof(RZ_BIN_JAVA_NULL_TYPE));
	RZ_BIN_JAVA_NULL_TYPE.metas = RZ_NEW0(RzBinJavaMetaInfo);
	if (!RZ_BIN_JAVA_NULL_TYPE.metas) {
		return NULL;
	}
	memset(RZ_BIN_JAVA_NULL_TYPE.metas, 0, sizeof(RzBinJavaMetaInfo));
	RZ_BIN_JAVA_NULL_TYPE.metas->type_info = &RZ_BIN_JAVA_CP_METAS[0];
	RZ_BIN_JAVA_NULL_TYPE.metas->ord = 0;
	RZ_BIN_JAVA_NULL_TYPE.file_offset = 0;
	RZ_BIN_JAVA_NULL_TYPE_INITTED = true;
	return &RZ_BIN_JAVA_NULL_TYPE;
}

RZ_API RzBinJavaElementValueMetas *rz_bin_java_get_ev_meta_from_tag(ut8 tag) {
	ut16 i = 0;
	RzBinJavaElementValueMetas *res = &RZ_BIN_JAVA_ELEMENT_VALUE_METAS[13];
	for (i = 0; i < RZ_BIN_JAVA_ELEMENT_VALUE_METAS_SZ; i++) {
		if (tag == RZ_BIN_JAVA_ELEMENT_VALUE_METAS[i].tag) {
			res = &RZ_BIN_JAVA_ELEMENT_VALUE_METAS[i];
			break;
		}
	}
	return res;
}

RZ_API ut8 rz_bin_java_quick_check(ut8 expected_tag, ut8 actual_tag, ut32 actual_len, const char *name) {
	ut8 res = 0;
	if (expected_tag > RZ_BIN_JAVA_CP_METAS_SZ) {
		eprintf("Invalid tag '%d' expected 0x%02x for %s.\n", actual_tag, expected_tag, name);
		res = 1;
	} else if (expected_tag != actual_tag) {
		eprintf("Invalid tag '%d' expected 0x%02x for %s.\n", actual_tag, expected_tag, name);
		res = 1;
	} else if (actual_len < RZ_BIN_JAVA_CP_METAS[expected_tag].len) {
		eprintf("Unable to parse '%d' expected sz=0x%02x got 0x%02x for %s.\n",
			actual_tag, RZ_BIN_JAVA_CP_METAS[expected_tag].len, actual_len, name);
		res = 2;
	}
	return res;
}

RZ_API RzBinJavaField *rz_bin_java_read_next_method(RzBinJavaObj *bin, const ut64 offset, const ut8 *buf, const ut64 len) {
	ut32 i, idx;
	const ut8 *f_buf = buf + offset;
	ut64 adv = 0;
	RzBinJavaCPTypeObj *item = NULL;
	if (!bin || offset + 8 >= len) {
		return NULL;
	}
	RzBinJavaField *method = (RzBinJavaField *)RZ_NEW0(RzBinJavaField);
	if (!method) {
		eprintf("Unable to allocate memory for method information\n");
		return NULL;
	}
	method->metas = (RzBinJavaMetaInfo *)RZ_NEW0(RzBinJavaMetaInfo);
	if (!method->metas) {
		eprintf("Unable to allocate memory for meta information\n");
		free(method);
		return NULL;
	}
	method->file_offset = offset;
	method->flags = rz_read_at_be16(f_buf, 0);
	method->flags_str = retrieve_method_access_string(method->flags);
	// need to subtract 1 for the idx
	method->name_idx = rz_read_at_be16(f_buf, 2);
	method->descriptor_idx = rz_read_at_be16(f_buf, 4);
	method->attr_count = rz_read_at_be16(f_buf, 6);
	method->attributes = rz_list_newf(rz_bin_java_free_attribute);
	method->type = RZ_BIN_JAVA_FIELD_TYPE_METHOD;
	method->metas->ord = bin->method_idx;
	adv += 8;
	idx = method->name_idx;
	rz_bin_java_get_item_from_bin_cp_list(bin, idx);
	method->name = rz_bin_java_get_utf8_from_bin_cp_list(bin, (ut32)(method->name_idx));
	// eprintf("Method name_idx: %d, which is: ord: %d, name: %s, value: %s\n", idx, item->metas->ord, ((RzBinJavaCPTypeMetas *)item->metas->type_info)->name, method->name);
	if (!method->name) {
		method->name = (char *)malloc(21);
		snprintf((char *)method->name, 20, "sym.method_%08x", method->metas->ord);
		// eprintf("rz_bin_java_read_next_method: Unable to find the name for 0x%02x index.\n", method->name_idx);
	}
	idx = method->descriptor_idx;
	rz_bin_java_get_item_from_bin_cp_list(bin, idx);
	method->descriptor = rz_bin_java_get_utf8_from_bin_cp_list(bin, (ut32)method->descriptor_idx);
	// eprintf("Method descriptor_idx: %d, which is: ord: %d, name: %s, value: %s\n", idx, item->metas->ord, ((RzBinJavaCPTypeMetas *)item->metas->type_info)->name, method->descriptor);
	if (!method->descriptor) {
		method->descriptor = rz_str_dup(NULL, "NULL");
		// eprintf("rz_bin_java_read_next_method: Unable to find the descriptor for 0x%02x index.\n", method->descriptor_idx);
	}
	// eprintf("Looking for a NameAndType CP with name_idx: %d descriptor_idx: %d\n", method->name_idx, method->descriptor_idx);
	method->field_ref_cp_obj = rz_bin_java_find_cp_ref_info_from_name_and_type(bin, method->name_idx, method->descriptor_idx);
	if (method->field_ref_cp_obj) {
		// eprintf("Found the obj.\n");
		item = rz_bin_java_get_item_from_bin_cp_list(bin, method->field_ref_cp_obj->info.cp_method.class_idx);
		// eprintf("Method class reference value: %d, which is: ord: %d, name: %s\n", method->field_ref_cp_obj->info.cp_method.class_idx, item->metas->ord, ((RzBinJavaCPTypeMetas *)item->metas->type_info)->name);
		method->class_name = rz_bin_java_get_item_name_from_bin_cp_list(bin, item);
		// eprintf("Method requesting ref_cp_obj the following which is: ord: %d, name: %s\n", method->field_ref_cp_obj->metas->ord, ((RzBinJavaCPTypeMetas *)method->field_ref_cp_obj->metas->type_info)->name);
		// eprintf("MethodRef class name resolves to: %s\n", method->class_name);
		if (!method->class_name) {
			method->class_name = rz_str_dup(NULL, "NULL");
		}
	} else {
		// XXX - default to this class?
		method->field_ref_cp_obj = rz_bin_java_get_item_from_bin_cp_list(bin, bin->cf2.this_class);
		method->class_name = rz_bin_java_get_item_name_from_bin_cp_list(bin, method->field_ref_cp_obj);
	}
	// eprintf("Parsing %s(%s)\n", method->name, method->descriptor);
	if (method->attr_count > 0) {
		method->attr_offset = adv + offset;
		RzBinJavaAttrInfo *attr = NULL;
		for (i = 0; i < method->attr_count; i++) {
			attr = rz_bin_java_read_next_attr(bin, adv + offset, buf, len);
			if (!attr) {
				eprintf("[X] rz_bin_java: Error unable to parse remainder of classfile after Method Attribute: %d.\n", i);
				break;
			}
			if ((rz_bin_java_get_attr_type_by_name(attr->name))->type == RZ_BIN_JAVA_ATTRIBUTE_CODE_ATTR) {
				// This is necessary for determing the appropriate number of bytes when readin
				// uoffset, ustack, ulocalvar values
				bin->cur_method_code_length = attr->info.code_attr.code_length;
				bin->offset_sz = 2; // (attr->info.code_attr.code_length > 65535) ? 4 : 2;
				bin->ustack_sz = 2; // (attr->info.code_attr.max_stack > 65535) ? 4 : 2;
				bin->ulocalvar_sz = 2; // (attr->info.code_attr.max_locals > 65535) ? 4 : 2;
			}
			// eprintf("Parsing @ 0x%" PFMT64x " (%s) = 0x%" PFMT64x " bytes\n", attr->file_offset, attr->name, attr->size);
			rz_list_append(method->attributes, attr);
			adv += attr->size;
			if (adv + offset >= len) {
				eprintf("[X] rz_bin_java: Error unable to parse remainder of classfile after Method Attribute: %d.\n", i);
				break;
			}
		}
	}
	method->size = adv;
	// reset after parsing the method attributes
	// eprintf("Parsing @ 0x%" PFMT64x " %s(%s) = 0x%" PFMT64x " bytes\n", method->file_offset, method->name, method->descriptor, method->size);
	return method;
}

RZ_API RzBinJavaField *rz_bin_java_read_next_field(RzBinJavaObj *bin, const ut64 offset, const ut8 *buffer, const ut64 len) {
	RzBinJavaAttrInfo *attr;
	ut32 i, idx;
	ut8 buf[8];
	RzBinJavaCPTypeObj *item = NULL;
	const ut8 *f_buf = buffer + offset;
	ut64 adv = 0;
	if (!bin || offset + 8 >= len) {
		return NULL;
	}
	RzBinJavaField *field = (RzBinJavaField *)RZ_NEW0(RzBinJavaField);
	if (!field) {
		eprintf("Unable to allocate memory for field information\n");
		return NULL;
	}
	field->metas = (RzBinJavaMetaInfo *)RZ_NEW0(RzBinJavaMetaInfo);
	if (!field->metas) {
		eprintf("Unable to allocate memory for meta information\n");
		free(field);
		return NULL;
	}
	memcpy(buf, f_buf, 8);
	field->file_offset = offset;
	field->flags = rz_read_at_be16(buf, 0);
	field->flags_str = retrieve_field_access_string(field->flags);
	field->name_idx = rz_read_at_be16(buf, 2);
	field->descriptor_idx = rz_read_at_be16(buf, 4);
	field->attr_count = rz_read_at_be16(buf, 6);
	field->attributes = rz_list_newf(rz_bin_java_free_attribute);
	field->type = RZ_BIN_JAVA_FIELD_TYPE_FIELD;
	adv += 8;
	field->metas->ord = bin->field_idx;

	idx = field->name_idx;
	rz_bin_java_get_item_from_bin_cp_list(bin, idx);
	field->name = rz_bin_java_get_utf8_from_bin_cp_list(bin, (ut32)(field->name_idx));
	// eprintf("Field name_idx: %d, which is: ord: %d, name: %s, value: %s\n", idx, item->metas->ord, ((RzBinJavaCPTypeMetas *)item->metas->type_info)->name, field->name);
	if (!field->name) {
		field->name = (char *)malloc(21);
		snprintf((char *)field->name, 20, "sym.field_%08x", field->metas->ord);
		// eprintf("rz_bin_java_read_next_field: Unable to find the name for 0x%02x index.\n", field->name_idx);
	}
	idx = field->descriptor_idx;
	rz_bin_java_get_item_from_bin_cp_list(bin, idx);
	field->descriptor = rz_bin_java_get_utf8_from_bin_cp_list(bin, (ut32)field->descriptor_idx);
	// eprintf("Field descriptor_idx: %d, which is: ord: %d, name: %s, value: %s\n", idx, item->metas->ord, ((RzBinJavaCPTypeMetas *)item->metas->type_info)->name, field->descriptor);
	if (!field->descriptor) {
		field->descriptor = rz_str_dup(NULL, "NULL");
		// eprintf("rz_bin_java_read_next_field: Unable to find the descriptor for 0x%02x index.\n", field->descriptor_idx);
	}
	// eprintf("Looking for a NameAndType CP with name_idx: %d descriptor_idx: %d\n", field->name_idx, field->descriptor_idx);
	field->field_ref_cp_obj = rz_bin_java_find_cp_ref_info_from_name_and_type(bin, field->name_idx, field->descriptor_idx);
	if (field->field_ref_cp_obj) {
		// eprintf("Found the obj.\n");
		item = rz_bin_java_get_item_from_bin_cp_list(bin, field->field_ref_cp_obj->info.cp_field.class_idx);
		// eprintf("Field class reference value: %d, which is: ord: %d, name: %s\n", field->field_ref_cp_obj->info.cp_field.class_idx, item->metas->ord, ((RzBinJavaCPTypeMetas *)item->metas->type_info)->name);
		field->class_name = rz_bin_java_get_item_name_from_bin_cp_list(bin, item);
		// eprintf("Field requesting ref_cp_obj the following which is: ord: %d, name: %s\n", field->field_ref_cp_obj->metas->ord, ((RzBinJavaCPTypeMetas *)field->field_ref_cp_obj->metas->type_info)->name);
		// eprintf("FieldRef class name resolves to: %s\n", field->class_name);
		if (!field->class_name) {
			field->class_name = rz_str_dup(NULL, "NULL");
		}
	} else {
		// XXX - default to this class?
		field->field_ref_cp_obj = rz_bin_java_get_item_from_bin_cp_list(bin, bin->cf2.this_class);
		field->class_name = rz_bin_java_get_item_name_from_bin_cp_list(bin, field->field_ref_cp_obj);
	}
	// eprintf("Parsing %s(%s)", field->name, field->descriptor);
	if (field->attr_count > 0) {
		field->attr_offset = adv + offset;
		for (i = 0; i < field->attr_count && offset + adv < len; i++) {
			attr = rz_bin_java_read_next_attr(bin, offset + adv, buffer, len);
			if (!attr) {
				eprintf("[X] rz_bin_java: Error unable to parse remainder of classfile after Field Attribute: %d.\n", i);
				free(field->metas);
				free(field);
				return NULL;
			}
			if ((rz_bin_java_get_attr_type_by_name(attr->name))->type == RZ_BIN_JAVA_ATTRIBUTE_CODE_ATTR) {
				// This is necessary for determing the appropriate number of bytes when readin
				// uoffset, ustack, ulocalvar values
				bin->cur_method_code_length = attr->info.code_attr.code_length;
				bin->offset_sz = 2; // (attr->info.code_attr.code_length > 65535) ? 4 : 2;
				bin->ustack_sz = 2; // (attr->info.code_attr.max_stack > 65535) ? 4 : 2;
				bin->ulocalvar_sz = 2; // (attr->info.code_attr.max_locals > 65535) ? 4 : 2;
			}
			rz_list_append(field->attributes, attr);
			adv += attr->size;
			if (adv + offset >= len) {
				eprintf("[X] rz_bin_java: Error unable to parse remainder of classfile after Field Attribute: %d.\n", i);
				rz_bin_java_free_fmtype(field);
				return NULL;
			}
		}
	}
	field->size = adv;
	return field;
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_clone_cp_idx(RzBinJavaObj *bin, ut32 idx) {
	RzBinJavaCPTypeObj *obj = NULL;
	if (bin) {
		obj = rz_bin_java_get_item_from_bin_cp_list(bin, idx);
	}
	return rz_bin_java_clone_cp_item(obj);
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_clone_cp_item(RzBinJavaCPTypeObj *obj) {
	RzBinJavaCPTypeObj *clone_obj = NULL;
	if (obj == NULL) {
		return clone_obj;
	}
	clone_obj = RZ_NEW0(RzBinJavaCPTypeObj);
	if (clone_obj) {
		memcpy(clone_obj, obj, sizeof(RzBinJavaCPTypeObj));
		clone_obj->metas = (RzBinJavaMetaInfo *)RZ_NEW0(RzBinJavaMetaInfo);
		clone_obj->metas->type_info = (void *)&RZ_BIN_JAVA_CP_METAS[clone_obj->tag];
		clone_obj->name = strdup(obj->name ? obj->name : "unk");
		if (obj->tag == RZ_BIN_JAVA_CP_UTF8) {
			clone_obj->info.cp_utf8.bytes = (ut8 *)malloc(obj->info.cp_utf8.length + 1);
			if (clone_obj->info.cp_utf8.bytes) {
				memcpy(clone_obj->info.cp_utf8.bytes, obj->info.cp_utf8.bytes, clone_obj->info.cp_utf8.length);
			} else {
				// TODO: eprintf allocation error
			}
		}
	}
	return clone_obj;
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_read_next_constant_pool_item(RzBinJavaObj *bin, const ut64 offset, const ut8 *buf, ut64 len) {
	RzBinJavaCPTypeMetas *java_constant_info = NULL;
	ut8 tag = 0;
	ut64 buf_sz = 0;
	ut8 *cp_buf = NULL;
	ut32 str_len = 0;
	RzBinJavaCPTypeObj *java_obj = NULL;
	tag = buf[offset];
	if (tag > RZ_BIN_JAVA_CP_METAS_SZ) {
		eprintf("Invalid tag '%d' at offset 0x%08" PFMT64x "\n", tag, (ut64)offset);
		return NULL;
	}
	java_constant_info = &RZ_BIN_JAVA_CP_METAS[tag];
	if (java_constant_info->tag == 0 || java_constant_info->tag == 2) {
		return java_obj;
	}
	buf_sz += java_constant_info->len;
	if (java_constant_info->tag == 1) {
		if (offset + 32 < len) {
			str_len = rz_read_at_be16(buf, offset + 1);
			buf_sz += str_len;
		} else {
			return NULL;
		}
	}
	cp_buf = calloc(buf_sz, 1);
	if (!cp_buf) {
		return java_obj;
	}
	if (offset + buf_sz < len) {
		memcpy(cp_buf, (ut8 *)buf + offset, buf_sz);
		// eprintf("Parsed the tag '%d':%s and create object from offset 0x%08" PFMT64x ".\n", tag, RZ_BIN_JAVA_CP_METAS[tag].name, offset);
		java_obj = (*java_constant_info->allocs->new_obj)(bin, cp_buf, buf_sz);
		if (java_obj != NULL && java_obj->metas != NULL) {
			java_obj->file_offset = offset;
			// // eprintf ("java_obj->file_offset = 0x%08"PFMT64x".\n",java_obj->file_offset);
		} else if (!java_obj) {
			eprintf("Unable to parse the tag '%d' and create valid object.\n", tag);
		} else if (!java_obj->metas) {
			eprintf("Unable to parse the tag '%d' and create valid object.\n", tag);
		} else {
			eprintf("Failed to set the java_obj->metas-file_offset for '%d' offset is(0x%08" PFMT64x ").\n", tag, offset);
		}
	}
	free(cp_buf);
	return java_obj;
}

RZ_API RzBinJavaInterfaceInfo *rz_bin_java_read_next_interface_item(RzBinJavaObj *bin, const ut64 offset, const ut8 *buf, const ut64 len) {
	ut8 idx[2] = {
		0
	};
	RzBinJavaInterfaceInfo *ifobj;
	const ut8 *if_buf = buf + offset;
	if (offset + 2 >= len) {
		return NULL;
	}
	memcpy(&idx, if_buf, 2);
	ifobj = rz_bin_java_new_interface(bin, if_buf, len - offset);
	if (ifobj) {
		ifobj->file_offset = offset;
	}
	return ifobj;
}

RZ_API char *rz_bin_java_get_utf8_from_bin_cp_list(RzBinJavaObj *bin, ut64 idx) {
	/*
	Search through the Constant Pool list for the given CP Index.
	If the idx not found by directly going to the list index,
	the list will be walked and then the IDX will be checked.
	rvalue: new char* for caller to free.
	*/
	if (bin == NULL) {
		return NULL;
	}
	return rz_bin_java_get_utf8_from_cp_item_list(bin->cp_list, idx);
}

RZ_API ut32 rz_bin_java_get_utf8_len_from_bin_cp_list(RzBinJavaObj *bin, ut64 idx) {
	/*
	Search through the Constant Pool list for the given CP Index.
	If the idx not found by directly going to the list index,
	the list will be walked and then the IDX will be checked.
	rvalue: new char* for caller to free.
	*/
	if (bin == NULL) {
		return 0;
	}
	return rz_bin_java_get_utf8_len_from_cp_item_list(bin->cp_list, idx);
}

RZ_API char *rz_bin_java_get_name_from_bin_cp_list(RzBinJavaObj *bin, ut64 idx) {
	/*
	Search through the Constant Pool list for the given CP Index.
	If the idx not found by directly going to the list index,
	the list will be walked and then the IDX will be checked.
	rvalue: new char* for caller to free.
	*/
	if (bin == NULL) {
		return NULL;
	}
	return rz_bin_java_get_name_from_cp_item_list(bin->cp_list, idx);
}

RZ_API char *rz_bin_java_get_desc_from_bin_cp_list(RzBinJavaObj *bin, ut64 idx) {
	/*
	Search through the Constant Pool list for the given CP Index.
	If the idx not found by directly going to the list index,
	the list will be walked and then the IDX will be checked.
	rvalue: new char* for caller to free.
	*/
	if (bin == NULL) {
		return NULL;
	}
	return rz_bin_java_get_desc_from_cp_item_list(bin->cp_list, idx);
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_get_item_from_bin_cp_list(RzBinJavaObj *bin, ut64 idx) {
	/*
	Search through the Constant Pool list for the given CP Index.
	If the idx not found by directly going to the list index,
	the list will be walked and then the IDX will be checked.
	rvalue: RzBinJavaObj* (user does NOT free).
	*/
	if (bin == NULL) {
		return NULL;
	}
	if (idx > bin->cp_count || idx == 0) {
		return rz_bin_java_get_java_null_cp();
	}
	return rz_bin_java_get_item_from_cp_item_list(bin->cp_list, idx);
}

RZ_API char *rz_bin_java_get_item_name_from_bin_cp_list(RzBinJavaObj *bin, RzBinJavaCPTypeObj *obj) {
	char *res = NULL;
	/*
	Given a constant poool object Class, FieldRef, MethodRef, or InterfaceMethodRef
	return the actual descriptor string.
	@param cp_list: RzList of RzBinJavaCPTypeObj *
	@param obj object to look up the name for
	@rvalue char* (user frees) or NULL
	*/
	if (bin && obj) {
		res = rz_bin_java_get_item_name_from_cp_item_list(
			bin->cp_list, obj, MAX_CPITEMS);
	}
	return res;
}

RZ_API char *rz_bin_java_get_item_desc_from_bin_cp_list(RzBinJavaObj *bin, RzBinJavaCPTypeObj *obj) {
	/*
	Given a constant poool object Class, FieldRef, MethodRef, or InterfaceMethodRef
	return the actual descriptor string.
	@param cp_list: RzList of RzBinJavaCPTypeObj *
	@param obj object to look up the name for
	@rvalue char* (user frees) or NULL
	*/
	return bin ? rz_bin_java_get_item_desc_from_cp_item_list(bin->cp_list, obj, MAX_CPITEMS) : NULL;
}

RZ_API char *rz_bin_java_get_utf8_from_cp_item_list(RzList *cp_list, ut64 idx) {
	/*
	Search through the Constant Pool list for the given CP Index.
	If the idx not found by directly going to the list index,
	the list will be walked and then the IDX will be checked.
	rvalue: new char* for caller to free.
	*/
	char *value = NULL;
	RzListIter *iter;
	if (!cp_list) {
		return NULL;
	}
	RzBinJavaCPTypeObj *item = (RzBinJavaCPTypeObj *)rz_list_get_n(cp_list, idx);
	if (item && item->tag == RZ_BIN_JAVA_CP_UTF8 && item->metas->ord == idx) {
		value = sanitize_string((const char *)item->info.cp_utf8.bytes, item->info.cp_utf8.length);
	}
	if (!value) {
		rz_list_foreach (cp_list, iter, item) {
			if (item && (item->tag == RZ_BIN_JAVA_CP_UTF8) && item->metas->ord == idx) {
				value = sanitize_string((const char *)item->info.cp_utf8.bytes, item->info.cp_utf8.length);
				break;
			}
		}
	}
	return value;
}

RZ_API ut32 rz_bin_java_get_utf8_len_from_cp_item_list(RzList *cp_list, ut64 idx) {
	/*
	Search through the Constant Pool list for the given CP Index.
	If the idx not found by directly going to the list index,
	the list will be walked and then the IDX will be checked.
	rvalue: new ut32 .
	*/
	ut32 value = -1;
	RzListIter *iter;
	if (!cp_list) {
		return 0;
	}
	RzBinJavaCPTypeObj *item = (RzBinJavaCPTypeObj *)rz_list_get_n(cp_list, idx);
	if (item && (item->tag == RZ_BIN_JAVA_CP_UTF8) && item->metas->ord == idx) {
		value = item->info.cp_utf8.length;
	}
	if (value == -1) {
		rz_list_foreach (cp_list, iter, item) {
			if (item && (item->tag == RZ_BIN_JAVA_CP_UTF8) && item->metas->ord == idx) {
				value = item->info.cp_utf8.length;
				break;
			}
		}
	}
	return value;
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_get_item_from_cp_item_list(RzList *cp_list, ut64 idx) {
	/*
	Search through the Constant Pool list for the given CP Index.
	rvalue: RzBinJavaObj *
	*/
	RzBinJavaCPTypeObj *item = NULL;
	if (cp_list == NULL) {
		return NULL;
	}
	item = (RzBinJavaCPTypeObj *)rz_list_get_n(cp_list, idx);
	return item;
}

RZ_API char *rz_bin_java_get_item_name_from_cp_item_list(RzList *cp_list, RzBinJavaCPTypeObj *obj, int depth) {
	/*
	Given a constant poool object Class, FieldRef, MethodRef, or InterfaceMethodRef
	return the actual descriptor string.
	@param cp_list: RzList of RzBinJavaCPTypeObj *
	@param obj object to look up the name for
	@rvalue ut8* (user frees) or NULL
	*/
	if (obj == NULL || cp_list == NULL || depth < 0) {
		return NULL;
	}
	switch (obj->tag) {
	case RZ_BIN_JAVA_CP_NAMEANDTYPE:
		return rz_bin_java_get_utf8_from_cp_item_list(
			cp_list, obj->info.cp_name_and_type.name_idx);
	case RZ_BIN_JAVA_CP_CLASS:
		return rz_bin_java_get_utf8_from_cp_item_list(
			cp_list, obj->info.cp_class.name_idx);
	// XXX - Probably not good form, but they are the same memory structure
	case RZ_BIN_JAVA_CP_FIELDREF:
	case RZ_BIN_JAVA_CP_INTERFACEMETHOD_REF:
	case RZ_BIN_JAVA_CP_METHODREF:
		obj = rz_bin_java_get_item_from_cp_item_list(
			cp_list, obj->info.cp_method.name_and_type_idx);
		return rz_bin_java_get_item_name_from_cp_item_list(
			cp_list, obj, depth - 1);
	default:
		return NULL;
	case 0:
		// eprintf("Invalid 0 tag in the constant pool\n");
		return NULL;
	}
	return NULL;
}

RZ_API char *rz_bin_java_get_name_from_cp_item_list(RzList *cp_list, ut64 idx) {
	/*
	Given a constant poool object Class, FieldRef, MethodRef, or InterfaceMethodRef
	return the actual descriptor string.
	@param cp_list: RzList of RzBinJavaCPTypeObj *
	@param obj object to look up the name for
	@rvalue ut8* (user frees) or NULL
	*/
	RzBinJavaCPTypeObj *obj = rz_bin_java_get_item_from_cp_item_list(
		cp_list, idx);
	if (obj && cp_list) {
		return rz_bin_java_get_item_name_from_cp_item_list(
			cp_list, obj, MAX_CPITEMS);
	}
	return NULL;
}

RZ_API char *rz_bin_java_get_item_desc_from_cp_item_list(RzList *cp_list, RzBinJavaCPTypeObj *obj, int depth) {
	/*
	Given a constant poool object FieldRef, MethodRef, or InterfaceMethodRef
	return the actual descriptor string.
	@rvalue ut8* (user frees) or NULL
	*/
	if (!obj || !cp_list || depth < 0) {
		return NULL;
	}
	switch (obj->tag) {
	case RZ_BIN_JAVA_CP_NAMEANDTYPE:
		return rz_bin_java_get_utf8_from_cp_item_list(cp_list,
			obj->info.cp_name_and_type.descriptor_idx);
	// XXX - Probably not good form, but they are the same memory structure
	case RZ_BIN_JAVA_CP_FIELDREF:
	case RZ_BIN_JAVA_CP_INTERFACEMETHOD_REF:
	case RZ_BIN_JAVA_CP_METHODREF:
		obj = rz_bin_java_get_item_from_cp_item_list(cp_list,
			obj->info.cp_method.name_and_type_idx);
		return rz_bin_java_get_item_desc_from_cp_item_list(
			cp_list, obj, depth - 1);
	default:
		return NULL;
	}
	return NULL;
}

RZ_API char *rz_bin_java_get_desc_from_cp_item_list(RzList *cp_list, ut64 idx) {
	/*
	Given a constant poool object FieldRef, MethodRef, or InterfaceMethodRef
	return the actual descriptor string.
	@rvalue ut8* (user frees) or NULL
	*/
	RzBinJavaCPTypeObj *obj = rz_bin_java_get_item_from_cp_item_list(cp_list, idx);
	if (cp_list == NULL) {
		return NULL;
	}
	return rz_bin_java_get_item_desc_from_cp_item_list(cp_list, obj, MAX_CPITEMS);
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_get_method_code_attribute(const RzBinJavaField *method) {
	/*
	Search through a methods attributes and return the code attr.
	rvalue: RzBinJavaAttrInfo* if found otherwise NULL.
	*/
	RzBinJavaAttrInfo *res = NULL, *attr = NULL;
	RzListIter *iter;
	if (method) {
		rz_list_foreach (method->attributes, iter, attr) {
			if (attr && (attr->type == RZ_BIN_JAVA_ATTRIBUTE_CODE_ATTR)) {
				res = attr;
				break;
			}
		}
	}
	return res;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_get_attr_from_field(RzBinJavaField *field, RzBinJavaAttributeType attr_type, ut32 pos) {
	/*
	Search through the Attribute list for the given type starting at position pos.
	rvalue: NULL or the first occurrence of attr_type after pos
	*/
	RzBinJavaAttrInfo *attr = NULL, *item;
	RzListIter *iter;
	ut32 i = 0;
	if (field) {
		rz_list_foreach (field->attributes, iter, item) {
			// Note the increment happens after the comparison
			if ((i++) >= pos) {
				if (item && (item->type == attr_type)) {
					attr = item;
					break;
				}
			}
		}
	}
	return attr;
}

RZ_API ut8 *rz_bin_java_get_attr_buf(RzBinJavaObj *bin, ut64 sz, const ut64 offset, const ut8 *buf, const ut64 len) {
	ut8 *attr_buf = NULL;
	int pending = len - offset;
	const ut8 *a_buf = offset + buf;
	attr_buf = (ut8 *)calloc(pending + 1, 1);
	if (attr_buf == NULL) {
		eprintf("Unable to allocate enough bytes (0x%04" PFMT64x
			") to read in the attribute.\n",
			sz);
		return attr_buf;
	}
	memcpy(attr_buf, a_buf, pending); // sz+1);
	return attr_buf;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_default_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	// NOTE: this function receives the buffer offset in the original buffer,
	// but the buffer is already point to that particular offset.
	// XXX - all the code that relies on this function should probably be modified
	// so that the original buffer pointer is passed in and then the buffer+buf_offset
	// points to the correct location.
	RzBinJavaAttrInfo *attr = RZ_NEW0(RzBinJavaAttrInfo);
	if (!attr) {
		return NULL;
	}
	RzBinJavaAttrMetas *type_info = NULL;
	attr->metas = RZ_NEW0(RzBinJavaMetaInfo);
	if (attr->metas == NULL) {
		free(attr);
		return NULL;
	}
	attr->is_attr_in_old_format = rz_bin_java_is_old_format(bin);
	attr->file_offset = buf_offset;
	attr->name_idx = rz_read_at_be16(buffer, 0);
	attr->length = rz_read_at_be32(buffer, 2);
	attr->size = rz_read_at_be32(buffer, 2) + 6;
	attr->name = rz_bin_java_get_utf8_from_bin_cp_list(RZ_BIN_JAVA_GLOBAL_BIN, attr->name_idx);
	if (attr->name == NULL) {
		// Something bad has happened
		attr->name = rz_str_dup(NULL, "NULL");
		eprintf("rz_bin_java_new_default_attr: Unable to find the name for %d index.\n", attr->name_idx);
	}
	type_info = rz_bin_java_get_attr_type_by_name(attr->name);
	attr->metas->ord = (RZ_BIN_JAVA_GLOBAL_BIN->attr_idx++);
	attr->metas->type_info = (void *)type_info;
	// // eprintf ("	Addrs for type_info [tag=%d]: 0x%08"PFMT64x"\n", type_val, &attr->metas->type_info);
	return attr;
}

RZ_API RzBinJavaAttrMetas *rz_bin_java_get_attr_type_by_name(const char *name) {
	// TODO: use sdb/hashtable here
	int i;
	for (i = 0; i < RBIN_JAVA_ATTRS_METAS_SZ; i++) {
		if (!strcmp((const char *)name, RBIN_JAVA_ATTRS_METAS[i].name)) {
			return &RBIN_JAVA_ATTRS_METAS[i];
		}
	}
	return &RBIN_JAVA_ATTRS_METAS[RZ_BIN_JAVA_ATTRIBUTE_UNKNOWN_ATTR];
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_read_next_attr(RzBinJavaObj *bin, const ut64 offset, const ut8 *buf, const ut64 buf_len) {
	RzBinJavaAttrInfo *attr = NULL;
	ut32 sz = 0;
	ut8 *buffer = NULL;
	const ut8 *a_buf = offset + buf;
	ut8 attr_idx_len = 6;
	if (offset + 6 > buf_len) {
		eprintf("[X] rz_bin_java: Error unable to parse remainder of classfile in Attribute offset "
			"(0x%" PFMT64x ") > len  of remaining bytes (0x%" PFMT64x ").\n",
			offset, buf_len);
		return NULL;
	}
	// ut16 attr_idx, ut32 length of attr.
	sz = rz_read_at_be32(a_buf, 2) + attr_idx_len; // rz_bin_java_read_int (bin, buf_offset+2) + attr_idx_len;
	if (sz + offset > buf_len) {
		eprintf("[X] rz_bin_java: Error unable to parse remainder of classfile in Attribute len "
			"(0x%x) + offset (0x%" PFMT64x ") exceeds length of buffer (0x%" PFMT64x ").\n",
			sz, offset, buf_len);
		return NULL;
	}
	// when reading the attr bytes, need to also
	// include the initial 6 bytes, which
	// are not included in the attribute length
	// ,
	// sz, buf_offset, buf_offset+sz);
	buffer = rz_bin_java_get_attr_buf(bin, sz, offset, buf, buf_len);
	// printf ("%d %d %d\n", sz, buf_len, offset);
	if (offset < buf_len) {
		attr = rz_bin_java_read_next_attr_from_buffer(bin, buffer, buf_len - offset, offset);
		free(buffer);

		if (!attr) {
			return NULL;
		}
		attr->size = sz;
	} else {
		free(buffer);
		eprintf("IS OOB\n");
	}
	return attr;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_read_next_attr_from_buffer(RzBinJavaObj *bin, ut8 *buffer, st64 sz, st64 buf_offset) {
	RzBinJavaAttrInfo *attr = NULL;
	ut64 offset = 0;
	ut16 name_idx;
	st64 nsz;

	if (!buffer || ((int)sz) < 4 || buf_offset < 0) {
		eprintf("rz_bin_Java_read_next_attr_from_buffer: invalid buffer size %d\n", (int)sz);
		return NULL;
	}
	name_idx = rz_read_at_be16(buffer, offset);
	offset += 2;
	nsz = rz_read_at_be32(buffer, offset);

	char *name = rz_bin_java_get_utf8_from_bin_cp_list(RZ_BIN_JAVA_GLOBAL_BIN, name_idx);
	if (!name) {
		name = strdup("unknown");
	}
	// eprintf("rz_bin_java_read_next_attr: name_idx = %d is %s\n", name_idx, name);
	RzBinJavaAttrMetas *type_info = rz_bin_java_get_attr_type_by_name(name);
	if (type_info) {
		// eprintf("Typeinfo: %s, was %s\n", type_info->name, name);
		if (nsz > sz) {
			free(name);
			return NULL;
		}
		if ((attr = type_info->allocs->new_obj(bin, buffer, nsz, buf_offset))) {
			attr->metas->ord = (RZ_BIN_JAVA_GLOBAL_BIN->attr_idx++);
		}
	} else {
		eprintf("rz_bin_java_read_next_attr_from_buffer: Cannot find type_info for %s\n", name);
	}
	free(name);
	return attr;
}

RZ_API ut64 rz_bin_java_read_class_file2(RzBinJavaObj *bin, const ut64 offset, const ut8 *obuf, ut64 len) {
	const ut8 *cf2_buf = obuf + offset;
	RzBinJavaCPTypeObj *this_class_cp_obj = NULL;
	// eprintf("\n0x%" PFMT64x " Offset before reading the cf2 structure\n", offset);
	/*
	Reading the following fields:
	ut16 access_flags;
	ut16 this_class;
	ut16 super_class;
	*/
	if (cf2_buf + 6 > obuf + len) {
		return 0;
	}
	bin->cf2.cf2_size = 6;
	bin->cf2.access_flags = rz_read_at_be16(cf2_buf, 0);
	bin->cf2.this_class = rz_read_at_be16(cf2_buf, 2);
	bin->cf2.super_class = rz_read_at_be16(cf2_buf, 4);
	free(bin->cf2.flags_str);
	free(bin->cf2.this_class_name);
	bin->cf2.flags_str = retrieve_class_method_access_string(bin->cf2.access_flags);
	this_class_cp_obj = rz_bin_java_get_item_from_bin_cp_list(bin, bin->cf2.this_class);
	bin->cf2.this_class_name = rz_bin_java_get_item_name_from_bin_cp_list(bin, this_class_cp_obj);
	// eprintf("This class flags are: %s\n", bin->cf2.flags_str);
	return bin->cf2.cf2_size;
}

RZ_API ut64 rz_bin_java_parse_cp_pool(RzBinJavaObj *bin, const ut64 offset, const ut8 *buf, const ut64 len) {
	int ord = 0;
	ut64 adv = 0;
	RzBinJavaCPTypeObj *obj = NULL;
	const ut8 *cp_buf = buf + offset;
	rz_list_free(bin->cp_list);
	bin->cp_list = rz_list_newf(rz_bin_java_constant_pool);
	bin->cp_offset = offset;
	memcpy((char *)&bin->cp_count, cp_buf, 2);
	bin->cp_count = rz_read_at_be16(cp_buf, 0) - 1;
	adv += 2;
	// eprintf("ConstantPoolCount %d\n", bin->cp_count);
	rz_list_append(bin->cp_list, rz_bin_java_get_java_null_cp());
	for (ord = 1, bin->cp_idx = 0; bin->cp_idx < bin->cp_count && adv < len; ord++, bin->cp_idx++) {
		obj = rz_bin_java_read_next_constant_pool_item(bin, offset + adv, buf, len);
		if (obj) {
			// // eprintf ("SUCCESS Read ConstantPoolItem %d\n", i);
			obj->metas->ord = ord;
			obj->idx = ord;
			rz_list_append(bin->cp_list, obj);
			if (obj->tag == RZ_BIN_JAVA_CP_LONG || obj->tag == RZ_BIN_JAVA_CP_DOUBLE) {
				// i++;
				ord++;
				bin->cp_idx++;
				rz_list_append(bin->cp_list, &RZ_BIN_JAVA_NULL_TYPE);
			}

			//((RzBinJavaCPTypeMetas *)obj->metas->type_info)->allocs->print_summary(obj);
			adv += ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->allocs->calc_size(obj);
			if (offset + adv > len) {
				eprintf("[X] rz_bin_java: Error unable to parse remainder of classfile after Constant Pool Object: %d.\n", ord);
				break;
			}
		} else {
			// eprintf("Failed to read ConstantPoolItem %d\n", bin->cp_idx);
			break;
		}
	}
	// Update the imports
	rz_bin_java_set_imports(bin);
	bin->cp_size = adv;
	return bin->cp_size;
}

RZ_API ut64 rz_bin_java_parse_interfaces(RzBinJavaObj *bin, const ut64 offset, const ut8 *buf, const ut64 len) {
	int i = 0;
	ut64 adv = 0;
	RzBinJavaInterfaceInfo *interfaces_obj;
	const ut8 *if_buf = buf + offset;
	bin->cp_offset = offset;
	bin->interfaces_offset = offset;
	rz_list_free(bin->interfaces_list);
	bin->interfaces_list = rz_list_newf(rz_bin_java_free_interface);
	if (offset + 2 > len) {
		bin->interfaces_size = 0;
		return 0;
	}
	bin->interfaces_count = rz_read_at_be16(if_buf, 0);
	adv += 2;
	// eprintf("Interfaces count: %d\n", bin->interfaces_count);
	if (bin->interfaces_count > 0) {
		for (i = 0; i < bin->interfaces_count; i++) {
			interfaces_obj = rz_bin_java_read_next_interface_item(bin, offset + adv, buf, len);
			if (interfaces_obj) {
				rz_list_append(bin->interfaces_list, interfaces_obj);
				adv += interfaces_obj->size;
				if (offset + adv > len) {
					eprintf("[X] rz_bin_java: Error unable to parse remainder of classfile after Interface: %d.\n", i);
					break;
				}
			} else {
				break;
			}
		}
	}
	bin->interfaces_size = adv;
	return adv;
}

RZ_API ut64 rz_bin_java_parse_fields(RzBinJavaObj *bin, const ut64 offset, const ut8 *buf, const ut64 len) {
	int i = 0;
	ut64 adv = 0;
	RzBinJavaField *field;
	const ut8 *fm_buf = buf + offset;
	rz_list_free(bin->fields_list);
	bin->fields_list = rz_list_newf(rz_bin_java_free_fmtype);
	bin->fields_offset = offset;
	if (offset + 2 >= len) {
		return UT64_MAX;
	}
	bin->fields_count = rz_read_at_be16(fm_buf, 0);
	adv += 2;
	// eprintf("Fields count: %d 0x%" PFMT64x "\n", bin->fields_count, bin->fields_offset);
	if (bin->fields_count > 0) {
		for (i = 0; i < bin->fields_count; i++, bin->field_idx++) {
			field = rz_bin_java_read_next_field(bin, offset + adv, buf, len);
			if (field) {
				adv += field->size;
				rz_list_append(bin->fields_list, field);
				// rz_bin_java_summary_print_field(field);
				if (adv + offset > len) {
					eprintf("[X] rz_bin_java: Error unable to parse remainder of classfile after Field: %d.\n", i);
					break;
				}
			} else {
				// eprintf("Failed to read Field %d\n", i);
				break;
			}
		}
	}
	bin->fields_size = adv;
	return adv;
}

RZ_API ut64 rz_bin_java_parse_attrs(RzBinJavaObj *bin, const ut64 offset, const ut8 *buf, const ut64 len) {
	int i = 0;
	ut64 adv = 0;
	const ut8 *a_buf = buf + offset;
	if (offset + 2 >= len) {
		// Check if we can read that ushort
		return UT64_MAX;
	}
	rz_list_free(bin->attrs_list);
	bin->attrs_list = rz_list_newf(rz_bin_java_free_attribute);
	bin->attrs_offset = offset;
	bin->attrs_count = rz_read_at_be16(a_buf, adv);
	adv += 2;
	if (bin->attrs_count > 0) {
		for (i = 0; i < bin->attrs_count; i++, bin->attr_idx++) {
			RzBinJavaAttrInfo *attr = rz_bin_java_read_next_attr(bin, offset + adv, buf, len);
			if (!attr) {
				// eprintf ("[X] rz_bin_java: Error unable to parse remainder of classfile after Attribute: %d.\n", i);
				break;
			}
			rz_list_append(bin->attrs_list, attr);
			adv += attr->size;
			if (adv + offset >= len) {
				// eprintf ("[X] rz_bin_java: Error unable to parse remainder of classfile after Attribute: %d.\n", i);
				break;
			}
		}
	}
	bin->attrs_size = adv;
	return adv;
}

RZ_API ut64 rz_bin_java_parse_methods(RzBinJavaObj *bin, const ut64 offset, const ut8 *buf, const ut64 len) {
	int i = 0;
	ut64 adv = 0;
	RzBinJavaField *method;
	const ut8 *fm_buf = buf + offset;
	rz_list_free(bin->methods_list);
	bin->methods_list = rz_list_newf(rz_bin_java_free_fmtype);

	if (offset + 2 >= len) {
		return 0LL;
	}
	bin->methods_offset = offset;
	bin->methods_count = rz_read_at_be16(fm_buf, 0);
	adv += 2;
	// eprintf("Methods count: %d 0x%" PFMT64x "\n", bin->methods_count, bin->methods_offset);
	bin->main = NULL;
	bin->entrypoint = NULL;
	bin->main_code_attr = NULL;
	bin->entrypoint_code_attr = NULL;
	for (i = 0; i < bin->methods_count; i++, bin->method_idx++) {
		method = rz_bin_java_read_next_method(bin, offset + adv, buf, len);
		if (method) {
			adv += method->size;
			rz_list_append(bin->methods_list, method);
		}
		// Update Main, Init, or Class Init
		if (method && !strcmp((const char *)method->name, "main")) {
			bin->main = method;
			// get main code attr
			bin->main_code_attr = rz_bin_java_get_attr_from_field(method, RZ_BIN_JAVA_ATTRIBUTE_CODE_ATTR, 0);
		} else if (method && (!strcmp((const char *)method->name, "<init>") || !strcmp((const char *)method->name, "init"))) {
			// eprintf("Found an init function.\n");
			bin->entrypoint = method;
			bin->entrypoint_code_attr = rz_bin_java_get_attr_from_field(method, RZ_BIN_JAVA_ATTRIBUTE_CODE_ATTR, 0);
		} else if (method && (!strcmp((const char *)method->name, "<cinit>") || !strcmp((const char *)method->name, "cinit"))) {
			bin->cf2.this_class_entrypoint = method;
			bin->cf2.this_class_entrypoint_code_attr = rz_bin_java_get_attr_from_field(method, RZ_BIN_JAVA_ATTRIBUTE_CODE_ATTR, 0);
		}
		if (adv + offset > len) {
			eprintf("[X] rz_bin_java: Error unable to parse remainder of classfile after Method: %d.\n", i);
			break;
		}
		// rz_bin_java_summary_print_field(method);
	}
	bin->methods_size = adv;
	return adv;
}

RZ_API int rz_bin_java_new_bin(RzBinJavaObj *bin, ut64 loadaddr, Sdb *kv, const ut8 *buf, ut64 len) {
	RZ_BIN_JAVA_GLOBAL_BIN = bin;
	if (!rz_str_constpool_init(&bin->constpool)) {
		return false;
	}
	bin->lines.count = 0;
	bin->loadaddr = loadaddr;
	rz_bin_java_get_java_null_cp();
	bin->id = rz_num_rand(UT32_MAX);
	bin->kv = kv ? kv : sdb_new(NULL, NULL, 0);
	bin->AllJavaBinObjs = NULL;
	return rz_bin_java_load_bin(bin, buf, len);
}

RZ_API int rz_bin_java_load_bin(RzBinJavaObj *bin, const ut8 *buf, ut64 buf_sz) {
	ut64 adv = 0;
	RZ_BIN_JAVA_GLOBAL_BIN = bin;
	if (!bin) {
		return false;
	}
	rz_bin_java_reset_bin_info(bin);
	memcpy((ut8 *)&bin->cf, buf, 10);
	if (memcmp(bin->cf.cafebabe, "\xCA\xFE\xBA\xBE", 4)) {
		eprintf("rz_bin_java_new_bin: Invalid header (%02x %02x %02x %02x)\n",
			bin->cf.cafebabe[0], bin->cf.cafebabe[1],
			bin->cf.cafebabe[2], bin->cf.cafebabe[3]);
		return false;
	}
	if (bin->cf.major[0] == bin->cf.major[1] && bin->cf.major[0] == 0) {
		eprintf("Java CLASS with MACH0 header?\n");
		return false;
	}
	adv += 8;
	// -2 so that the cp_count will be parsed
	adv += rz_bin_java_parse_cp_pool(bin, adv, buf, buf_sz);
	if (adv > buf_sz) {
		eprintf("[X] rz_bin_java: Error unable to parse remainder of classfile after Constant Pool.\n");
		return true;
	}
	adv += rz_bin_java_read_class_file2(bin, adv, buf, buf_sz);
	if (adv > buf_sz) {
		eprintf("[X] rz_bin_java: Error unable to parse remainder of classfile after class file info.\n");
		return true;
	}
	// eprintf("This class: %d %s\n", bin->cf2.this_class, bin->cf2.this_class_name);
	// eprintf("0x%" PFMT64x " Access flags: 0x%04x\n", adv, bin->cf2.access_flags);
	adv += rz_bin_java_parse_interfaces(bin, adv, buf, buf_sz);
	if (adv > buf_sz) {
		eprintf("[X] rz_bin_java: Error unable to parse remainder of classfile after Interfaces.\n");
		return true;
	}
	adv += rz_bin_java_parse_fields(bin, adv, buf, buf_sz);
	if (adv > buf_sz) {
		eprintf("[X] rz_bin_java: Error unable to parse remainder of classfile after Fields.\n");
		return true;
	}
	adv += rz_bin_java_parse_methods(bin, adv, buf, buf_sz);
	if (adv > buf_sz) {
		eprintf("[X] rz_bin_java: Error unable to parse remainder of classfile after Methods.\n");
		return true;
	}
	adv += rz_bin_java_parse_attrs(bin, adv, buf, buf_sz);
	bin->calc_size = adv;
	// if (adv > buf_sz) {
	// eprintf ("[X] rz_bin_java: Error unable to parse remainder of classfile after Attributes.\n");
	// return true;
	// }

	// add_cp_objs_to_sdb(bin);
	// add_method_infos_to_sdb(bin);
	// add_field_infos_to_sdb(bin);
	return true;
}

RZ_API char *rz_bin_java_get_version(RzBinJavaObj *bin) {
	return rz_str_newf("0x%02x%02x 0x%02x%02x",
		bin->cf.major[1], bin->cf.major[0],
		bin->cf.minor[1], bin->cf.minor[0]);
}

RZ_API RzList *rz_bin_java_get_entrypoints(RzBinJavaObj *bin) {
	RzListIter *iter = NULL, *iter_tmp = NULL;
	RzBinJavaField *fm_type;
	RzList *ret = rz_list_newf(free);
	if (!ret) {
		return NULL;
	}
	rz_list_foreach_safe (bin->methods_list, iter, iter_tmp, fm_type) {
		if (!strcmp(fm_type->name, "main") || !strcmp(fm_type->name, "<init>") || !strcmp(fm_type->name, "<clinit>") || strstr(fm_type->flags_str, "static")) {
			RzBinAddr *addr = RZ_NEW0(RzBinAddr);
			if (addr) {
				addr->vaddr = addr->paddr =
					rz_bin_java_get_method_code_offset(fm_type) + bin->loadaddr;
				addr->hpaddr = fm_type->file_offset;
				rz_list_append(ret, addr);
			}
		}
	}
	return ret;
}

RZ_API RzBinJavaField *rz_bin_java_get_method_code_attribute_with_addr(RzBinJavaObj *bin, ut64 addr) {
	RzListIter *iter = NULL, *iter_tmp = NULL;
	RzBinJavaField *fm_type, *res = NULL;
	if (bin == NULL && RZ_BIN_JAVA_GLOBAL_BIN) {
		bin = RZ_BIN_JAVA_GLOBAL_BIN;
	} else if (bin == NULL) {
		eprintf("Attempting to analyse function when the RZ_BIN_JAVA_GLOBAL_BIN has not been set.\n");
		return NULL;
	}
	rz_list_foreach_safe (bin->methods_list, iter, iter_tmp, fm_type) {
		ut64 offset = rz_bin_java_get_method_code_offset(fm_type) + bin->loadaddr,
		     size = rz_bin_java_get_method_code_size(fm_type);
		if (addr >= offset && addr <= size + offset) {
			res = fm_type;
		}
	}
	return res;
}

RZ_API RzBinAddr *rz_bin_java_get_entrypoint(RzBinJavaObj *bin, int sym) {
	RzBinAddr *ret = NULL;
	ret = RZ_NEW0(RzBinAddr);
	if (!ret) {
		return NULL;
	}
	ret->paddr = UT64_MAX;
	switch (sym) {
	case RZ_BIN_SYM_ENTRY:
	case RZ_BIN_SYM_INIT:
		ret->paddr = rz_bin_java_find_method_offset(bin, "<init>");
		if (ret->paddr == UT64_MAX) {
			ret->paddr = rz_bin_java_find_method_offset(bin, "<cinit>");
		}
		break;
	case RZ_BIN_SYM_FINI:
		ret->paddr = UT64_MAX;
		break;
	case RZ_BIN_SYM_MAIN:
		ret->paddr = rz_bin_java_find_method_offset(bin, "main");
		break;
	default:
		ret->paddr = -1;
	}
	if (ret->paddr != -1) {
		ret->paddr += bin->loadaddr;
	}
	return ret;
}

RZ_API ut64 rz_bin_java_get_method_code_size(RzBinJavaField *fm_type) {
	RzListIter *attr_iter = NULL, *attr_iter_tmp = NULL;
	RzBinJavaAttrInfo *attr = NULL;
	ut64 sz = 0;
	rz_list_foreach_safe (fm_type->attributes, attr_iter, attr_iter_tmp, attr) {
		if (attr->type == RZ_BIN_JAVA_ATTRIBUTE_CODE_ATTR) {
			sz = attr->info.code_attr.code_length;
			break;
		}
	}
	return sz;
}

RZ_API ut64 rz_bin_java_find_method_offset(RzBinJavaObj *bin, const char *method_name) {
	RzListIter *attr_iter = NULL, *attr_iter_tmp = NULL;
	RzBinJavaField *method = NULL;
	ut64 offset = -1;
	rz_list_foreach_safe (bin->methods_list, attr_iter, attr_iter_tmp, method) {
		if (method && !strcmp((const char *)method->name, method_name)) {
			offset = rz_bin_java_get_method_code_offset(method) + bin->loadaddr;
			break;
		}
	}
	return offset;
}

RZ_API ut64 rz_bin_java_get_method_code_offset(RzBinJavaField *fm_type) {
	RzListIter *attr_iter = NULL, *attr_iter_tmp = NULL;
	RzBinJavaAttrInfo *attr = NULL;
	ut64 offset = 0;
	rz_list_foreach_safe (fm_type->attributes, attr_iter, attr_iter_tmp, attr) {
		if (attr->type == RZ_BIN_JAVA_ATTRIBUTE_CODE_ATTR) {
			offset = attr->info.code_attr.code_offset;
			break;
		}
	}
	return offset;
}

RZ_API RzBinField *rz_bin_java_allocate_rbinfield(void) {
	RzBinField *t = (RzBinField *)malloc(sizeof(RzBinField));
	if (t) {
		memset(t, 0, sizeof(RzBinField));
	}
	return t;
}

RZ_API RzBinField *rz_bin_java_create_new_rbinfield_from_field(RzBinJavaField *fm_type, ut64 baddr) {
	RzBinField *field = rz_bin_java_allocate_rbinfield();
	if (field) {
		field->name = strdup(fm_type->name);
		field->paddr = fm_type->file_offset + baddr;
		field->visibility = fm_type->flags;
	}
	return field;
}

RZ_API RzBinSymbol *rz_bin_java_create_new_symbol_from_field(RzBinJavaField *fm_type, ut64 baddr) {
	RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
	if (fm_type == NULL || fm_type->field_ref_cp_obj == NULL || fm_type->field_ref_cp_obj == &RZ_BIN_JAVA_NULL_TYPE) {
		RZ_FREE(sym);
	}
	if (sym) {
		sym->name = strdup(fm_type->name);
		// strncpy (sym->type, fm_type->descriptor, RZ_BIN_SIZEOF_STRINGS);
		if (fm_type->type == RZ_BIN_JAVA_FIELD_TYPE_METHOD) {
			sym->type = RZ_BIN_TYPE_FUNC_STR;
			sym->paddr = rz_bin_java_get_method_code_offset(fm_type);
			sym->vaddr = rz_bin_java_get_method_code_offset(fm_type) + baddr;
			sym->size = rz_bin_java_get_method_code_size(fm_type);
		} else {
			sym->type = "FIELD";
			sym->paddr = fm_type->file_offset; // rz_bin_java_get_method_code_offset (fm_type);
			sym->vaddr = fm_type->file_offset + baddr;
			sym->size = fm_type->size;
		}
		if (rz_bin_java_is_fm_type_protected(fm_type)) {
			sym->bind = RZ_BIN_BIND_LOCAL_STR;
		} else if (rz_bin_java_is_fm_type_private(fm_type)) {
			sym->bind = RZ_BIN_BIND_LOCAL_STR;
		} else if (rz_bin_java_is_fm_type_protected(fm_type)) {
			sym->bind = RZ_BIN_BIND_GLOBAL_STR;
		}
		sym->forwarder = "NONE";
		if (fm_type->class_name) {
			sym->classname = strdup(fm_type->class_name);
		} else {
			sym->classname = strdup("UNKNOWN"); // dupped names?
		}
		sym->ordinal = fm_type->metas->ord;
		sym->visibility = fm_type->flags;
		if (fm_type->flags_str) {
			sym->visibility_str = strdup(fm_type->flags_str);
		}
	}
	return sym;
}

RZ_API RzBinSymbol *rz_bin_java_create_new_symbol_from_fm_type_meta(RzBinJavaField *fm_type, ut64 baddr) {
	RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
	if (!sym || !fm_type || !fm_type->field_ref_cp_obj || fm_type->field_ref_cp_obj == &RZ_BIN_JAVA_NULL_TYPE) {
		free(sym);
		return NULL;
	}
	// ut32 new_name_len = strlen (fm_type->name) + strlen ("_meta") + 1;
	// char *new_name = malloc (new_name_len);
	sym->name = rz_str_newf("meta_%s", fm_type->name);
	if (fm_type->type == RZ_BIN_JAVA_FIELD_TYPE_METHOD) {
		sym->type = "FUNC_META";
	} else {
		sym->type = "FIELD_META";
	}
	if (rz_bin_java_is_fm_type_protected(fm_type)) {
		sym->bind = RZ_BIN_BIND_LOCAL_STR;
	} else if (rz_bin_java_is_fm_type_private(fm_type)) {
		sym->bind = RZ_BIN_BIND_LOCAL_STR;
	} else if (rz_bin_java_is_fm_type_protected(fm_type)) {
		sym->bind = RZ_BIN_BIND_GLOBAL_STR;
	}
	sym->forwarder = "NONE";
	if (fm_type->class_name) {
		sym->classname = strdup(fm_type->class_name);
	} else {
		sym->classname = strdup("UNKNOWN");
	}
	sym->paddr = fm_type->file_offset; // rz_bin_java_get_method_code_offset (fm_type);
	sym->vaddr = fm_type->file_offset + baddr;
	sym->ordinal = fm_type->metas->ord;
	sym->size = fm_type->size;
	sym->visibility = fm_type->flags;
	if (fm_type->flags_str) {
		sym->visibility_str = strdup(fm_type->flags_str);
	}
	return sym;
}

RZ_API RzBinSymbol *rz_bin_java_create_new_symbol_from_ref(RzBinJavaObj *bin, RzBinJavaCPTypeObj *obj, ut64 baddr) {
	RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
	if (!sym) {
		return NULL;
	}
	char *class_name, *name, *type_name;
	if (obj == NULL || (obj->tag != RZ_BIN_JAVA_CP_METHODREF && obj->tag != RZ_BIN_JAVA_CP_INTERFACEMETHOD_REF && obj->tag != RZ_BIN_JAVA_CP_FIELDREF)) {
		RZ_FREE(sym);
		return sym;
	}
	if (sym) {
		class_name = rz_bin_java_get_name_from_bin_cp_list(bin,
			obj->info.cp_method.class_idx);
		name = rz_bin_java_get_name_from_bin_cp_list(bin,
			obj->info.cp_method.name_and_type_idx);
		type_name = rz_bin_java_get_name_from_bin_cp_list(bin,
			obj->info.cp_method.name_and_type_idx);
		if (name) {
			sym->name = name;
			name = NULL;
		}
		if (type_name) {
			sym->type = rz_str_constpool_get(&bin->constpool, type_name);
			RZ_FREE(type_name);
		}
		if (class_name) {
			sym->classname = strdup(class_name);
		}
		sym->paddr = obj->file_offset + baddr;
		sym->vaddr = obj->file_offset + baddr;
		sym->ordinal = obj->metas->ord;
		sym->size = 0;
	}
	return sym;
}

// TODO: vaddr+vsize break things if set
RZ_API RzList *rz_bin_java_get_sections(RzBinJavaObj *bin) {
	RzBinSection *section = NULL;
	RzList *sections = rz_list_newf(free);
	ut64 baddr = bin->loadaddr;
	RzBinJavaField *fm_type;
	RzListIter *iter = NULL;
	if (bin->cp_count > 0) {
		section = RZ_NEW0(RzBinSection);
		if (section) {
			section->name = strdup("constant_pool");
			section->paddr = bin->cp_offset + baddr;
			section->size = bin->cp_size;
#if 0
			section->vsize = section->size;
			section->vaddr = 0x10; // XXX // bin->cp_offset; //  + baddr;
#endif
			section->vaddr = baddr;
			// section->vaddr = section->paddr;
			// section->vsize = section->size;
			section->perm = RZ_PERM_R;
			section->add = true;
			rz_list_append(sections, section);
		}
		section = NULL;
	}
	if (bin->fields_count > 0) {
		section = RZ_NEW0(RzBinSection);
		if (section) {
			section->name = strdup("fields");
			section->size = bin->fields_size;
			section->paddr = bin->fields_offset + baddr;
#if 0
			section->vsize = section->size;
			section->vaddr = section->paddr;
#endif
			section->perm = RZ_PERM_R;
			section->add = true;
			rz_list_append(sections, section);
			section = NULL;
			rz_list_foreach (bin->fields_list, iter, fm_type) {
				if (fm_type->attr_offset == 0) {
					continue;
				}
				section = RZ_NEW0(RzBinSection);
				if (section) {
					section->name = rz_str_newf("attrs.%s", fm_type->name);
					section->size = fm_type->size - (fm_type->file_offset - fm_type->attr_offset);
#if 0
					section->vsize = section->size;
					section->vaddr = section->paddr;
#endif
					section->paddr = fm_type->attr_offset + baddr;
					section->perm = RZ_PERM_R;
					section->add = true;
					rz_list_append(sections, section);
				}
			}
		}
	}
	if (bin->methods_count > 0) {
		section = RZ_NEW0(RzBinSection);
		if (section) {
			section->name = strdup("methods");
			section->paddr = bin->methods_offset + baddr;
			section->size = bin->methods_size;
			// section->vaddr = section->paddr;
			// section->vsize = section->size;
			section->perm = RZ_PERM_RX;
			section->add = true;
			rz_list_append(sections, section);
			section = NULL;
			rz_list_foreach (bin->methods_list, iter, fm_type) {
				if (fm_type->attr_offset == 0) {
					continue;
				}
				section = RZ_NEW0(RzBinSection);
				if (section) {
					section->name = rz_str_newf("attrs.%s", fm_type->name);
					section->size = fm_type->size - (fm_type->file_offset - fm_type->attr_offset);
					// section->vsize = section->size;
					// section->vaddr = section->paddr;
					section->paddr = fm_type->attr_offset + baddr;
					section->perm = RZ_PERM_R | RZ_PERM_X;
					section->add = true;
					rz_list_append(sections, section);
				}
			}
		}
	}
	if (bin->interfaces_count > 0) {
		section = RZ_NEW0(RzBinSection);
		if (section) {
			section->name = strdup("interfaces");
			section->paddr = bin->interfaces_offset + baddr;
			section->size = bin->interfaces_size;
			// section->vaddr = section->paddr;
			// section->vsize = section->size;
			section->perm = RZ_PERM_R;
			section->add = true;
			rz_list_append(sections, section);
		}
		section = NULL;
	}
	if (bin->attrs_count > 0) {
		section = RZ_NEW0(RzBinSection);
		if (section) {
			section->name = strdup("attributes");
			section->paddr = bin->attrs_offset + baddr;
			section->size = bin->attrs_size;
			// section->vaddr = section->paddr;
			// section->vsize = section->size;
			section->perm = RZ_PERM_R;
			section->perm = RZ_PERM_R;
			section->add = true;
			rz_list_append(sections, section);
		}
		section = NULL;
	}
	return sections;
}

RZ_API RzList *rz_bin_java_enum_class_methods(RzBinJavaObj *bin, ut16 class_idx) {
	RzList *methods = rz_list_newf(free);
	RzListIter *iter;
	RzBinJavaField *field;
	rz_list_foreach (bin->methods_list, iter, field) {
		if (field->field_ref_cp_obj && 0) {
			if ((field && field->field_ref_cp_obj->metas->ord == class_idx)) {
				RzBinSymbol *sym = rz_bin_java_create_new_symbol_from_ref(
					bin, field->field_ref_cp_obj, bin->loadaddr);
				if (sym) {
					rz_list_append(methods, sym);
				}
			}
		} else {
			RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
			sym->name = strdup(field->name);
			// func defintion
			// sym->paddr = field->file_offset + bin->loadaddr;
			// code implementation
			sym->paddr = rz_bin_java_get_method_code_offset(field);
			sym->vaddr = sym->paddr; // + bin->loadaddr;
			rz_list_append(methods, sym);
		}
	}
	return methods;
}

RZ_API RzList *rz_bin_java_enum_class_fields(RzBinJavaObj *bin, ut16 class_idx) {
	RzList *fields = rz_list_newf(free);
	RzListIter *iter;
	RzBinJavaField *fm_type;
	RzBinField *field = NULL;
	rz_list_foreach (bin->fields_list, iter, fm_type) {
		if (fm_type) {
			if (fm_type && fm_type->field_ref_cp_obj && fm_type->field_ref_cp_obj->metas->ord == class_idx) {
				field = rz_bin_java_create_new_rbinfield_from_field(fm_type, bin->loadaddr);
				if (field) {
					rz_list_append(fields, field);
				}
			}
		}
	}
	return fields;
}

RZ_API int is_class_interface(RzBinJavaObj *bin, RzBinJavaCPTypeObj *cp_obj) {
	RzBinJavaInterfaceInfo *ifobj;
	RzListIter *iter;
	int res = false;
	rz_list_foreach (bin->interfaces_list, iter, ifobj) {
		if (ifobj) {
			res = cp_obj == ifobj->cp_class;
			if (res) {
				break;
			}
		}
	}
	return res;
}
/*
   RZ_API RzList * rz_bin_java_get_interface_classes(RzBinJavaObj * bin) {
        RzList *interfaces_names = rz_list_new ();
        RzListIter *iter;
        RzBinJavaInterfaceInfo *ifobj;
        rz_list_foreach(bin->interfaces_list, iter, iinfo) {
                RzBinClass *class_ = RZ_NEW0 (RzBinClass);
                RzBinJavaCPTypeObj *cp_obj = ;
                if (ifobj && ifobj->name) {
                        ut8 * name = strdup(ifobj->name);
                        rz_list_append(interfaces_names, name);
                }
        }
        return interfaces_names;
   }
*/

RZ_API RzList *rz_bin_java_get_lib_names(RzBinJavaObj *bin) {
	RzList *lib_names = rz_list_newf(free);
	RzListIter *iter;
	RzBinJavaCPTypeObj *cp_obj = NULL;
	if (!bin) {
		return lib_names;
	}
	rz_list_foreach (bin->cp_list, iter, cp_obj) {
		if (cp_obj && cp_obj->tag == RZ_BIN_JAVA_CP_CLASS &&
			(bin->cf2.this_class != cp_obj->info.cp_class.name_idx || !is_class_interface(bin, cp_obj))) {
			char *name = rz_bin_java_get_item_name_from_bin_cp_list(bin, cp_obj);
			if (name) {
				rz_list_append(lib_names, name);
			}
		}
	}
	return lib_names;
}

RZ_API void rz_bin_java_free_classes(void /*RzBinClass*/ *k) {
	RzBinClass *klass = k;
	if (klass) {
		rz_list_free(klass->methods);
		rz_list_free(klass->fields);
		free(klass->name);
		free(klass->super);
		free(klass->visibility_str);
		free(klass);
	}
}

RZ_API RzList *rz_bin_java_get_classes(RzBinJavaObj *bin) {
	RzList *classes = rz_list_newf(rz_bin_java_free_classes);
	RzListIter *iter;
	RzBinJavaCPTypeObj *cp_obj = NULL;
	RzBinJavaCPTypeObj *this_class_cp_obj = rz_bin_java_get_item_from_bin_cp_list(bin, bin->cf2.this_class);
	ut32 idx = 0;
	RzBinClass *k = RZ_NEW0(RzBinClass);
	if (!k) {
		rz_list_free(classes);
		return NULL;
	}
	k->visibility = bin->cf2.access_flags;
	if (bin->cf2.flags_str) {
		k->visibility_str = strdup(bin->cf2.flags_str);
	}
	k->methods = rz_bin_java_enum_class_methods(bin, bin->cf2.this_class);
	k->fields = rz_bin_java_enum_class_fields(bin, bin->cf2.this_class);
	k->name = rz_bin_java_get_this_class_name(bin);
	k->super = rz_bin_java_get_name_from_bin_cp_list(bin, bin->cf2.super_class);
	k->index = (idx++);
	rz_list_append(classes, k);
	rz_list_foreach (bin->cp_list, iter, cp_obj) {
		if (cp_obj && cp_obj->tag == RZ_BIN_JAVA_CP_CLASS && (this_class_cp_obj != cp_obj && is_class_interface(bin, cp_obj))) {
			k = RZ_NEW0(RzBinClass);
			if (!k) {
				break;
			}
			k->methods = rz_bin_java_enum_class_methods(bin, cp_obj->info.cp_class.name_idx);
			k->fields = rz_bin_java_enum_class_fields(bin, cp_obj->info.cp_class.name_idx);
			k->index = idx;
			k->name = rz_bin_java_get_item_name_from_bin_cp_list(bin, cp_obj);
			rz_list_append(classes, k);
			idx++;
		}
	}
	return classes;
}

RZ_API RzBinSymbol *rz_bin_java_create_new_symbol_from_invoke_dynamic(RzBinJavaCPTypeObj *obj, ut64 baddr) {
	if (!obj || (obj->tag != RZ_BIN_JAVA_CP_INVOKEDYNAMIC)) {
		return NULL;
	}
	return rz_bin_java_create_new_symbol_from_cp_idx(obj->info.cp_invoke_dynamic.name_and_type_index, baddr);
}

RZ_API RzBinSymbol *rz_bin_java_create_new_symbol_from_cp_idx(ut32 cp_idx, ut64 baddr) {
	RzBinSymbol *sym = NULL;
	RzBinJavaCPTypeObj *obj = rz_bin_java_get_item_from_bin_cp_list(
		RZ_BIN_JAVA_GLOBAL_BIN, cp_idx);
	if (obj) {
		switch (obj->tag) {
		case RZ_BIN_JAVA_CP_METHODREF:
		case RZ_BIN_JAVA_CP_FIELDREF:
		case RZ_BIN_JAVA_CP_INTERFACEMETHOD_REF:
			sym = rz_bin_java_create_new_symbol_from_ref(RZ_BIN_JAVA_GLOBAL_BIN, obj, baddr);
			break;
		case RZ_BIN_JAVA_CP_INVOKEDYNAMIC:
			sym = rz_bin_java_create_new_symbol_from_invoke_dynamic(obj, baddr);
			break;
		default:
			break;
		}
	}
	return sym;
}

RZ_API RzList *rz_bin_java_get_fields(RzBinJavaObj *bin) {
	RzListIter *iter = NULL, *iter_tmp = NULL;
	RzList *fields = rz_list_new();
	RzBinJavaField *fm_type;
	RzBinField *field;
	rz_list_foreach_safe (bin->fields_list, iter, iter_tmp, fm_type) {
		field = rz_bin_java_create_new_rbinfield_from_field(fm_type, bin->loadaddr);
		if (field) {
			rz_list_append(fields, field);
		}
	}
	return fields;
}

RZ_API void rz_bin_add_import(RzBinJavaObj *bin, RzBinJavaCPTypeObj *obj, const char *type) {
	RzBinImport *imp = RZ_NEW0(RzBinImport);
	char *class_name = rz_bin_java_get_name_from_bin_cp_list(bin, obj->info.cp_method.class_idx);
	char *name = rz_bin_java_get_name_from_bin_cp_list(bin, obj->info.cp_method.name_and_type_idx);
	char *descriptor = rz_bin_java_get_desc_from_bin_cp_list(bin, obj->info.cp_method.name_and_type_idx);
	class_name = class_name ? class_name : strdup("INVALID CLASS NAME INDEX");
	name = name ? name : strdup("InvalidNameIndex");
	descriptor = descriptor ? descriptor : strdup("INVALID DESCRIPTOR INDEX");
	imp->classname = class_name;
	imp->name = name;
	imp->bind = "NONE";
	imp->type = rz_str_constpool_get(&bin->constpool, type);
	imp->descriptor = descriptor;
	imp->ordinal = obj->idx;
	rz_list_append(bin->imports_list, imp);
}

RZ_API void rz_bin_java_set_imports(RzBinJavaObj *bin) {
	RzListIter *iter = NULL;
	RzBinJavaCPTypeObj *obj = NULL;
	rz_list_free(bin->imports_list);
	bin->imports_list = rz_list_newf(free);
	rz_list_foreach (bin->cp_list, iter, obj) {
		const char *type = NULL;
		switch (obj->tag) {
		case RZ_BIN_JAVA_CP_METHODREF: type = "METHOD"; break;
		case RZ_BIN_JAVA_CP_INTERFACEMETHOD_REF: type = "FIELD"; break;
		case RZ_BIN_JAVA_CP_FIELDREF: type = "INTERFACE_METHOD"; break;
		default: type = NULL; break;
		}
		if (type) {
			rz_bin_add_import(bin, obj, type);
		}
	}
}

RZ_API RzList *rz_bin_java_get_imports(RzBinJavaObj *bin) {
	RzList *ret = rz_list_newf(free);
	RzBinImport *import = NULL;
	RzListIter *iter;
	rz_list_foreach (bin->imports_list, iter, import) {
		RzBinImport *n_import = RZ_NEW0(RzBinImport);
		if (!n_import) {
			rz_list_free(ret);
			return NULL;
		}
		memcpy(n_import, import, sizeof(RzBinImport));
		rz_list_append(ret, n_import);
	}
	return ret;
}

RZ_API RzList *rz_bin_java_get_symbols(RzBinJavaObj *bin) {
	RzListIter *iter = NULL, *iter_tmp = NULL;
	RzList *imports, *symbols = rz_list_newf(free);
	RzBinSymbol *sym = NULL;
	RzBinImport *imp;
	RzBinJavaField *fm_type;
	rz_list_foreach_safe (bin->methods_list, iter, iter_tmp, fm_type) {
		sym = rz_bin_java_create_new_symbol_from_field(fm_type, bin->loadaddr);
		if (sym) {
			rz_list_append(symbols, (void *)sym);
		}
		sym = rz_bin_java_create_new_symbol_from_fm_type_meta(fm_type, bin->loadaddr);
		if (sym) {
			rz_list_append(symbols, (void *)sym);
		}
	}
	rz_list_foreach_safe (bin->fields_list, iter, iter_tmp, fm_type) {
		sym = rz_bin_java_create_new_symbol_from_field(fm_type, bin->loadaddr);
		if (sym) {
			rz_list_append(symbols, (void *)sym);
		}
		sym = rz_bin_java_create_new_symbol_from_fm_type_meta(fm_type, bin->loadaddr);
		if (sym) {
			rz_list_append(symbols, (void *)sym);
		}
	}
	bin->lang = "java";
	if (bin->cf.major[1] >= 46) {
		switch (bin->cf.major[1]) {
			static char lang[32];
			int langid;
		case 46:
		case 47:
		case 48:
			langid = 2 + (bin->cf.major[1] - 46);
			snprintf(lang, sizeof(lang) - 1, "java 1.%d", langid);
			bin->lang = lang;
			break;
		default:
			langid = 5 + (bin->cf.major[1] - 49);
			snprintf(lang, sizeof(lang) - 1, "java %d", langid);
			bin->lang = lang;
		}
	}
	imports = rz_bin_java_get_imports(bin);
	rz_list_foreach (imports, iter, imp) {
		sym = RZ_NEW0(RzBinSymbol);
		if (!sym) {
			break;
		}
		if (imp->classname && !strncmp(imp->classname, "kotlin/jvm", 10)) {
			bin->lang = "kotlin";
		}
		sym->name = strdup(imp->name);
		sym->is_imported = true;
		if (!sym->name) {
			free(sym);
			break;
		}
		sym->type = "import";
		if (!sym->type) {
			free(sym);
			break;
		}
		sym->vaddr = sym->paddr = imp->ordinal;
		sym->ordinal = imp->ordinal;
		rz_list_append(symbols, (void *)sym);
	}
	rz_list_free(imports);
	return symbols;
}

RZ_API RzList *rz_bin_java_get_strings(RzBinJavaObj *bin) {
	RzList *strings = rz_list_newf(free);
	RzBinString *str = NULL;
	RzListIter *iter = NULL, *iter_tmp = NULL;
	RzBinJavaCPTypeObj *cp_obj = NULL;
	rz_list_foreach_safe (bin->cp_list, iter, iter_tmp, cp_obj) {
		if (cp_obj && cp_obj->tag == RZ_BIN_JAVA_CP_UTF8) {
			str = (RzBinString *)RZ_NEW0(RzBinString);
			if (str) {
				str->paddr = cp_obj->file_offset + bin->loadaddr;
				str->ordinal = cp_obj->metas->ord;
				str->size = cp_obj->info.cp_utf8.length + 3;
				str->length = cp_obj->info.cp_utf8.length;
				if (str->size > 0) {
					str->string = rz_str_ndup((const char *)
									  cp_obj->info.cp_utf8.bytes,
						RZ_BIN_JAVA_MAXSTR);
				}
				rz_list_append(strings, (void *)str);
			}
		}
	}
	return strings;
}

RZ_API void *rz_bin_java_free(RzBinJavaObj *bin) {
	char *bin_obj_key = NULL;
	if (!bin) {
		return NULL;
	}
	// Delete the bin object from the data base.
	bin_obj_key = rz_bin_java_build_obj_key(bin);
	// if (bin->AllJavaBinObjs && sdb_exists (bin->AllJavaBinObjs, bin_obj_key)) {
	// sdb_unset (bin->AllJavaBinObjs, bin_obj_key, 0);
	// }
	free(bin_obj_key);
	rz_list_free(bin->imports_list);
	// XXX - Need to remove all keys belonging to this class from
	// the share meta information sdb.
	// TODO e.g. iterate over bin->kv and delete all obj, func, etc. keys
	// sdb_free (bin->kv);
	// free up the constant pool list
	rz_list_free(bin->cp_list);
	// free up the fields list
	rz_list_free(bin->fields_list);
	// free up methods list
	rz_list_free(bin->methods_list);
	// free up interfaces list
	rz_list_free(bin->interfaces_list);
	rz_list_free(bin->attrs_list);
	// TODO: XXX if a class list of all inner classes
	// are formed then this will need to be updated
	free(bin->cf2.flags_str);
	free(bin->cf2.this_class_name);
	if (bin == RZ_BIN_JAVA_GLOBAL_BIN) {
		RZ_BIN_JAVA_GLOBAL_BIN = NULL;
	}
	free(bin->file);
	rz_str_constpool_fini(&bin->constpool);
	free(bin);
	return NULL;
}

RZ_API RzBinJavaObj *rz_bin_java_new_buf(RzBuffer *buf, ut64 loadaddr, Sdb *kv) {
	RzBinJavaObj *bin = RZ_NEW0(RzBinJavaObj);
	if (!bin) {
		return NULL;
	}
	ut64 tmpsz;
	const ut8 *tmp = rz_buf_data(buf, &tmpsz);
	if (!rz_bin_java_new_bin(bin, loadaddr, kv, tmp, tmpsz)) {
		return rz_bin_java_free(bin);
	}
	return bin;
}

RZ_API void rz_bin_java_free_attribute(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	if (attr) {
		// eprintf("Deleting attr %s, %p\n", attr->name, attr);
		if (attr && attr->metas && attr->metas->type_info) {
			RzBinJavaAttrMetas *a = attr->metas->type_info;
			if (a && a->allocs && a->allocs->delete_obj) {
				a->allocs->delete_obj(attr);
			}
		}
		// free (attr->metas);
		// free (attr);
	}
}

RZ_API void rz_bin_java_constant_pool(void /*RzBinJavaCPTypeObj*/ *o) {
	RzBinJavaCPTypeObj *obj = o;
	if (obj != &RZ_BIN_JAVA_NULL_TYPE) {
		((RzBinJavaCPTypeMetas *)obj->metas->type_info)->allocs->delete_obj(obj);
	}
}

RZ_API void rz_bin_java_free_fmtype(void /*RzBinJavaField*/ *f) {
	RzBinJavaField *fm_type = f;
	if (!fm_type) {
		return;
	}
	free(fm_type->descriptor);
	free(fm_type->name);
	free(fm_type->flags_str);
	free(fm_type->class_name);
	free(fm_type->metas);
	rz_list_free(fm_type->attributes);
	free(fm_type);
}
// Start Free the various attribute types
RZ_API void rz_bin_java_free_unknown_attr(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	if (attr) {
		free(attr->name);
		free(attr->metas);
		free(attr);
	}
}

RZ_API void rz_bin_java_free_local_variable_table_attr_entry(void /*RzBinJavaLocalVariableAttribute*/ *a) {
	RzBinJavaLocalVariableAttribute *lvattr = a;
	if (lvattr) {
		free(lvattr->descriptor);
		free(lvattr->name);
		free(lvattr);
	}
}

RZ_API void rz_bin_java_free_local_variable_table_attr(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	if (attr) {
		free(attr->name);
		free(attr->metas);
		rz_list_free(attr->info.local_variable_table_attr.local_variable_table);
		free(attr);
	}
}

RZ_API void rz_bin_java_free_local_variable_type_table_attr_entry(void /*RzBinJavaLocalVariableTypeAttribute*/ *a) {
	RzBinJavaLocalVariableTypeAttribute *attr = a;
	if (attr) {
		free(attr->name);
		free(attr->signature);
		free(attr);
	}
}

RZ_API void rz_bin_java_free_local_variable_type_table_attr(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	if (attr) {
		free(attr->name);
		free(attr->metas);
		rz_list_free(attr->info.local_variable_type_table_attr.local_variable_table);
		free(attr);
	}
}

RZ_API void rz_bin_java_free_deprecated_attr(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	if (attr) {
		free(attr->name);
		free(attr->metas);
		free(attr);
	}
}

RZ_API void rz_bin_java_free_enclosing_methods_attr(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	if (attr) {
		free(attr->name);
		free(attr->metas);
		free(attr->info.enclosing_method_attr.class_name);
		free(attr->info.enclosing_method_attr.method_name);
		free(attr->info.enclosing_method_attr.method_descriptor);
		free(attr);
	}
}

RZ_API void rz_bin_java_free_synthetic_attr(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	if (attr) {
		free(attr->name);
		free(attr->metas);
		free(attr);
	}
}

RZ_API void rz_bin_java_free_constant_value_attr(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	if (attr) {
		free(attr->name);
		free(attr->metas);
		free(attr);
	}
}

RZ_API void rz_bin_java_free_line_number_table_attr(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	if (attr) {
		free(attr->name);
		free(attr->metas);
		rz_list_free(attr->info.line_number_table_attr.line_number_table);
		free(attr);
	}
}

RZ_API void rz_bin_java_free_code_attr(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	if (attr) {
		// XXX - Intentional memory leak here.  When one of the
		// Code attributes is parsed, the code (the rz_bin_java)
		// is not properly parsing the class file
		rz_bin_java_free_stack_frame(attr->info.code_attr.implicit_frame);
		rz_list_free(attr->info.code_attr.attributes);
		free(attr->info.code_attr.code);
		rz_list_free(attr->info.code_attr.exception_table);
		free(attr->name);
		free(attr->metas);
		free(attr);
	}
}

RZ_API void rz_bin_java_free_exceptions_attr(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	if (attr) {
		free(attr->name);
		free(attr->metas);
		free(attr->info.exceptions_attr.exception_idx_table);
		free(attr);
	}
}

RZ_API void rz_bin_java_free_inner_classes_attr_entry(void /*RzBinJavaClassesAttribute*/ *a) {
	RzBinJavaClassesAttribute *attr = a;
	if (attr) {
		free(attr->name);
		free(attr->flags_str);
		free(attr);
	}
}

RZ_API void rz_bin_java_free_inner_classes_attr(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	if (attr) {
		free(attr->name);
		free(attr->metas);
		rz_list_free(attr->info.inner_classes_attr.classes);
		free(attr);
	}
}

RZ_API void rz_bin_java_free_signature_attr(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	if (attr) {
		free(attr->name);
		free(attr->metas);
		free(attr->info.signature_attr.signature);
		free(attr);
	}
}

RZ_API void rz_bin_java_free_source_debug_attr(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	if (attr) {
		free(attr->name);
		free(attr->metas);
		free(attr->info.debug_extensions.debug_extension);
		free(attr);
	}
}

RZ_API void rz_bin_java_free_source_code_file_attr(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	if (attr) {
		free(attr->name);
		free(attr->metas);
		free(attr);
	}
}

RZ_API void rz_bin_java_free_stack_map_table_attr(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	if (attr) {
		free(attr->name);
		free(attr->metas);
		rz_list_free(attr->info.stack_map_table_attr.stack_map_frame_entries);
		free(attr);
	}
}

RZ_API void rz_bin_java_free_stack_frame(void /*RzBinJavaStackMapFrame*/ *o) {
	RzBinJavaStackMapFrame *obj = o;
	if (obj) {
		rz_list_free(obj->local_items);
		rz_list_free(obj->stack_items);
		free(obj->metas);
		free(obj);
	}
}

RZ_API void rz_bin_java_free_verification_info(void /*RzBinJavaVerificationObj*/ *o) {
	RzBinJavaVerificationObj *obj = o;
	// eprintf ("Freeing verification object\n");
	if (obj) {
		free(obj->name);
		free(obj);
	}
}

RZ_API void rz_bin_java_free_interface(void /*RzBinJavaInterfaceInfo*/ *o) {
	RzBinJavaInterfaceInfo *obj = o;
	if (obj) {
		free(obj->name);
		free(obj);
	}
}
// End Free the various attribute types
// Start the various attibute types new
RZ_API ut64 rz_bin_java_calc_size_attr(RzBinJavaAttrInfo *attr) {
	return attr ? ((RzBinJavaAttrMetas *)attr->metas->type_info)->allocs->calc_size(attr) : 0;
}

RZ_API ut64 rz_bin_java_calc_size_unknown_attr(RzBinJavaAttrInfo *attr) {
	return attr ? 6 : 0;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_unknown_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	return rz_bin_java_new_default_attr(bin, buffer, sz, buf_offset);
}

RZ_API ut64 rz_bin_java_calc_size_code_attr(RzBinJavaAttrInfo *attr) {
	RzListIter *iter;
	// RzListIter *iter_tmp;
	ut64 size = 0;
	bool is_attr_in_old_format = attr->is_attr_in_old_format;
	if (attr) {
		// attr = rz_bin_java_new_default_attr (buffer, sz, buf_offset);
		size += is_attr_in_old_format ? 4 : 6;
		// attr->info.code_attr.max_stack = rz_read_at_be16 (buffer, 0);
		size += is_attr_in_old_format ? 1 : 2;
		// attr->info.code_attr.max_locals = rz_read_at_be16 (buffer, 2);
		size += is_attr_in_old_format ? 1 : 2;
		// attr->info.code_attr.code_length = rz_read_at_be32 (buffer, 4);
		size += is_attr_in_old_format ? 2 : 4;
		if (attr->info.code_attr.code) {
			size += attr->info.code_attr.code_length;
		}
		// attr->info.code_attr.exception_table_length =  rz_read_at_be16 (buffer, offset);
		size += 2;
		// RzBinJavaExceptionEntry *exc_entry;
		// rz_list_foreach_safe (attr->info.code_attr.exception_table, iter, iter_tmp, exc_entry) {
		rz_list_foreach_iter(attr->info.code_attr.exception_table, iter) {
			// exc_entry->start_pc = rz_read_at_be16 (buffer,offset);
			size += 2;
			// exc_entry->end_pc = rz_read_at_be16 (buffer,offset);
			size += 2;
			// exc_entry->handler_pc = rz_read_at_be16 (buffer,offset);
			size += 2;
			// exc_entry->catch_type = rz_read_at_be16 (buffer, offset);
			size += 2;
		}
		// attr->info.code_attr.attributes_count = rz_read_at_be16 (buffer, offset);
		size += 2;
		// RzBinJavaAttrInfo *_attr;
		if (attr->info.code_attr.attributes_count > 0) {
			// rz_list_foreach_safe (attr->info.code_attr.attributes, iter, iter_tmp, _attr) {
			rz_list_foreach_iter(attr->info.code_attr.attributes, iter) {
				size += rz_bin_java_calc_size_attr(attr);
			}
		}
	}
	return size;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_code_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	RzBinJavaAttrInfo *attr = NULL, *_attr = NULL;
	ut32 k = 0, curpos;
	ut64 offset = 0;
	attr = rz_bin_java_new_default_attr(bin, buffer, sz, buf_offset);
	if (!attr) {
		return NULL;
	}
	if (sz < 16 || sz > buf_offset) { // sz > buf_offset) {
		free(attr);
		return NULL;
	}
	offset += 6;
	attr->type = RZ_BIN_JAVA_ATTRIBUTE_CODE_ATTR;
	attr->info.code_attr.max_stack = attr->is_attr_in_old_format ? buffer[offset] : rz_read_at_be16(buffer, offset);
	offset += attr->is_attr_in_old_format ? 1 : 2;
	attr->info.code_attr.max_locals = attr->is_attr_in_old_format ? buffer[offset] : rz_read_at_be16(buffer, offset);
	offset += attr->is_attr_in_old_format ? 1 : 2;
	attr->info.code_attr.code_length = attr->is_attr_in_old_format ? rz_read_at_be16(buffer, offset) : rz_read_at_be32(buffer, offset);
	offset += attr->is_attr_in_old_format ? 2 : 4;
	// BUG: possible unsigned integer overflow here
	attr->info.code_attr.code_offset = buf_offset + offset;
	attr->info.code_attr.code = (ut8 *)malloc(attr->info.code_attr.code_length);
	if (!attr->info.code_attr.code) {
		eprintf("Handling Code Attributes: Unable to allocate memory "
			"(%u bytes) for a code.\n",
			attr->info.code_attr.code_length);
		return attr;
	}
	RZ_BIN_JAVA_GLOBAL_BIN->current_code_attr = attr;
	{
		int len = attr->info.code_attr.code_length;
		memset(attr->info.code_attr.code, 0, len);
		if (offset + len >= sz) {
			return attr;
		}
		memcpy(attr->info.code_attr.code, buffer + offset, len);
		offset += len;
	}
	attr->info.code_attr.exception_table_length = rz_read_at_be16(buffer, offset);
	offset += 2;
	attr->info.code_attr.exception_table = rz_list_newf(free);
	for (k = 0; k < attr->info.code_attr.exception_table_length; k++) {
		curpos = buf_offset + offset;
		if (curpos + 8 > sz) {
			return attr;
		}
		RzBinJavaExceptionEntry *e = RZ_NEW0(RzBinJavaExceptionEntry);
		if (!e) {
			free(attr);
			return NULL;
		}
		e->file_offset = curpos;
		e->start_pc = rz_read_at_be16(buffer, offset);
		offset += 2;
		e->end_pc = rz_read_at_be16(buffer, offset);
		offset += 2;
		e->handler_pc = rz_read_at_be16(buffer, offset);
		offset += 2;
		e->catch_type = rz_read_at_be16(buffer, offset);
		offset += 2;
		rz_list_append(attr->info.code_attr.exception_table, e);
		e->size = 8;
	}
	attr->info.code_attr.attributes_count = rz_read_at_be16(buffer, offset);
	offset += 2;
	// // eprintf ("	code Attributes_count: %d\n", attr->info.code_attr.attributes_count);
	// XXX - attr->info.code_attr.attributes is not freed because one of the code attributes is improperly parsed.
	attr->info.code_attr.attributes = rz_list_newf(rz_bin_java_free_attribute);
	if (attr->info.code_attr.attributes_count > 0) {
		for (k = 0; k < attr->info.code_attr.attributes_count; k++) {
			int size = (offset < sz) ? sz - offset : 0;
			if (size > sz || size <= 0) {
				break;
			}
			_attr = rz_bin_java_read_next_attr_from_buffer(bin, buffer + offset, size, buf_offset + offset);
			if (!_attr) {
				eprintf("[X] rz_bin_java_new_code_attr: Error unable to parse remainder of classfile after Method's Code Attribute: %d.\n", k);
				break;
			}
			// eprintf("Parsing @ 0x%" PFMT64x " (%s) = 0x%" PFMT64x " bytes, %p\n", _attr->file_offset, _attr->name, _attr->size, _attr);
			offset += _attr->size;
			rz_list_append(attr->info.code_attr.attributes, _attr);
			if (_attr->type == RZ_BIN_JAVA_ATTRIBUTE_LOCAL_VARIABLE_TABLE_ATTR) {
				// eprintf("Parsed the LocalVariableTable, preparing the implicit mthod frame.\n");
				// rz_bin_java_summary_print_attr(_attr);
				attr->info.code_attr.implicit_frame = rz_bin_java_build_stack_frame_from_local_variable_table(RZ_BIN_JAVA_GLOBAL_BIN, _attr);
				attr->info.code_attr.implicit_frame->file_offset = buf_offset;
				// rz_bin_java_summary_print_stack_map_frame(attr->info.code_attr.implicit_frame);
				// rz_list_append (attr->info.code_attr.attributes, attr->info.code_attr.implicit_frame);
			}
			// if (offset > sz) {
			// eprintf ("[X] rz_bin_java: Error unable to parse remainder of classfile after Attribute: %d.\n", k);
			// break;
			// }
		}
	}
	if (attr->info.code_attr.implicit_frame == NULL) {
		// build a default implicit_frame
		attr->info.code_attr.implicit_frame = rz_bin_java_default_stack_frame();
		// rz_list_append (attr->info.code_attr.attributes, attr->info.code_attr.implicit_frame);
	}
	attr->size = offset;
	return attr;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_constant_value_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	ut64 offset = 6;
	RzBinJavaAttrInfo *attr = rz_bin_java_new_default_attr(bin, buffer, sz, buf_offset);
	if (attr) {
		attr->type = RZ_BIN_JAVA_ATTRIBUTE_CONST_VALUE_ATTR;
		attr->info.constant_value_attr.constantvalue_idx = rz_read_at_be16(buffer, offset);
		offset += 2;
		attr->size = offset;
	}
	// // rz_bin_java_summary_print_constant_value_attr(attr);
	return attr;
}

RZ_API ut64 rz_bin_java_calc_size_constant_value_attr(RzBinJavaAttrInfo *attr) {
	return attr ? 8 : 0;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_deprecated_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	RzBinJavaAttrInfo *attr = NULL;
	ut64 offset = 0;
	attr = rz_bin_java_new_default_attr(bin, buffer, sz, buf_offset);
	offset += 6;
	if (attr) {
		attr->type = RZ_BIN_JAVA_ATTRIBUTE_DEPRECATED_ATTR;
		attr->size = offset;
	}
	// // rz_bin_java_summary_print_deprecated_attr(attr);
	return attr;
}

RZ_API ut64 rz_bin_java_calc_size_deprecated_attr(RzBinJavaAttrInfo *attr) {
	return attr ? 6 : 0;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_signature_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	ut64 offset = 6;
	RzBinJavaAttrInfo *attr = rz_bin_java_new_default_attr(bin, buffer, sz, buf_offset);
	if (!attr) {
		return NULL;
	}
	attr->type = RZ_BIN_JAVA_ATTRIBUTE_SIGNATURE_ATTR;
	// attr->info.source_file_attr.sourcefile_idx = rz_read_at_be16 (buffer, offset);
	// offset += 2;
	attr->info.signature_attr.signature_idx = rz_read_at_be16(buffer, offset);
	offset += 2;
	attr->info.signature_attr.signature = rz_bin_java_get_utf8_from_bin_cp_list(
		RZ_BIN_JAVA_GLOBAL_BIN, attr->info.signature_attr.signature_idx);
	if (!attr->info.signature_attr.signature) {
		eprintf("rz_bin_java_new_signature_attr: Unable to resolve the "
			"Signature UTF8 String Index: 0x%02x\n",
			attr->info.signature_attr.signature_idx);
	}
	attr->size = offset;
	// // rz_bin_java_summary_print_source_code_file_attr(attr);
	return attr;
}

RZ_API ut64 rz_bin_java_calc_size_signature_attr(RzBinJavaAttrInfo *attr) {
	ut64 size = 0;
	if (attr == NULL) {
		// TODO eprintf allocation fail
		return size;
	}
	size += 6;
	// attr->info.source_file_attr.sourcefile_idx = rz_read_at_be16 (buffer, offset);
	size += 2;
	// attr->info.signature_attr.signature_idx = rz_read_at_be16 (buffer, offset);
	size += 2;
	return size;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_enclosing_methods_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	ut64 offset = 6;
	RzBinJavaAttrInfo *attr = rz_bin_java_new_default_attr(bin, buffer, sz, buf_offset);
	if (!attr || sz < 10) {
		free(attr);
		return NULL;
	}
	attr->type = RZ_BIN_JAVA_ATTRIBUTE_ENCLOSING_METHOD_ATTR;
	attr->info.enclosing_method_attr.class_idx = rz_read_at_be16(buffer, offset);
	offset += 2;
	attr->info.enclosing_method_attr.method_idx = rz_read_at_be16(buffer, offset);
	offset += 2;
	attr->info.enclosing_method_attr.class_name = rz_bin_java_get_name_from_bin_cp_list(RZ_BIN_JAVA_GLOBAL_BIN, attr->info.enclosing_method_attr.class_idx);
	if (attr->info.enclosing_method_attr.class_name == NULL) {
		eprintf("Could not resolve enclosing class name for the enclosed method.\n");
	}
	attr->info.enclosing_method_attr.method_name = rz_bin_java_get_name_from_bin_cp_list(RZ_BIN_JAVA_GLOBAL_BIN, attr->info.enclosing_method_attr.method_idx);
	if (attr->info.enclosing_method_attr.class_name == NULL) {
		eprintf("Could not resolve method descriptor for the enclosed method.\n");
	}
	attr->info.enclosing_method_attr.method_descriptor = rz_bin_java_get_desc_from_bin_cp_list(RZ_BIN_JAVA_GLOBAL_BIN, attr->info.enclosing_method_attr.method_idx);
	if (attr->info.enclosing_method_attr.method_name == NULL) {
		eprintf("Could not resolve method name for the enclosed method.\n");
	}
	attr->size = offset;
	return attr;
}

RZ_API ut64 rz_bin_java_calc_size_enclosing_methods_attr(RzBinJavaAttrInfo *attr) {
	ut64 size = 0;
	if (attr) {
		size += 6;
		// attr->info.enclosing_method_attr.class_idx = rz_read_at_be16 (buffer, offset);
		size += 2;
		// attr->info.enclosing_method_attr.method_idx = rz_read_at_be16 (buffer, offset);
		size += 2;
	}
	return size;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_exceptions_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	ut32 i = 0, offset = 0;
	ut64 size;
	RzBinJavaAttrInfo *attr = NULL;
	if (sz < 8) {
		return NULL;
	}
	attr = rz_bin_java_new_default_attr(bin, buffer, sz, buf_offset);
	offset += 6;
	if (!attr) {
		return attr;
	}
	attr->type = RZ_BIN_JAVA_ATTRIBUTE_LINE_NUMBER_TABLE_ATTR;
	attr->info.exceptions_attr.number_of_exceptions = rz_read_at_be16(buffer, offset);
	offset += 2;
	size = sizeof(ut16) * attr->info.exceptions_attr.number_of_exceptions;
	if (size < attr->info.exceptions_attr.number_of_exceptions) {
		free(attr);
		return NULL;
	}
	attr->info.exceptions_attr.exception_idx_table = (ut16 *)malloc(size);
	if (!attr->info.exceptions_attr.exception_idx_table) {
		free(attr);
		return NULL;
	}
	for (i = 0; i < attr->info.exceptions_attr.number_of_exceptions; i++) {
		if (offset + 2 > sz) {
			break;
		}
		attr->info.exceptions_attr.exception_idx_table[i] = rz_read_at_be16(buffer, offset);
		offset += 2;
	}
	attr->size = offset;
	// // rz_bin_java_summary_print_exceptions_attr(attr);
	return attr;
}

RZ_API ut64 rz_bin_java_calc_size_exceptions_attr(RzBinJavaAttrInfo *attr) {
	ut64 size = 0, i = 0;
	if (attr) {
		size += 6;
		for (i = 0; i < attr->info.exceptions_attr.number_of_exceptions; i++) {
			// attr->info.exceptions_attr.exception_idx_table[i] = rz_read_at_be16 (buffer, offset);
			size += 2;
		}
	}
	return size;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_inner_classes_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	RzBinJavaClassesAttribute *icattr;
	RzBinJavaAttrInfo *attr = NULL;
	RzBinJavaCPTypeObj *obj;
	ut32 i = 0;
	ut64 offset = 0, curpos;
	attr = rz_bin_java_new_default_attr(bin, buffer, sz, buf_offset);
	offset += 6;
	if (attr == NULL) {
		// TODO eprintf
		return attr;
	}
	attr->type = RZ_BIN_JAVA_ATTRIBUTE_INNER_CLASSES_ATTR;
	attr->info.inner_classes_attr.number_of_classes = rz_read_at_be16(buffer, offset);
	offset += 2;
	attr->info.inner_classes_attr.classes = rz_list_newf(rz_bin_java_free_inner_classes_attr_entry);
	for (i = 0; i < attr->info.inner_classes_attr.number_of_classes; i++) {
		curpos = buf_offset + offset;
		if (offset + 8 > sz) {
			eprintf("Invalid amount of inner classes\n");
			break;
		}
		icattr = RZ_NEW0(RzBinJavaClassesAttribute);
		if (!icattr) {
			break;
		}
		icattr->inner_class_info_idx = rz_read_at_be16(buffer, offset);
		offset += 2;
		icattr->outer_class_info_idx = rz_read_at_be16(buffer, offset);
		offset += 2;
		icattr->inner_name_idx = rz_read_at_be16(buffer, offset);
		offset += 2;
		icattr->inner_class_access_flags = rz_read_at_be16(buffer, offset);
		offset += 2;
		icattr->flags_str = retrieve_class_method_access_string(icattr->inner_class_access_flags);
		icattr->file_offset = curpos;
		icattr->size = 8;

		obj = rz_bin_java_get_item_from_bin_cp_list(RZ_BIN_JAVA_GLOBAL_BIN, icattr->inner_name_idx);
		if (obj == NULL) {
			eprintf("BINCPLIS IS HULL %d\n", icattr->inner_name_idx);
		}
		icattr->name = rz_bin_java_get_item_name_from_bin_cp_list(RZ_BIN_JAVA_GLOBAL_BIN, obj);
		if (!icattr->name) {
			obj = rz_bin_java_get_item_from_bin_cp_list(RZ_BIN_JAVA_GLOBAL_BIN, icattr->inner_class_info_idx);
			if (!obj) {
				eprintf("BINCPLIST IS NULL %d\n", icattr->inner_class_info_idx);
			}
			icattr->name = rz_bin_java_get_item_name_from_bin_cp_list(RZ_BIN_JAVA_GLOBAL_BIN, obj);
			if (!icattr->name) {
				icattr->name = rz_str_dup(NULL, "NULL");
				eprintf("rz_bin_java_inner_classes_attr: Unable to find the name for %d index.\n", icattr->inner_name_idx);
				free(icattr);
				break;
			}
		}

		// eprintf("rz_bin_java_inner_classes_attr: Inner class name %d is %s.\n", icattr->inner_name_idx, icattr->name);
		rz_list_append(attr->info.inner_classes_attr.classes, (void *)icattr);
	}
	attr->size = offset;
	// // rz_bin_java_summary_print_inner_classes_attr(attr);
	return attr;
}

RZ_API ut64 rz_bin_java_calc_size_inner_class_attr(RzBinJavaClassesAttribute *icattr) {
	ut64 size = 0;
	if (icattr) {
		// icattr->inner_class_info_idx = rz_read_at_be16 (buffer, offset);
		size += 2;
		// icattr->outer_class_info_idx = rz_read_at_be16 (buffer, offset);
		size += 2;
		// icattr->inner_name_idx = rz_read_at_be16 (buffer, offset);
		size += 2;
		// icattr->inner_class_access_flags = rz_read_at_be16 (buffer, offset);
		size += 2;
	}
	return size;
}

RZ_API ut64 rz_bin_java_calc_size_inner_classes_attr(RzBinJavaAttrInfo *attr) {
	RzBinJavaClassesAttribute *icattr = NULL;
	RzListIter *iter;
	ut64 size = 6;
	if (!attr) {
		return 0;
	}
	rz_list_foreach (attr->info.inner_classes_attr.classes, iter, icattr) {
		size += rz_bin_java_calc_size_inner_class_attr(icattr);
	}
	return size;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_line_number_table_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	ut32 i = 0;
	ut64 curpos, offset = 0;
	RzBinJavaLineNumberAttribute *lnattr;
	if (sz < 6) {
		return NULL;
	}
	RzBinJavaAttrInfo *attr = rz_bin_java_new_default_attr(bin, buffer, sz, buf_offset);
	if (!attr) {
		return NULL;
	}
	offset += 6;
	attr->type = RZ_BIN_JAVA_ATTRIBUTE_LINE_NUMBER_TABLE_ATTR;
	attr->info.line_number_table_attr.line_number_table_length = rz_read_at_be16(buffer, offset);
	offset += 2;
	attr->info.line_number_table_attr.line_number_table = rz_list_newf(free);

	ut32 linenum_len = attr->info.line_number_table_attr.line_number_table_length;
	RzList *linenum_list = attr->info.line_number_table_attr.line_number_table;
	for (i = 0; i < linenum_len; i++) {
		curpos = buf_offset + offset;
		// printf ("%llx %llx \n", curpos, sz);
		// XXX if (curpos + 8 >= sz) break;
		lnattr = RZ_NEW0(RzBinJavaLineNumberAttribute);
		if (!lnattr) {
			break;
		}
		if (offset - 2 > sz) {
			RZ_FREE(lnattr);
			break;
		}
		lnattr->start_pc = rz_read_at_be16(buffer, offset);
		offset += 2;
		lnattr->line_number = rz_read_at_be16(buffer, offset);
		offset += 2;
		lnattr->file_offset = curpos;
		lnattr->size = 4;
		rz_list_append(linenum_list, lnattr);
	}
	attr->size = offset;
	return attr;
}

RZ_API ut64 rz_bin_java_calc_size_line_number_table_attr(RzBinJavaAttrInfo *attr) {
	ut64 size = 6;
	// RzBinJavaLineNumberAttribute *lnattr;
	RzListIter *iter;
	// RzListIter *iter_tmp;
	if (!attr) {
		return 0LL;
	}
	// rz_list_foreach_safe (attr->info.line_number_table_attr.line_number_table, iter, iter_tmp, lnattr) {
	rz_list_foreach_iter(attr->info.line_number_table_attr.line_number_table, iter) {
		// lnattr->start_pc = rz_read_at_be16 (buffer, offset);
		size += 2;
		// lnattr->line_number = rz_read_at_be16 (buffer, offset);
		size += 2;
	}
	return size;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_source_debug_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	ut64 offset = 6;
	RzBinJavaAttrInfo *attr = rz_bin_java_new_default_attr(bin, buffer, sz, buf_offset);
	if (!attr) {
		return NULL;
	}
	attr->type = RZ_BIN_JAVA_ATTRIBUTE_SOURCE_DEBUG_EXTENTSION_ATTR;
	if (attr->length == 0) {
		eprintf("rz_bin_java_new_source_debug_attr: Attempting to allocate 0 bytes for debug_extension.\n");
		attr->info.debug_extensions.debug_extension = NULL;
		return attr;
	} else if ((attr->length + offset) > sz) {
		eprintf("rz_bin_java_new_source_debug_attr: Expected %d byte(s) got %" PFMT64d " bytes for debug_extension.\n", attr->length, (offset + sz));
	}
	attr->info.debug_extensions.debug_extension = (ut8 *)malloc(attr->length);
	if (attr->info.debug_extensions.debug_extension && (attr->length > (sz - offset))) {
		memcpy(attr->info.debug_extensions.debug_extension, buffer + offset, sz - offset);
	} else if (attr->info.debug_extensions.debug_extension) {
		memcpy(attr->info.debug_extensions.debug_extension, buffer + offset, attr->length);
	} else {
		eprintf("rz_bin_java_new_source_debug_attr: Unable to allocate the data for the debug_extension.\n");
	}
	offset += attr->length;
	attr->size = offset;
	return attr;
}

RZ_API ut64 rz_bin_java_calc_size_source_debug_attr(RzBinJavaAttrInfo *attr) {
	ut64 size = 6;
	if (!attr) {
		return 0LL;
	}
	if (attr->info.debug_extensions.debug_extension) {
		size += attr->length;
	}
	return size;
}

RZ_API ut64 rz_bin_java_calc_size_local_variable_table_attr(RzBinJavaAttrInfo *attr) {
	ut64 size = 0;
	// ut64 offset = 0;
	RzListIter *iter;
	// RzBinJavaLocalVariableAttribute *lvattr;
	if (!attr) {
		return 0LL;
	}
	size += 6;
	// attr->info.local_variable_table_attr.table_length = rz_read_at_be16 (buffer, offset);
	size += 2;
	// rz_list_foreach (attr->info.local_variable_table_attr.local_variable_table, iter, lvattr) {
	rz_list_foreach_iter(attr->info.local_variable_table_attr.local_variable_table, iter) {
		// lvattr->start_pc = rz_read_at_be16 (buffer, offset);
		size += 2;
		// lvattr->length = rz_read_at_be16 (buffer, offset);
		size += 2;
		// lvattr->name_idx = rz_read_at_be16 (buffer, offset);
		size += 2;
		// lvattr->descriptor_idx = rz_read_at_be16 (buffer, offset);
		size += 2;
		// lvattr->index = rz_read_at_be16 (buffer, offset);
		size += 2;
	}
	return size;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_local_variable_table_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	RzBinJavaLocalVariableAttribute *lvattr;
	ut64 curpos = 0, offset = 6;
	RzBinJavaAttrInfo *attr;
	ut32 i = 0;
	if (!buffer || sz < 1) {
		return NULL;
	}
	attr = rz_bin_java_new_default_attr(bin, buffer, sz, buf_offset);
	if (!attr) {
		return NULL;
	}
	attr->type = RZ_BIN_JAVA_ATTRIBUTE_LOCAL_VARIABLE_TABLE_ATTR;
	attr->info.local_variable_table_attr.table_length = rz_read_at_be16(buffer, offset);
	offset += 2;
	attr->info.local_variable_table_attr.local_variable_table =
		rz_list_newf(rz_bin_java_free_local_variable_table_attr_entry);
	for (i = 0; i < attr->info.local_variable_table_attr.table_length; i++) {
		if (offset + 10 > sz) {
			break;
		}
		curpos = buf_offset + offset;
		lvattr = RZ_NEW0(RzBinJavaLocalVariableAttribute);
		lvattr->start_pc = rz_read_at_be16(buffer, offset);
		offset += 2;
		lvattr->length = rz_read_at_be16(buffer, offset);
		offset += 2;
		lvattr->name_idx = rz_read_at_be16(buffer, offset);
		offset += 2;
		lvattr->descriptor_idx = rz_read_at_be16(buffer, offset);
		offset += 2;
		lvattr->index = rz_read_at_be16(buffer, offset);
		offset += 2;
		lvattr->file_offset = curpos;
		lvattr->name = rz_bin_java_get_utf8_from_bin_cp_list(RZ_BIN_JAVA_GLOBAL_BIN, lvattr->name_idx);
		lvattr->size = 10;
		if (!lvattr->name) {
			lvattr->name = strdup("NULL");
			eprintf("rz_bin_java_new_local_variable_table_attr: Unable to find the name for %d index.\n", lvattr->name_idx);
		}
		lvattr->descriptor = rz_bin_java_get_utf8_from_bin_cp_list(RZ_BIN_JAVA_GLOBAL_BIN, lvattr->descriptor_idx);
		if (!lvattr->descriptor) {
			lvattr->descriptor = strdup("NULL");
			eprintf("rz_bin_java_new_local_variable_table_attr: Unable to find the descriptor for %d index.\n", lvattr->descriptor_idx);
		}
		rz_list_append(attr->info.local_variable_table_attr.local_variable_table, lvattr);
	}
	attr->size = offset;
	// // rz_bin_java_summary_print_local_variable_table_attr(attr);
	return attr;
}

RZ_API ut64 rz_bin_java_calc_size_local_variable_type_table_attr(RzBinJavaAttrInfo *attr) {
	// RzBinJavaLocalVariableTypeAttribute *lvattr;
	RzListIter *iter;
	ut64 size = 0;
	if (attr) {
		RzList *list = attr->info.local_variable_type_table_attr.local_variable_table;
		size += 6;
		// attr->info.local_variable_type_table_attr.table_length = rz_read_at_be16 (buffer, offset);
		size += 2;
		// rz_list_foreach (list, iter, lvattr) {
		rz_list_foreach_iter(list, iter) {
			// lvattr->start_pc = rz_read_at_be16 (buffer, offset);
			size += 2;
			// lvattr->length = rz_read_at_be16 (buffer, offset);
			size += 2;
			// lvattr->name_idx = rz_read_at_be16 (buffer, offset);
			size += 2;
			// lvattr->signature_idx = rz_read_at_be16 (buffer, offset);
			size += 2;
			// lvattr->index = rz_read_at_be16 (buffer, offset);
			size += 2;
		}
	}
	return size;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_local_variable_type_table_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	RzBinJavaLocalVariableTypeAttribute *lvattr;
	ut64 offset = 6;
	ut32 i = 0;
	RzBinJavaAttrInfo *attr = rz_bin_java_new_default_attr(bin, buffer, sz, 0);
	if (!attr) {
		return NULL;
	}
	attr->type = RZ_BIN_JAVA_ATTRIBUTE_LOCAL_VARIABLE_TYPE_TABLE_ATTR;
	attr->info.local_variable_type_table_attr.table_length = rz_read_at_be16(buffer, offset);
	offset += 2;
	attr->info.local_variable_type_table_attr.local_variable_table = rz_list_newf(rz_bin_java_free_local_variable_type_table_attr_entry);
	for (i = 0; i < attr->info.local_variable_type_table_attr.table_length; i++) {
		ut64 curpos = buf_offset + offset;
		lvattr = RZ_NEW0(RzBinJavaLocalVariableTypeAttribute);
		if (!lvattr) {
			perror("calloc");
			break;
		}
		if (offset + 10 > sz) {
			eprintf("oob");
			free(lvattr);
			break;
		}
		lvattr->start_pc = rz_read_at_be16(buffer, offset);
		offset += 2;
		lvattr->length = rz_read_at_be16(buffer, offset);
		offset += 2;
		lvattr->name_idx = rz_read_at_be16(buffer, offset);
		offset += 2;
		lvattr->signature_idx = rz_read_at_be16(buffer, offset);
		offset += 2;
		lvattr->index = rz_read_at_be16(buffer, offset);
		offset += 2;
		lvattr->file_offset = curpos;
		lvattr->name = rz_bin_java_get_utf8_from_bin_cp_list(RZ_BIN_JAVA_GLOBAL_BIN, lvattr->name_idx);
		lvattr->size = 10;
		if (!lvattr->name) {
			lvattr->name = strdup("NULL");
			eprintf("rz_bin_java_new_local_variable_type_table_attr: Unable to find the name for %d index.\n", lvattr->name_idx);
		}
		lvattr->signature = rz_bin_java_get_utf8_from_bin_cp_list(RZ_BIN_JAVA_GLOBAL_BIN, lvattr->signature_idx);
		if (!lvattr->signature) {
			lvattr->signature = strdup("NULL");
			eprintf("rz_bin_java_new_local_variable_type_table_attr: Unable to find the descriptor for %d index.\n", lvattr->signature_idx);
		}
		rz_list_append(attr->info.local_variable_type_table_attr.local_variable_table, lvattr);
	}
	// // rz_bin_java_summary_print_local_variable_type_table_attr(attr);
	attr->size = offset;
	return attr;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_source_code_file_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	if (!sz) {
		return NULL;
	}
	ut64 offset = 0;
	RzBinJavaAttrInfo *attr = rz_bin_java_new_default_attr(bin, buffer, sz, buf_offset);
	offset += 6;
	if (!attr) {
		return NULL;
	}
	attr->type = RZ_BIN_JAVA_ATTRIBUTE_SOURCE_FILE_ATTR;
	// if (buffer + offset > buffer + sz) return NULL;
	attr->info.source_file_attr.sourcefile_idx = rz_read_at_be16(buffer, offset);
	offset += 2;
	attr->size = offset;
	// // rz_bin_java_summary_print_source_code_file_attr(attr);
	return attr;
}

RZ_API ut64 rz_bin_java_calc_size_source_code_file_attr(RzBinJavaAttrInfo *attr) {
	return attr ? 8 : 0;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_synthetic_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	ut64 offset = 0;
	RzBinJavaAttrInfo *attr = rz_bin_java_new_default_attr(bin, buffer, sz, buf_offset);
	if (!attr) {
		return NULL;
	}
	offset += 6;
	attr->type = RZ_BIN_JAVA_ATTRIBUTE_SYNTHETIC_ATTR;
	attr->size = offset;
	return attr;
}

RZ_API ut64 rz_bin_java_calc_size_synthetic_attr(RzBinJavaAttrInfo *attr) {
	return attr ? 12 : 6;
}

RZ_API RzBinJavaInterfaceInfo *rz_bin_java_new_interface(RzBinJavaObj *bin, const ut8 *buffer, ut64 sz) {
	RzBinJavaInterfaceInfo *ifobj = NULL;
	ifobj = RZ_NEW0(RzBinJavaInterfaceInfo);
	// eprintf("Parsing RzBinJavaInterfaceInfo\n");
	if (ifobj) {
		if (buffer) {
			ifobj->class_info_idx = rz_read_at_be16(buffer, 0);
			ifobj->cp_class = rz_bin_java_get_item_from_bin_cp_list(bin, ifobj->class_info_idx);
			if (ifobj->cp_class) {
				ifobj->name = rz_bin_java_get_item_name_from_bin_cp_list(bin, ifobj->cp_class);
			} else {
				ifobj->name = rz_str_dup(NULL, "NULL");
			}
			ifobj->size = 2;
		} else {
			ifobj->class_info_idx = 0;
			ifobj->name = rz_str_dup(NULL, "NULL");
		}
	}
	return ifobj;
}

RZ_API RzBinJavaVerificationObj *rz_bin_java_verification_info_from_type(RzBinJavaObj *bin, RzBinJavaStackmapType type, ut32 value) {
	RzBinJavaVerificationObj *se = RZ_NEW0(RzBinJavaVerificationObj);
	if (!se) {
		return NULL;
	}
	se->tag = type;
	if (se->tag == RZ_BIN_JAVA_STACKMAP_OBJECT) {
		se->info.obj_val_cp_idx = (ut16)value;
	} else if (se->tag == RZ_BIN_JAVA_STACKMAP_UNINIT) {
		/*if (bin->offset_sz == 4) {
		se->info.uninit_offset = value;
		} else {
		se->info.uninit_offset = (ut16) value;
		}*/
		se->info.uninit_offset = (ut16)value;
	}
	return se;
}

RZ_API RzBinJavaVerificationObj *rz_bin_java_new_read_from_buffer_verification_info(ut8 *buffer, ut64 sz, ut64 buf_offset) {
	ut64 offset = 0;
	RzBinJavaVerificationObj *se = RZ_NEW0(RzBinJavaVerificationObj);
	if (!se) {
		return NULL;
	}
	se->file_offset = buf_offset;
	se->tag = buffer[offset];
	offset += 1;
	if (se->tag == RZ_BIN_JAVA_STACKMAP_OBJECT) {
		se->info.obj_val_cp_idx = rz_read_at_be16(buffer, offset);
		offset += 2;
	} else if (se->tag == RZ_BIN_JAVA_STACKMAP_UNINIT) {
		se->info.uninit_offset = rz_read_at_be16(buffer, offset);
		offset += 2;
	}
	if (RZ_BIN_JAVA_STACKMAP_UNINIT < se->tag) {
		rz_bin_java_free_verification_info(se);
		return NULL;
	}
	se->size = offset;
	return se;
}

RZ_API ut64 rbin_java_verification_info_calc_size(RzBinJavaVerificationObj *se) {
	ut64 sz = 1;
	if (!se) {
		return 0;
	}
	// rz_buf_read_at (bin->b, offset, (ut8*)(&se->tag), 1)
	switch (se->tag) {
	case RZ_BIN_JAVA_STACKMAP_OBJECT:
		// rz_buf_read_at (bin->b, offset+1, (ut8*)buf, 2)
		sz += 2;
		break;
	case RZ_BIN_JAVA_STACKMAP_UNINIT:
		// rz_buf_read_at (bin->b, offset+1, (ut8*)buf, 2)
		sz += 2;
		break;
	}
	return sz;
}

RZ_API RzBinJavaStackMapFrameMetas *rz_bin_java_determine_stack_frame_type(ut8 tag) {
	ut8 type_value = 0;
	if (tag < 64) {
		type_value = RZ_BIN_JAVA_STACK_FRAME_SAME;
	} else if (tag < 128) {
		type_value = RZ_BIN_JAVA_STACK_FRAME_SAME_LOCALS_1;
	} else if (247 < tag && tag < 251) {
		type_value = RZ_BIN_JAVA_STACK_FRAME_CHOP;
	} else if (tag == 251) {
		type_value = RZ_BIN_JAVA_STACK_FRAME_SAME_FRAME_EXTENDED;
	} else if (251 < tag && tag < 255) {
		type_value = RZ_BIN_JAVA_STACK_FRAME_APPEND;
	} else if (tag == 255) {
		type_value = RZ_BIN_JAVA_STACK_FRAME_FULL_FRAME;
	} else {
		type_value = RZ_BIN_JAVA_STACK_FRAME_RESERVED;
	}
	return &RZ_BIN_JAVA_STACK_MAP_FRAME_METAS[type_value];
}

RZ_API ut64 rz_bin_java_calc_size_stack_map_frame(RzBinJavaStackMapFrame *sf) {
	ut64 size = 0;
	RzListIter *iter, *iter_tmp;
	RzBinJavaVerificationObj *se;
	if (sf) {
		// sf->tag = buffer[offset];
		size += 1;
		switch (sf->type) {
		case RZ_BIN_JAVA_STACK_FRAME_SAME:
			// Nothing to read
			break;
		case RZ_BIN_JAVA_STACK_FRAME_SAME_LOCALS_1:
			rz_list_foreach_safe (sf->stack_items, iter, iter_tmp, se) {
				size += rbin_java_verification_info_calc_size(se);
			}
			break;
		case RZ_BIN_JAVA_STACK_FRAME_CHOP:
			// sf->offset_delta = rz_read_at_be16 (buffer, offset);
			size += 2;
			break;
		case RZ_BIN_JAVA_STACK_FRAME_SAME_FRAME_EXTENDED:
			// sf->offset_delta = rz_read_at_be16 (buffer, offset);
			size += 2;
			rz_list_foreach_safe (sf->stack_items, iter, iter_tmp, se) {
				size += rbin_java_verification_info_calc_size(se);
			}
			break;
		case RZ_BIN_JAVA_STACK_FRAME_APPEND:
			// sf->offset_delta = rz_read_at_be16 (buffer, offset);
			size += 2;
			rz_list_foreach_safe (sf->stack_items, iter, iter_tmp, se) {
				size += rbin_java_verification_info_calc_size(se);
			}
			break;
		case RZ_BIN_JAVA_STACK_FRAME_FULL_FRAME:
			// sf->offset_delta = rz_read_at_be16 (buffer, offset);
			size += 2;
			// sf->number_of_locals = rz_read_at_be16 (buffer, offset);
			size += 2;
			rz_list_foreach_safe (sf->local_items, iter, iter_tmp, se) {
				size += rbin_java_verification_info_calc_size(se);
			}
			// sf->number_of_stack_items = rz_read_at_be16 (buffer, offset);
			size += 2;
			rz_list_foreach_safe (sf->stack_items, iter, iter_tmp, se) {
				size += rbin_java_verification_info_calc_size(se);
			}
			break;
		default:
			eprintf("Unknown type\n");
			break;
		}
	}
	return size;
}

RZ_API RzBinJavaStackMapFrame *rz_bin_java_new_stack_map_frame(ut8 *buffer, ut64 sz, RzBinJavaStackMapFrame *p_frame, ut64 buf_offset) {
	RzBinJavaStackMapFrame *stack_frame = rz_bin_java_default_stack_frame();
	if (!stack_frame) {
		return NULL;
	}

	RzBinJavaVerificationObj *se = NULL;
	ut64 offset = 0;
	ut16 k;
	ut32 i;

	stack_frame->tag = buffer[offset];
	offset += 1;
	stack_frame->metas->type_info = (void *)rz_bin_java_determine_stack_frame_type(stack_frame->tag);
	stack_frame->type = ((RzBinJavaStackMapFrameMetas *)stack_frame->metas->type_info)->type;
	stack_frame->file_offset = buf_offset;
	stack_frame->p_stack_frame = p_frame;
	switch (stack_frame->type) {
	case RZ_BIN_JAVA_STACK_FRAME_SAME:
		// Maybe?  1. Copy the previous frames locals and set the locals count.
		// copy_type_info_to_stack_frame_list_up_to_idx (p_frame->local_items, stack_frame->local_items, idx);
		if (p_frame) {
			stack_frame->number_of_locals = p_frame->number_of_locals;
		} else {
			// eprintf("><?><\n");
			// eprintf("Unable to set previous stackframe with the number of locals (current info.code_attr.implicit_frame was probably not set :/)");
		}
		// eprintf("rz_bin_java_new_stack_map_frame: TODO Stack Frame Same Locals Condition is untested, so there may be issues.\n");
		break;
	case RZ_BIN_JAVA_STACK_FRAME_SAME_LOCALS_1:
		// 1. Read the stack type
		stack_frame->number_of_stack_items = 1;
		if (offset > sz) {
			rz_bin_java_free_stack_frame(stack_frame);
			return NULL;
		}
		se = rz_bin_java_new_read_from_buffer_verification_info(buffer + offset, sz - offset, buf_offset + offset);
		// eprintf("rz_bin_java_new_stack_map_frame: Parsed RZ_BIN_JAVA_STACK_FRAME_SAME_LOCALS_1.\n");
		if (se) {
			offset += se->size;
		} else {
			eprintf("rz_bin_java_new_stack_map_frame: Unable to parse the Stack Items for the stack frame.\n");
			rz_bin_java_free_stack_frame(stack_frame);
			return NULL;
		}
		rz_list_append(stack_frame->stack_items, (void *)se);
		// Maybe?  3. Copy the previous frames locals and set the locals count.
		// copy_type_info_to_stack_frame_list_up_to_idx (p_frame->local_items, stack_frame->local_items, idx);
		if (p_frame) {
			stack_frame->number_of_locals = p_frame->number_of_locals;
		} else {
			// eprintf("Unable to set previous stackframe with the number of locals (current info.code_attr.implicit_frame was probably not set :/)");
		}
		// eprintf("rz_bin_java_new_stack_map_frame: TODO Stack Frame Same Locals 1 Stack Element Condition is untested, so there may be issues.\n");
		break;
	case RZ_BIN_JAVA_STACK_FRAME_CHOP:
		// 1. Calculate the max index we want to copy from the list of the
		// previous frames locals
		// eprintf("rz_bin_java_new_stack_map_frame: Parsing RZ_BIN_JAVA_STACK_FRAME_CHOP.\n");
		// ut16 k = 251 - stack_frame->tag;
		/*,
		idx = p_frame->number_of_locals - k;
		*/
		// 2.  read the uoffset value
		stack_frame->offset_delta = rz_read_at_be16(buffer, offset);
		offset += 2;
		// Maybe? 3. Copy the previous frames locals and set the locals count.
		// copy_type_info_to_stack_frame_list_up_to_idx (p_frame->local_items, stack_frame->local_items, idx);
		if (p_frame) {
			stack_frame->number_of_locals = p_frame->number_of_locals;
		} else {
			// eprintf("><?><\n");
			// eprintf("Unable to set previous stackframe with the number of locals (current info.code_attr.implicit_frame was probably not set :/)");
		}
		// eprintf("rz_bin_java_new_stack_map_frame: TODO Stack Frame Chop Condition is untested, so there may be issues.\n");
		break;
	case RZ_BIN_JAVA_STACK_FRAME_SAME_FRAME_EXTENDED:
		// eprintf("rz_bin_java_new_stack_map_frame: Parsing RZ_BIN_JAVA_STACK_FRAME_SAME_FRAME_EXTENDED.\n");
		// 1. Read the uoffset
		stack_frame->offset_delta = rz_read_at_be16(buffer, offset);
		offset += 2;
		// 2. Read the stack element type
		stack_frame->number_of_stack_items = 1;
		se = rz_bin_java_new_read_from_buffer_verification_info(buffer + offset, sz - offset, buf_offset + offset);
		if (se) {
			offset += se->size;
		} else {
			eprintf("rz_bin_java_new_stack_map_frame: Unable to parse the Stack Items for the stack frame.\n");
			rz_bin_java_free_stack_frame(stack_frame);
			return NULL;
		}
		rz_list_append(stack_frame->stack_items, (void *)se);
		// Maybe? 3. Copy the previous frames locals to the current locals
		// copy_type_info_to_stack_frame_list_up_to_idx (p_frame->local_items, stack_frame->local_items, idx);
		if (p_frame) {
			stack_frame->number_of_locals = p_frame->number_of_locals;
		} else {
			// eprintf("><?><\n");
			// eprintf("Unable to set previous stackframe with the number of locals (current info.code_attr.implicit_frame was probably not set :/)");
		}
		// eprintf("rz_bin_java_new_stack_map_frame: TODO Stack Frame Same Locals Frame Stack 1 Extended Condition is untested, so there may be issues.\n");
		break;
	case RZ_BIN_JAVA_STACK_FRAME_APPEND:
		// eprintf("rz_bin_java_new_stack_map_frame: Parsing RZ_BIN_JAVA_STACK_FRAME_APPEND.\n");
		// 1. Calculate the max index we want to copy from the list of the
		// previous frames locals
		k = stack_frame->tag - 251;
		// 2. Read the uoffset
		stack_frame->offset_delta = rz_read_at_be16(buffer, offset);
		offset += 2;
		// Maybe? 3. Copy the previous frames locals to the current locals
		// copy_type_info_to_stack_frame_list_up_to_idx (p_frame->local_items, stack_frame->local_items, idx);
		// 4. Read off the rest of the appended locals types
		for (i = 0; i < k; i++) {
			if (offset >= sz) {
				break;
			}
			// eprintf("rz_bin_java_new_stack_map_frame: Parsing verifying the k'th frame: %d of %d.\n", i, k);
			se = rz_bin_java_new_read_from_buffer_verification_info(buffer + offset, sz - offset, buf_offset + offset);
			// eprintf("rz_bin_java_new_stack_map_frame: Completed Parsing\n");
			if (se) {
				offset += se->size;
			} else {
				eprintf("rz_bin_java_new_stack_map_frame: Unable to parse the locals for the stack frame.\n");
				rz_bin_java_free_stack_frame(stack_frame);
				return NULL;
			}
			rz_list_append(stack_frame->local_items, (void *)se);
		}
		// eprintf("rz_bin_java_new_stack_map_frame: Breaking out of loop");
		// eprintf("p_frame: %p\n", p_frame);
		if (p_frame) {
			stack_frame->number_of_locals = p_frame->number_of_locals + k;
		} else {
			// eprintf("><?><\n");
			// eprintf("Unable to set previous stackframe with the number of locals (current info.code_attr.implicit_frame was probably not set :/)");
		}
		// eprintf("rz_bin_java_new_stack_map_frame: TODO Stack Frame Same Locals Frame Stack 1 Extended Condition is untested, so there may be issues.\n");
		break;
	case RZ_BIN_JAVA_STACK_FRAME_FULL_FRAME:
		// eprintf("rz_bin_java_new_stack_map_frame: Parsing RZ_BIN_JAVA_STACK_FRAME_FULL_FRAME.\n");
		stack_frame->offset_delta = rz_read_at_be16(buffer, offset);
		offset += 2;
		// // eprintf ("rz_bin_java_new_stack_map_frame: Code Size > 65535, read(%d byte(s)), offset = 0x%08x.\n", var_sz, stack_frame->offset_delta);
		// Read the number of variables based on the max # local variable
		stack_frame->number_of_locals = rz_read_at_be16(buffer, offset);
		offset += 2;
		// // eprintf ("rz_bin_java_new_stack_map_frame: Max ulocalvar > 65535, read(%d byte(s)), number_of_locals = 0x%08x.\n", var_sz, stack_frame->number_of_locals);
		// rz_bin_java_summary_print_stack_map_frame(stack_frame);
		// read the number of locals off the stack
		for (i = 0; i < stack_frame->number_of_locals; i++) {
			if (offset >= sz) {
				break;
			}
			se = rz_bin_java_new_read_from_buffer_verification_info(buffer + offset, sz - offset, buf_offset + offset);
			if (se) {
				offset += se->size;
				// rz_list_append (stack_frame->local_items, (void *) se);
			} else {
				eprintf("rz_bin_java_new_stack_map_frame: Unable to parse the locals for the stack frame.\n");
				rz_bin_java_free_stack_frame(stack_frame);
				return NULL;
			}
			rz_list_append(stack_frame->local_items, (void *)se);
		}
		// Read the number of stack items based on the max size of stack
		stack_frame->number_of_stack_items = rz_read_at_be16(buffer, offset);
		offset += 2;
		// // eprintf ("rz_bin_java_new_stack_map_frame: Max ustack items > 65535, read(%d byte(s)), number_of_locals = 0x%08x.\n", var_sz, stack_frame->number_of_stack_items);
		// read the stack items
		for (i = 0; i < stack_frame->number_of_stack_items; i++) {
			if (offset >= sz) {
				break;
			}
			se = rz_bin_java_new_read_from_buffer_verification_info(buffer + offset, sz - offset, buf_offset + offset);
			if (se) {
				offset += se->size;
				// rz_list_append (stack_frame->stack_items, (void *) se);
			} else {
				eprintf("rz_bin_java_new_stack_map_frame: Unable to parse the stack items for the stack frame.\n");
				rz_bin_java_free_stack_frame(stack_frame);
				return NULL;
			}
			rz_list_append(stack_frame->local_items, (void *)se);
		}
		break;
	default:
		eprintf("java: Unknown type\n");
		break;
	}
	// // eprintf ("Created a stack frame at offset(0x%08"PFMT64x") of size: %d\n", buf_offset, stack_frame->size);//rz_bin_java_summary_print_stack_map_frame(stack_frame);
	stack_frame->size = offset;
	// // rz_bin_java_summary_print_stack_map_frame(stack_frame);
	return stack_frame;
}

RZ_API ut16 rz_bin_java_find_cp_class_ref_from_name_idx(RzBinJavaObj *bin, ut16 name_idx) {
	ut16 pos, len = (ut16)rz_list_length(bin->cp_list);
	RzBinJavaCPTypeObj *item;
	for (pos = 0; pos < len; pos++) {
		item = (RzBinJavaCPTypeObj *)rz_list_get_n(bin->cp_list, pos);
		if (item && item->tag == RZ_BIN_JAVA_CP_CLASS && item->info.cp_class.name_idx == name_idx) {
			break;
		}
	}
	return (pos != len) ? pos : 0;
}

RZ_API RzBinJavaStackMapFrame *rz_bin_java_default_stack_frame(void) {
	RzBinJavaStackMapFrame *sf = RZ_NEW0(RzBinJavaStackMapFrame);
	if (!sf) {
		return NULL;
	}
	sf->metas = RZ_NEW0(RzBinJavaMetaInfo);
	if (!sf->metas) {
		free(sf);
		return NULL;
	}
	sf->metas->type_info = (void *)&RZ_BIN_JAVA_STACK_MAP_FRAME_METAS[RZ_BIN_JAVA_STACK_FRAME_IMPLICIT];
	sf->type = ((RzBinJavaStackMapFrameMetas *)sf->metas->type_info)->type;
	sf->local_items = rz_list_newf(rz_bin_java_free_verification_info);
	sf->stack_items = rz_list_newf(rz_bin_java_free_verification_info);
	sf->number_of_stack_items = 0;
	sf->number_of_locals = 0;
	return sf;
}

RZ_API RzBinJavaStackMapFrame *rz_bin_java_build_stack_frame_from_local_variable_table(RzBinJavaObj *bin, RzBinJavaAttrInfo *attr) {
	RzBinJavaStackMapFrame *sf = rz_bin_java_default_stack_frame();
	RzBinJavaLocalVariableAttribute *lvattr = NULL;
	RzBinJavaVerificationObj *type_item;
	RzListIter *iter = NULL;
	ut32 value_cnt = 0;
	ut8 value;
	if (!sf || !bin || !attr || attr->type != RZ_BIN_JAVA_ATTRIBUTE_LOCAL_VARIABLE_TABLE_ATTR) {
		eprintf("Attempting to create a stack_map frame from a bad attribute.\n");
		return sf;
	}
	sf->number_of_locals = attr->info.local_variable_table_attr.table_length;
	rz_list_foreach (attr->info.local_variable_table_attr.local_variable_table, iter, lvattr) {
		ut32 pos = 0;
		// knock the array Types
		while (lvattr->descriptor[pos] == '[') {
			pos++;
		}
		value = lvattr->descriptor[pos];
		// // eprintf ("Found the following type value: %c at pos %d in %s\n", value, pos, lvattr->descriptor);
		switch (value) {
		case 'I':
		case 'Z':
		case 'S':
		case 'B':
		case 'C':
			type_item = rz_bin_java_verification_info_from_type(bin, RZ_BIN_JAVA_STACKMAP_INTEGER, 0);
			break;
		case 'F':
			type_item = rz_bin_java_verification_info_from_type(bin, RZ_BIN_JAVA_STACKMAP_FLOAT, 0);
			break;
		case 'D':
			type_item = rz_bin_java_verification_info_from_type(bin, RZ_BIN_JAVA_STACKMAP_DOUBLE, 0);
			break;
		case 'J':
			type_item = rz_bin_java_verification_info_from_type(bin, RZ_BIN_JAVA_STACKMAP_LONG, 0);
			break;
		case 'L':
			// TODO: FIXME write something that will iterate over the CP Pool and find the
			// CONSTANT_Class_info referencing this
			{
				ut16 idx = rz_bin_java_find_cp_class_ref_from_name_idx(bin, lvattr->name_idx);
				type_item = rz_bin_java_verification_info_from_type(bin, RZ_BIN_JAVA_STACKMAP_OBJECT, idx);
			}
			break;
		default:
			eprintf("rz_bin_java_build_stack_frame_from_local_variable_table: "
				"not sure how to handle: name: %s, type: %s\n",
				lvattr->name, lvattr->descriptor);
			type_item = rz_bin_java_verification_info_from_type(bin, RZ_BIN_JAVA_STACKMAP_NULL, 0);
		}
		if (type_item) {
			rz_list_append(sf->local_items, (void *)type_item);
		}
		value_cnt++;
	}
	// if (value_cnt != attr->info.local_variable_table_attr.table_length) {
	// 	eprintf("rz_bin_java_build_stack_frame_from_local_variable_table: "
	// 	       "Number of locals not accurate.  Expected %d but got %d",
	// 	 attr->info.local_variable_table_attr.table_length, value_cnt);
	// }
	return sf;
}

RZ_API ut64 rz_bin_java_calc_size_stack_map_table_attr(RzBinJavaAttrInfo *attr) {
	ut64 size = 0;
	RzListIter *iter, *iter_tmp;
	RzBinJavaStackMapFrame *sf;
	if (attr) {
		// attr = rz_bin_java_new_default_attr (buffer, sz, buf_offset);
		size += 6;
		// // rz_bin_java_summary_print_source_code_file_attr(attr);
		// Current spec does not call for variable sizes.
		// attr->info.stack_map_table_attr.number_of_entries = rz_read_at_be16 (buffer, offset);
		size += 2;
		rz_list_foreach_safe (attr->info.stack_map_table_attr.stack_map_frame_entries, iter, iter_tmp, sf) {
			size += rz_bin_java_calc_size_stack_map_frame(sf);
		}
	}
	return size;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_stack_map_table_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	ut32 i = 0;
	ut64 offset = 0;
	RzBinJavaStackMapFrame *stack_frame = NULL, *new_stack_frame = NULL;
	if (sz < 10) {
		return NULL;
	}
	RzBinJavaAttrInfo *attr = rz_bin_java_new_default_attr(bin, buffer, sz, buf_offset);
	offset += 6;
	// eprintf("rz_bin_java_new_stack_map_table_attr: New stack map allocated.\n");
	if (!attr) {
		return NULL;
	}
	attr->info.stack_map_table_attr.stack_map_frame_entries = rz_list_newf(rz_bin_java_free_stack_frame);
	// // rz_bin_java_summary_print_source_code_file_attr(attr);
	// Current spec does not call for variable sizes.
	attr->info.stack_map_table_attr.number_of_entries = rz_read_at_be16(buffer, offset);
	offset += 2;
	// eprintf("rz_bin_java_new_stack_map_table_attr: Processing stack map, summary is:\n");
	// rz_bin_java_summary_print_stack_map_table_attr(attr);
	for (i = 0; i < attr->info.stack_map_table_attr.number_of_entries; i++) {
		// read next stack frame
		// eprintf("Reading StackMap Entry #%d @ 0x%08" PFMT64x "\n", i, buf_offset + offset);
		if (stack_frame == NULL && RZ_BIN_JAVA_GLOBAL_BIN && RZ_BIN_JAVA_GLOBAL_BIN->current_code_attr) {
			// eprintf("Setting an implicit frame at #%d @ 0x%08" PFMT64x "\n", i, buf_offset + offset);
			stack_frame = RZ_BIN_JAVA_GLOBAL_BIN->current_code_attr->info.code_attr.implicit_frame;
		}
		// eprintf("Reading StackMap Entry #%d @ 0x%08" PFMT64x ", current stack_frame: %p\n", i, buf_offset + offset, stack_frame);
		if (offset >= sz) {
			rz_bin_java_free_stack_map_table_attr(attr);
			return NULL;
		}
		new_stack_frame = rz_bin_java_new_stack_map_frame(buffer + offset, sz - offset, stack_frame, buf_offset + offset);
		if (new_stack_frame) {
			offset += new_stack_frame->size;
			// append stack frame to the list
			rz_list_append(attr->info.stack_map_table_attr.stack_map_frame_entries, (void *)new_stack_frame);
			stack_frame = new_stack_frame;
		} else {
			eprintf("rz_bin_java_new_stack_map_table_attr: Unable to parse the stack frame for the stack map table.\n");
			rz_bin_java_free_stack_map_table_attr(attr);
			attr = NULL;
			break;
		}
	}
	if (attr) {
		attr->size = offset;
	}
	return attr;
}
// End attribute types new
// Start new Constant Pool Types
RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_do_nothing(RzBinJavaObj *bin, ut8 *buffer, ut64 sz) {
	return (RzBinJavaCPTypeObj *)NULL;
}

RZ_API ut64 rz_bin_java_calc_size_do_nothing(RzBinJavaCPTypeObj *obj) {
	return 0;
}

RZ_API void rz_bin_java_free_do_nothing(void /*RzBinJavaCPTypeObj*/ *obj) {
	return;
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_unknown_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 sz) {
	ut8 tag = buffer[0];
	RzBinJavaCPTypeObj *obj = NULL;
	obj = (RzBinJavaCPTypeObj *)malloc(sizeof(RzBinJavaCPTypeObj));
	if (obj) {
		memset(obj, 0, sizeof(RzBinJavaCPTypeObj));
		obj->tag = tag;
		obj->metas = RZ_NEW0(RzBinJavaMetaInfo);
		obj->metas->type_info = (void *)&RZ_BIN_JAVA_CP_METAS[RZ_BIN_JAVA_CP_UNKNOWN];
	}
	return obj;
}

RZ_API ut64 rz_bin_java_calc_size_unknown_cp(RzBinJavaCPTypeObj *obj) {
	return 1LL;
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_class_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 sz) {
	ut8 tag = buffer[0];
	int quick_check = rz_bin_java_quick_check(RZ_BIN_JAVA_CP_CLASS, tag, sz, "Class");
	if (quick_check > 0) {
		return NULL;
	}
	RzBinJavaCPTypeObj *obj = RZ_NEW0(RzBinJavaCPTypeObj);
	if (obj) {
		obj->tag = tag;
		obj->metas = RZ_NEW0(RzBinJavaMetaInfo);
		obj->metas->type_info = (void *)&RZ_BIN_JAVA_CP_METAS[tag];
		obj->info.cp_class.name_idx = rz_read_at_be16(buffer, 1);
	}
	return obj;
}

RZ_API ut64 rz_bin_java_calc_size_class_cp(RzBinJavaCPTypeObj *obj) {
	ut64 size = 0;
	// ut8 tag = buffer[0];
	size += 1;
	// obj->info.cp_class.name_idx = rz_read_at_be16 (buffer, 1);
	size += 2;
	return size;
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_fieldref_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 sz) {
	ut8 tag = buffer[0];
	RzBinJavaCPTypeObj *obj = NULL;
	int quick_check = 0;
	quick_check = rz_bin_java_quick_check(RZ_BIN_JAVA_CP_FIELDREF, tag, sz, "FieldRef");
	if (quick_check > 0) {
		return obj;
	}
	obj = (RzBinJavaCPTypeObj *)malloc(sizeof(RzBinJavaCPTypeObj));
	if (obj) {
		memset(obj, 0, sizeof(RzBinJavaCPTypeObj));
		obj->tag = tag;
		obj->metas = RZ_NEW0(RzBinJavaMetaInfo);
		obj->metas->type_info = (void *)&RZ_BIN_JAVA_CP_METAS[tag];
		obj->info.cp_field.class_idx = rz_read_at_be16(buffer, 1);
		obj->info.cp_field.name_and_type_idx = rz_read_at_be16(buffer, 3);
	}
	return (RzBinJavaCPTypeObj *)obj;
}

RZ_API ut64 rz_bin_java_calc_size_fieldref_cp(RzBinJavaCPTypeObj *obj) {
	ut64 size = 0;
	// tag
	size += 1;
	// obj->info.cp_field.class_idx = rz_read_at_be16 (buffer, 1);
	size += 2;
	// obj->info.cp_field.name_and_type_idx = rz_read_at_be16 (buffer, 3);
	size += 2;
	return size;
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_methodref_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 sz) {
	ut8 tag = buffer[0];
	RzBinJavaCPTypeObj *obj = NULL;
	int quick_check = 0;
	quick_check = rz_bin_java_quick_check(RZ_BIN_JAVA_CP_METHODREF, tag, sz, "MethodRef");
	if (quick_check > 0) {
		return obj;
	}
	obj = (RzBinJavaCPTypeObj *)malloc(sizeof(RzBinJavaCPTypeObj));
	if (obj) {
		memset(obj, 0, sizeof(RzBinJavaCPTypeObj));
		obj->tag = tag;
		obj->metas = RZ_NEW0(RzBinJavaMetaInfo);
		obj->metas->type_info = (void *)&RZ_BIN_JAVA_CP_METAS[tag];
		obj->info.cp_method.class_idx = rz_read_at_be16(buffer, 1);
		obj->info.cp_method.name_and_type_idx = rz_read_at_be16(buffer, 3);
	}
	return obj;
}

RZ_API ut64 rz_bin_java_calc_size_methodref_cp(RzBinJavaCPTypeObj *obj) {
	ut64 size = 0;
	// tag
	size += 1;
	// obj->info.cp_method.class_idx = rz_read_at_be16 (buffer, 1);
	size += 2;
	// obj->info.cp_method.name_and_type_idx = rz_read_at_be16 (buffer, 3);
	size += 2;
	return size;
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_interfacemethodref_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 sz) {
	ut8 tag = buffer[0];
	int quick_check = rz_bin_java_quick_check(RZ_BIN_JAVA_CP_INTERFACEMETHOD_REF, tag, sz, "InterfaceMethodRef");
	if (quick_check > 0) {
		return NULL;
	}
	RzBinJavaCPTypeObj *obj = RZ_NEW0(RzBinJavaCPTypeObj);
	if (obj) {
		obj->tag = tag;
		obj->metas = RZ_NEW0(RzBinJavaMetaInfo);
		obj->metas->type_info = (void *)&RZ_BIN_JAVA_CP_METAS[tag];
		obj->name = rz_str_dup(NULL, (const char *)RZ_BIN_JAVA_CP_METAS[tag].name);
		obj->info.cp_interface.class_idx = rz_read_at_be16(buffer, 1);
		obj->info.cp_interface.name_and_type_idx = rz_read_at_be16(buffer, 3);
	}
	return obj;
}

RZ_API ut64 rz_bin_java_calc_size_interfacemethodref_cp(RzBinJavaCPTypeObj *obj) {
	ut64 size = 0;
	// tag
	size += 1;
	// obj->info.cp_interface.class_idx = rz_read_at_be16 (buffer, 1);
	size += 2;
	// obj->info.cp_interface.name_and_type_idx = rz_read_at_be16 (buffer, 3);
	size += 2;
	return size;
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_string_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 sz) {
	ut8 tag = buffer[0];
	int quick_check = rz_bin_java_quick_check(RZ_BIN_JAVA_CP_STRING, tag, sz, "String");
	if (quick_check > 0) {
		return NULL;
	}
	RzBinJavaCPTypeObj *obj = RZ_NEW0(RzBinJavaCPTypeObj);
	if (obj) {
		obj->tag = tag;
		obj->metas = RZ_NEW0(RzBinJavaMetaInfo);
		obj->metas->type_info = (void *)&RZ_BIN_JAVA_CP_METAS[tag];
		obj->name = rz_str_dup(NULL, (const char *)RZ_BIN_JAVA_CP_METAS[tag].name);
		obj->info.cp_string.string_idx = rz_read_at_be16(buffer, 1);
	}
	return obj;
}

RZ_API ut64 rz_bin_java_calc_size_string_cp(RzBinJavaCPTypeObj *obj) {
	ut64 size = 0;
	// tag
	size += 1;
	// obj->info.cp_string.string_idx = rz_read_at_be16 (buffer, 1);
	size += 2;
	return size;
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_integer_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 sz) {
	ut8 tag = buffer[0];
	RzBinJavaCPTypeObj *obj = NULL;
	int quick_check = 0;
	quick_check = rz_bin_java_quick_check(RZ_BIN_JAVA_CP_INTEGER, tag, sz, "Integer");
	if (quick_check > 0) {
		return obj;
	}
	obj = (RzBinJavaCPTypeObj *)RZ_NEW0(RzBinJavaCPTypeObj);
	if (obj) {
		obj->tag = tag;
		obj->metas = RZ_NEW0(RzBinJavaMetaInfo);
		obj->metas->type_info = (void *)&RZ_BIN_JAVA_CP_METAS[tag];
		obj->name = rz_str_dup(NULL, (const char *)RZ_BIN_JAVA_CP_METAS[tag].name);
		memset(&obj->info.cp_integer.bytes, 0, sizeof(obj->info.cp_integer.bytes));
		memcpy(&obj->info.cp_integer.bytes.raw, buffer + 1, 4);
	}
	return obj;
}

RZ_API ut64 rz_bin_java_calc_size_integer_cp(RzBinJavaCPTypeObj *obj) {
	ut64 size = 0;
	// tag
	size += 1;
	// obj->info.cp_string.string_idx = rz_read_at_be16 (buffer, 1);
	size += 4;
	return size;
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_float_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 sz) {
	ut8 tag = buffer[0];
	RzBinJavaCPTypeObj *obj = NULL;
	int quick_check = 0;
	quick_check = rz_bin_java_quick_check(RZ_BIN_JAVA_CP_FLOAT, tag, sz, "Float");
	if (quick_check > 0) {
		return obj;
	}
	obj = (RzBinJavaCPTypeObj *)calloc(1, sizeof(RzBinJavaCPTypeObj));
	if (obj) {
		obj->tag = tag;
		obj->metas = RZ_NEW0(RzBinJavaMetaInfo);
		obj->metas->type_info = (void *)&RZ_BIN_JAVA_CP_METAS[tag];
		obj->name = rz_str_dup(NULL, (const char *)RZ_BIN_JAVA_CP_METAS[tag].name);
		memset(&obj->info.cp_float.bytes, 0, sizeof(obj->info.cp_float.bytes));
		memcpy(&obj->info.cp_float.bytes.raw, buffer, 4);
	}
	return (RzBinJavaCPTypeObj *)obj;
}

RZ_API ut64 rz_bin_java_calc_size_float_cp(RzBinJavaCPTypeObj *obj) {
	ut64 size = 0;
	// tag
	size += 1;
	// obj->info.cp_string.string_idx = rz_read_at_be16 (buffer, 1);
	size += 4;
	return size;
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_long_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 sz) {
	ut8 tag = buffer[0];
	RzBinJavaCPTypeObj *obj = NULL;
	int quick_check = 0;
	quick_check = rz_bin_java_quick_check(RZ_BIN_JAVA_CP_LONG, tag, sz, "Long");
	if (quick_check > 0) {
		return obj;
	}
	obj = (RzBinJavaCPTypeObj *)malloc(sizeof(RzBinJavaCPTypeObj));
	if (obj) {
		memset(obj, 0, sizeof(RzBinJavaCPTypeObj));
		obj->tag = tag;
		obj->metas = RZ_NEW0(RzBinJavaMetaInfo);
		obj->metas->type_info = (void *)&RZ_BIN_JAVA_CP_METAS[tag];
		obj->name = rz_str_dup(NULL, (const char *)RZ_BIN_JAVA_CP_METAS[tag].name);
		memset(&obj->info.cp_long.bytes, 0, sizeof(obj->info.cp_long.bytes));
		memcpy(&(obj->info.cp_long.bytes), buffer + 1, 8);
	}
	return obj;
}

RZ_API ut64 rz_bin_java_calc_size_long_cp(RzBinJavaCPTypeObj *obj) {
	ut64 size = 0;
	// tag
	size += 1;
	// obj->info.cp_string.string_idx = rz_read_at_be16 (buffer, 1);
	size += 8;
	return size;
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_double_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 sz) {
	ut8 tag = buffer[0];
	RzBinJavaCPTypeObj *obj = NULL;
	int quick_check = 0;
	quick_check = rz_bin_java_quick_check(RZ_BIN_JAVA_CP_DOUBLE, tag, sz, "Double");
	if (quick_check > 0) {
		return (RzBinJavaCPTypeObj *)obj;
	}
	obj = (RzBinJavaCPTypeObj *)malloc(sizeof(RzBinJavaCPTypeObj));
	if (obj) {
		memset(obj, 0, sizeof(RzBinJavaCPTypeObj));
		obj->tag = tag;
		obj->metas = RZ_NEW0(RzBinJavaMetaInfo);
		obj->metas->type_info = (void *)&RZ_BIN_JAVA_CP_METAS[tag];
		obj->name = rz_str_dup(NULL, (const char *)RZ_BIN_JAVA_CP_METAS[tag].name);
		memset(&obj->info.cp_double.bytes, 0, sizeof(obj->info.cp_double.bytes));
		memcpy(&obj->info.cp_double.bytes, buffer + 1, 8);
	}
	return obj;
}

RZ_API ut64 rz_bin_java_calc_size_double_cp(RzBinJavaCPTypeObj *obj) {
	ut64 size = 0;
	// tag
	size += 1;
	// obj->info.cp_string.string_idx = rz_read_at_be16 (buffer, 1);
	size += 8;
	return size;
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_utf8_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 sz) {
	ut8 tag = buffer[0];
	RzBinJavaCPTypeObj *obj;
	int quick_check = rz_bin_java_quick_check(RZ_BIN_JAVA_CP_UTF8, tag, sz, "Utf8");
	if (quick_check > 0) {
		return NULL;
	}
	if ((obj = RZ_NEW0(RzBinJavaCPTypeObj))) {
		obj->tag = tag;
		obj->metas = RZ_NEW0(RzBinJavaMetaInfo);
		obj->metas->type_info = (void *)&RZ_BIN_JAVA_CP_METAS[tag];
		obj->name = rz_str_dup(NULL, (const char *)RZ_BIN_JAVA_CP_METAS[tag].name);
		obj->info.cp_utf8.length = rz_read_at_be16(buffer, 1);
		obj->info.cp_utf8.bytes = (ut8 *)malloc(obj->info.cp_utf8.length + 1);
		if (obj->info.cp_utf8.bytes) {
			memset(obj->info.cp_utf8.bytes, 0, obj->info.cp_utf8.length + 1);
			if (obj->info.cp_utf8.length < (sz - 3)) {
				memcpy(obj->info.cp_utf8.bytes, buffer + 3, (sz - 3));
				obj->info.cp_utf8.length = sz - 3;
			} else {
				memcpy(obj->info.cp_utf8.bytes, buffer + 3, obj->info.cp_utf8.length);
			}
			obj->value = obj->info.cp_utf8.bytes;
		} else {
			rz_bin_java_free_obj(obj);
			obj = NULL;
		}
	}
	return obj;
}

RZ_API ut64 rz_bin_java_calc_size_utf8_cp(RzBinJavaCPTypeObj *obj) {
	ut64 size = 0;
	size += 1;
	if (obj && RZ_BIN_JAVA_CP_UTF8 == obj->tag) {
		size += 2;
		size += obj->info.cp_utf8.length;
	}
	return size;
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_name_and_type_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 sz) {
	ut8 tag = buffer[0];
	RzBinJavaCPTypeObj *obj = NULL;
	int quick_check = 0;
	quick_check = rz_bin_java_quick_check(RZ_BIN_JAVA_CP_NAMEANDTYPE, tag, sz, "RzBinJavaCPTypeNameAndType");
	if (quick_check > 0) {
		return obj;
	}
	obj = RZ_NEW0(RzBinJavaCPTypeObj);
	if (obj) {
		obj->metas = RZ_NEW0(RzBinJavaMetaInfo);
		obj->metas->type_info = (void *)&RZ_BIN_JAVA_CP_METAS[tag];
		obj->name = rz_str_dup(NULL, (const char *)RZ_BIN_JAVA_CP_METAS[tag].name);
		;
		obj->tag = tag;
		obj->info.cp_name_and_type.name_idx = rz_read_at_be16(buffer, 1);
		obj->info.cp_name_and_type.descriptor_idx = rz_read_at_be16(buffer, 3);
	}
	return obj;
}

RZ_API ut64 rz_bin_java_calc_size_name_and_type_cp(RzBinJavaCPTypeObj *obj) {
	ut64 size = 0;
	if (obj) {
		size += 1;
		// obj->info.cp_name_and_type.name_idx = rz_read_at_be16 (buffer, 1);
		size += 2;
		// obj->info.cp_name_and_type.descriptor_idx = rz_read_at_be16 (buffer, 3);
		size += 2;
	}
	return size;
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_methodtype_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 sz) {
	ut8 tag = buffer[0];
	int quick_check = rz_bin_java_quick_check(RZ_BIN_JAVA_CP_METHODTYPE, tag, sz, "RzBinJavaCPTypeMethodType");
	if (quick_check > 0) {
		return NULL;
	}
	RzBinJavaCPTypeObj *obj = RZ_NEW0(RzBinJavaCPTypeObj);
	if (obj) {
		obj->metas = RZ_NEW0(RzBinJavaMetaInfo);
		obj->metas->type_info = (void *)&RZ_BIN_JAVA_CP_METAS[tag];
		obj->name = rz_str_dup(NULL, (const char *)RZ_BIN_JAVA_CP_METAS[tag].name);
		;
		obj->tag = tag;
		obj->info.cp_method_type.descriptor_index = rz_read_at_be16(buffer, 1);
	}
	return obj;
}

RZ_API ut64 rz_bin_java_calc_size_methodtype_cp(RzBinJavaCPTypeObj *obj) {
	ut64 size = 0;
	size += 1;
	// obj->info.cp_method_type.descriptor_index = rz_read_at_be16 (buffer, 1);
	size += 2;
	return size;
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_methodhandle_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 sz) {
	ut8 tag = buffer[0];
	int quick_check = rz_bin_java_quick_check(RZ_BIN_JAVA_CP_METHODHANDLE, tag, sz, "RzBinJavaCPTypeMethodHandle");
	if (quick_check > 0) {
		return NULL;
	}
	RzBinJavaCPTypeObj *obj = RZ_NEW0(RzBinJavaCPTypeObj);
	if (obj) {
		obj->metas = RZ_NEW0(RzBinJavaMetaInfo);
		obj->metas->type_info = (void *)&RZ_BIN_JAVA_CP_METAS[tag];
		obj->name = rz_str_dup(NULL, (const char *)RZ_BIN_JAVA_CP_METAS[tag].name);
		;
		obj->tag = tag;
		obj->info.cp_method_handle.reference_kind = buffer[1];
		obj->info.cp_method_handle.reference_index = rz_read_at_be16(buffer, 2);
	}
	return obj;
}

RZ_API ut64 rz_bin_java_calc_size_methodhandle_cp(RzBinJavaCPTypeObj *obj) {
	ut64 size = 0;
	size += 1;
	// obj->info.cp_method_handle.reference_index =  rz_read_at_be16 (buffer, 2);
	size += 2;
	return size;
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_new_invokedynamic_cp(RzBinJavaObj *bin, ut8 *buffer, ut64 sz) {
	ut8 tag = buffer[0];
	RzBinJavaCPTypeObj *obj;
	int quick_check = rz_bin_java_quick_check(RZ_BIN_JAVA_CP_INVOKEDYNAMIC, tag, sz, "RzBinJavaCPTypeMethodHandle");
	if (quick_check > 0) {
		return NULL;
	}
	if ((obj = RZ_NEW0(RzBinJavaCPTypeObj))) {
		obj->metas = RZ_NEW0(RzBinJavaMetaInfo);
		obj->metas->type_info = (void *)&RZ_BIN_JAVA_CP_METAS[tag];
		obj->name = rz_str_dup(NULL, (const char *)RZ_BIN_JAVA_CP_METAS[tag].name);
		;
		obj->tag = tag;
		obj->info.cp_invoke_dynamic.bootstrap_method_attr_index = rz_read_at_be16(buffer, 1);
		obj->info.cp_invoke_dynamic.name_and_type_index = rz_read_at_be16(buffer, 3);
	}
	return obj;
}

RZ_API int rz_bin_java_check_reset_cp_obj(RzBinJavaCPTypeObj *cp_obj, ut8 tag) {
	bool res = false;
	if (tag < RZ_BIN_JAVA_CP_METAS_SZ) {
		if (tag != cp_obj->tag) {
			if (cp_obj->tag == RZ_BIN_JAVA_CP_UTF8) {
				RZ_FREE(cp_obj->info.cp_utf8.bytes);
				cp_obj->info.cp_utf8.length = 0;
				RZ_FREE(cp_obj->name);
			}
			cp_obj->tag = tag;
			cp_obj->metas->type_info = (void *)&RZ_BIN_JAVA_CP_METAS[tag];
			cp_obj->name = strdup(RZ_BIN_JAVA_CP_METAS[tag].name);
			res = true;
		} else {
			eprintf("Invalid tag\n");
		}
	} else {
		eprintf("Invalid tag '%d'.\n", tag);
	}
	return res;
}

RZ_API ut8 *rz_bin_java_cp_get_4bytes(ut8 tag, ut32 *out_sz, const ut8 *buf, const ut64 len) {
	ut8 *buffer = malloc(5);
	if (!buffer) {
		return NULL;
	}
	ut32 val = 0;
	if (!buffer || len < 4) {
		if (out_sz) {
			*out_sz = 0;
		}
		free(buffer);
		return NULL;
	}
	buffer[0] = tag;
	val = rz_read_at_be32(buf, 0);
	memcpy(buffer + 1, (const char *)&val, 4);
	*out_sz = 5;
	return buffer;
}

RZ_API ut8 *rz_bin_java_cp_get_8bytes(ut8 tag, ut32 *out_sz, const ut8 *buf, const ut64 len) {
	ut8 *buffer = malloc(10);
	if (!buffer) {
		return NULL;
	}
	ut64 val = 0;
	if (len < 8) {
		*out_sz = 0;
		free(buffer);
		return NULL;
	}
	buffer[0] = tag;
	val = rz_read_at_be64(buf, 0);
	memcpy(buffer + 1, (const char *)&val, 8);
	*out_sz = 9;
	return buffer;
}

RZ_API ut8 *rz_bin_java_cp_append_classref_and_name(RzBinJavaObj *bin, ut32 *out_sz, const char *classname, const ut32 classname_len) {
	ut16 use_name_idx = bin->cp_idx + 1;
	ut8 *bytes = NULL, *name_bytes = NULL;
	name_bytes = rz_bin_java_cp_get_utf8(RZ_BIN_JAVA_CP_UTF8, out_sz, (const ut8 *)classname, classname_len);
	if (*out_sz > 0 && name_bytes) {
		ut8 *idx_addr = (ut8 *)&use_name_idx;
		bytes = malloc(*out_sz + 3);
		memcpy(bytes, name_bytes, *out_sz);
		bytes[*out_sz + 0] = RZ_BIN_JAVA_CP_CLASS;
		bytes[*out_sz + 1] = idx_addr[1];
		bytes[*out_sz + 2] = idx_addr[0];
		*out_sz += 3;
	}
	free(name_bytes);
	return bytes;
}

RZ_API ut8 *rz_bin_java_cp_get_fref_bytes(RzBinJavaObj *bin, ut32 *out_sz, ut8 tag, ut16 cn_idx, ut16 fn_idx, ut16 ft_idx) {
	ut8 *bytes = NULL, *fnt_bytes = NULL;
	RzBinJavaCPTypeObj *ref_cp_obj = NULL;
	ut16 fnt_idx = 0, cref_idx = 0;
	ut32 fnt_len = 0;
	ut16 ref_cp_obj_idx = rz_bin_java_find_cp_class_ref_from_name_idx(bin, cn_idx);
	if (!ref_cp_obj_idx) {
		return NULL;
	}
	ref_cp_obj = rz_bin_java_get_item_from_bin_cp_list(bin, ref_cp_obj_idx);
	if (ref_cp_obj) {
		cref_idx = ref_cp_obj->idx;
	}
	ref_cp_obj = rz_bin_java_find_cp_name_and_type_info(bin, fn_idx, ft_idx);
	if (ref_cp_obj) {
		fnt_idx = ref_cp_obj->idx;
	} else {
		fnt_bytes = rz_bin_java_cp_get_name_type(bin, &fnt_len, fn_idx, ft_idx);
		fnt_idx = bin->cp_idx + 1;
	}
	if (cref_idx && fnt_idx) {
		bytes = rz_bin_java_cp_get_fm_ref(bin, out_sz, tag, cref_idx, fnt_idx);
		if (fnt_bytes) {
			ut8 *tbuf = malloc(fnt_len + *out_sz);
			if (!tbuf) {
				free(bytes);
				free(fnt_bytes);
				return NULL;
			}
			// copy the bytes to the new buffer
			memcpy(tbuf, fnt_bytes, fnt_len);
			memcpy(tbuf + fnt_len, bytes, *out_sz);
			// update the values free old buffer
			*out_sz += fnt_len;
			free(bytes);
			bytes = tbuf;
		}
	}
	free(fnt_bytes);
	return bytes;
}

RZ_API ut8 *rz_bin_java_cp_get_classref(RzBinJavaObj *bin, ut32 *out_sz, const char *classname, const ut32 classname_len, const ut16 name_idx) {
	ut16 use_name_idx = -1;
	ut8 *bytes = NULL;
	if (name_idx == (ut16)-1 && classname && *classname && classname_len > 0) {
		// find class_name_idx by class name
		RzList *results = rz_bin_java_find_cp_const_by_val_utf8(bin, (const ut8 *)classname, classname_len);
		if (rz_list_length(results) == 1) {
			use_name_idx = (ut16) * ((ut32 *)rz_list_get_n(results, 0));
		}
		rz_list_free(results);
	} else if (name_idx != (ut16)-1 && name_idx != 0) {
		use_name_idx = name_idx;
	}
	if (use_name_idx == (ut16)-1 && classname && *classname && classname_len > 0) {
		bytes = rz_bin_java_cp_append_classref_and_name(bin, out_sz, classname, classname_len);
	} else if (use_name_idx != (ut16)-1) {
		ut8 *idx_addr = (ut8 *)&use_name_idx;
		bytes = malloc(3);
		if (!bytes) {
			return NULL;
		}
		bytes[0] = RZ_BIN_JAVA_CP_CLASS;
		bytes[1] = idx_addr[1];
		bytes[2] = idx_addr[0];
		*out_sz += 3;
	}
	return bytes;
}

RZ_API ut8 *rz_bin_java_cp_get_fm_ref(RzBinJavaObj *bin, ut32 *out_sz, ut8 tag, ut16 class_idx, ut16 name_and_type_idx) {
	return rz_bin_java_cp_get_2_ut16(bin, out_sz, tag, class_idx, name_and_type_idx);
}

RZ_API ut8 *rz_bin_java_cp_get_2_ut16(RzBinJavaObj *bin, ut32 *out_sz, ut8 tag, ut16 ut16_one, ut16 ut16_two) {
	ut8 *bytes = malloc(7);
	if (!bytes) {
		return NULL;
	}
	ut8 *idx_addr = NULL;
	bytes[*out_sz] = tag;
	*out_sz += 1;
	idx_addr = (ut8 *)&ut16_one;
	bytes[*out_sz + 1] = idx_addr[1];
	bytes[*out_sz + 2] = idx_addr[0];
	*out_sz += 3;
	idx_addr = (ut8 *)&ut16_two;
	bytes[*out_sz + 1] = idx_addr[1];
	bytes[*out_sz + 2] = idx_addr[0];
	*out_sz += 3;
	return bytes;
}

RZ_API ut8 *rz_bin_java_cp_get_name_type(RzBinJavaObj *bin, ut32 *out_sz, ut16 name_idx, ut16 type_idx) {
	return rz_bin_java_cp_get_2_ut16(bin, out_sz, RZ_BIN_JAVA_CP_NAMEANDTYPE, name_idx, type_idx);
}

RZ_API ut8 *rz_bin_java_cp_get_utf8(ut8 tag, ut32 *out_sz, const ut8 *buf, const ut64 len) {
	ut8 *buffer = NULL;
	ut16 sz = 0;
	ut16 t = (ut16)len;
	if (len > 0 && len > (ut16)-1) {
		*out_sz = 0;
		return NULL;
	}
	sz = rz_read_at_be16(((ut8 *)(ut16 *)&t), 0);
	*out_sz = 3 + t; // tag + sz + bytes
	buffer = malloc(*out_sz + 3);
	if (!buffer) {
		return NULL;
	}
	// XXX - excess bytes are created to ensure null for string operations.
	memset(buffer, 0, *out_sz + 3);
	buffer[0] = tag;
	memcpy(buffer + 1, (const char *)&sz, 2);
	memcpy(buffer + 3, buf, *out_sz - 3);
	return buffer;
}

RZ_API ut64 rz_bin_java_calc_size_invokedynamic_cp(RzBinJavaCPTypeObj *obj) {
	ut64 size = 0;
	size += 1;
	// obj->info.cp_invoke_dynamic.bootstrap_method_attr_index = rz_read_at_be16 (buffer, 1);
	size += 2;
	// obj->info.cp_invoke_dynamic.name_and_type_index = rz_read_at_be16 (buffer, 3);
	size += 2;
	return size;
}
// End new Constant Pool types
// Start free Constant Pool types
RZ_API void rz_bin_java_free_default(void /* RzBinJavaCPTypeObj*/ *o) {
	RzBinJavaCPTypeObj *obj = o;
	if (obj) {
		free(obj->metas);
		free(obj->name);
		free(obj->value);
		free(obj);
	}
}

RZ_API void rz_bin_java_free_utf8_info(void /* RzBinJavaCPTypeObj*/ *o) {
	RzBinJavaCPTypeObj *obj = o;
	if (obj) {
		free(obj->name);
		free(obj->metas);
		free(obj->info.cp_utf8.bytes);
		free(obj);
	}
}
// Deallocs for type objects
RZ_API void rz_bin_java_free_obj(void /*RzBinJavaCPTypeObj*/ *o) {
	RzBinJavaCPTypeObj *obj = o;
	((RzBinJavaCPTypeMetas *)obj->metas->type_info)->allocs->delete_obj(obj);
}

RZ_API char *rz_bin_java_stringify_cp_interfacemethodref(RzBinJavaCPTypeObj *obj) {
	ut32 size = 255, consumed = 0;
	char *value = malloc(size);
	if (value) {
		memset(value, 0, size);
		consumed = snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%d.%d",
			obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
			obj->info.cp_interface.class_idx, obj->info.cp_interface.name_and_type_idx);
		if (consumed >= size - 1) {
			free(value);
			size += size >> 1;
			value = malloc(size);
			if (value) {
				memset(value, 0, size);
				(void)snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%d.%d",
					obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
					obj->info.cp_interface.class_idx, obj->info.cp_interface.name_and_type_idx);
			}
		}
	}
	return value;
}

RZ_API char *rz_bin_java_stringify_cp_methodhandle(RzBinJavaCPTypeObj *obj) {
	ut32 size = 255, consumed = 0;
	char *value = malloc(size);
	ut8 ref_kind = obj->info.cp_method_handle.reference_kind;
	if (value) {
		memset(value, 0, size);
		consumed = snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%s.%d",
			obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
			RZ_BIN_JAVA_REF_METAS[ref_kind].name, obj->info.cp_method_handle.reference_index);
		if (consumed >= size - 1) {
			free(value);
			size += size >> 1;
			value = malloc(size);
			if (value) {
				memset(value, 0, size);
				(void)snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%s.%d",
					obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
					RZ_BIN_JAVA_REF_METAS[ref_kind].name, obj->info.cp_method_handle.reference_index);
			}
		}
	}
	return value;
}

RZ_API char *rz_bin_java_stringify_cp_methodtype(RzBinJavaCPTypeObj *obj) {
	ut32 size = 255, consumed = 0;
	char *value = malloc(size);
	if (value) {
		memset(value, 0, size);
		consumed = snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%d",
			obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
			obj->info.cp_method_type.descriptor_index);
		if (consumed >= size - 1) {
			free(value);
			size += size >> 1;
			value = malloc(size);
			if (value) {
				memset(value, 0, size);
				(void)snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%d",
					obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
					obj->info.cp_method_type.descriptor_index);
			}
		}
	}
	return value;
}

RZ_API char *rz_bin_java_stringify_cp_invokedynamic(RzBinJavaCPTypeObj *obj) {
	ut32 size = 255, consumed = 0;
	char *value = malloc(size);
	if (value) {
		memset(value, 0, size);
		consumed = snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%d.%d",
			obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
			obj->info.cp_invoke_dynamic.bootstrap_method_attr_index,
			obj->info.cp_invoke_dynamic.name_and_type_index);
		if (consumed >= size - 1) {
			free(value);
			size += size >> 1;
			value = malloc(size);
			if (value) {
				memset(value, 0, size);
				(void)snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%d.%d",
					obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
					obj->info.cp_invoke_dynamic.bootstrap_method_attr_index,
					obj->info.cp_invoke_dynamic.name_and_type_index);
			}
		}
	}
	return value;
}

RZ_API char *rz_bin_java_stringify_cp_methodref(RzBinJavaCPTypeObj *obj) {
	ut32 size = 255, consumed = 0;
	char *value = malloc(size);
	if (value) {
		memset(value, 0, size);
		consumed = snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%d.%d",
			obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
			obj->info.cp_method.class_idx,
			obj->info.cp_method.name_and_type_idx);
		if (consumed >= size - 1) {
			free(value);
			size += size >> 1;
			value = malloc(size);
			if (value) {
				memset(value, 0, size);
				(void)snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%d.%d",
					obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
					obj->info.cp_method.class_idx,
					obj->info.cp_method.name_and_type_idx);
			}
		}
	}
	return value;
}

RZ_API char *rz_bin_java_stringify_cp_fieldref(RzBinJavaCPTypeObj *obj) {
	ut32 size = 255, consumed = 0;
	char *value = malloc(size);
	if (value) {
		memset(value, 0, size);
		consumed = snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%d.%d",
			obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
			obj->info.cp_field.class_idx,
			obj->info.cp_field.name_and_type_idx);
		if (consumed >= size - 1) {
			free(value);
			size += size >> 1;
			value = malloc(size);
			if (value) {
				memset(value, 0, size);
				(void)snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%d.%d",
					obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
					obj->info.cp_field.class_idx,
					obj->info.cp_field.name_and_type_idx);
			}
		}
	}
	return value;
}

RZ_API char *rz_bin_java_stringify_cp_classref(RzBinJavaCPTypeObj *obj) {
	ut32 size = 255, consumed = 0;
	char *value = malloc(size);
	if (value) {
		memset(value, 0, size);
		consumed = snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%d",
			obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
			obj->info.cp_class.name_idx);
		if (consumed >= size - 1) {
			free(value);
			size += size >> 1;
			value = malloc(size);
			if (value) {
				memset(value, 0, size);
				(void)snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%d",
					obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
					obj->info.cp_class.name_idx);
			}
		}
	}
	return value;
}

RZ_API char *rz_bin_java_stringify_cp_string(RzBinJavaCPTypeObj *obj) {
	ut32 size = 255, consumed = 0;
	char *value = malloc(size);
	if (value) {
		memset(value, 0, size);
		consumed = snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%d",
			obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
			obj->info.cp_string.string_idx);
		if (consumed >= size - 1) {
			free(value);
			size += size >> 1;
			value = malloc(size);
			if (value) {
				memset(value, 0, size);
				(void)snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%d",
					obj->metas->ord, obj->file_offset,
					((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
					obj->info.cp_string.string_idx);
			}
		}
	}
	return value;
}

RZ_API char *rz_bin_java_stringify_cp_integer(RzBinJavaCPTypeObj *obj) {
	ut32 size = 255, consumed = 0;
	char *value = malloc(size);
	if (value) {
		memset(value, 0, size);
		consumed = snprintf(value, size, "%d.0x%04" PFMT64x ".%s.0x%08x",
			obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
			rz_read_at_be32(obj->info.cp_integer.bytes.raw, 0));
		if (consumed >= size - 1) {
			free(value);
			size += size >> 1;
			value = malloc(size);
			if (value) {
				memset(value, 0, size);
				(void)snprintf(value, size, "%d.0x%04" PFMT64x ".%s.0x%08x",
					obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
					rz_read_at_be32(obj->info.cp_integer.bytes.raw, 0));
			}
		}
	}
	return value;
}

RZ_API char *rz_bin_java_stringify_cp_float(RzBinJavaCPTypeObj *obj) {
	ut32 size = 255, consumed = 0;
	char *value = malloc(size);
	if (value) {
		memset(value, 0, size);
		consumed = snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%f",
			obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
			raw_to_float(obj->info.cp_float.bytes.raw, 0));
		if (consumed >= size - 1) {
			free(value);
			size += size >> 1;
			value = malloc(size);
			if (value) {
				memset(value, 0, size);
				(void)snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%f",
					obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
					raw_to_float(obj->info.cp_float.bytes.raw, 0));
			}
		}
	}
	return value;
}

RZ_API char *rz_bin_java_stringify_cp_long(RzBinJavaCPTypeObj *obj) {
	ut32 size = 255, consumed = 0;
	char *value = malloc(size);
	if (value) {
		memset(value, 0, size);
		consumed = snprintf(value, size, "%d.0x%04" PFMT64x ".%s.0x%08" PFMT64x "",
			obj->metas->ord,
			obj->file_offset,
			((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
			rz_read_at_be64(obj->info.cp_long.bytes.raw, 0));
		if (consumed >= size - 1) {
			free(value);
			size += size >> 1;
			value = malloc(size);
			if (value) {
				memset(value, 0, size);
				(void)snprintf(value, size, "%d.0x%04" PFMT64x ".%s.0x%08" PFMT64x "",
					obj->metas->ord,
					obj->file_offset,
					((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
					rz_read_at_be64(obj->info.cp_long.bytes.raw, 0));
			}
		}
	}
	return value;
}

RZ_API char *rz_bin_java_stringify_cp_double(RzBinJavaCPTypeObj *obj) {
	ut32 size = 255, consumed = 0;
	char *value = malloc(size);
	if (value) {
		memset(value, 0, size);
		consumed = snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%f",
			obj->metas->ord,
			obj->file_offset,
			((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
			raw_to_double(obj->info.cp_double.bytes.raw, 0));
		if (consumed >= size - 1) {
			free(value);
			size += size >> 1;
			value = malloc(size);
			if (value) {
				memset(value, 0, size);
				(void)snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%f",
					obj->metas->ord,
					obj->file_offset,
					((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
					raw_to_double(obj->info.cp_double.bytes.raw, 0));
			}
		}
	}
	return value;
}

RZ_API char *rz_bin_java_stringify_cp_name_and_type(RzBinJavaCPTypeObj *obj) {
	ut32 size = 255, consumed = 0;
	char *value = malloc(size);
	if (value) {
		memset(value, 0, size);
		consumed = snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%d.%d",
			obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
			obj->info.cp_name_and_type.name_idx,
			obj->info.cp_name_and_type.descriptor_idx);
		if (consumed >= size - 1) {
			free(value);
			size += size >> 1;
			value = malloc(size);
			if (value) {
				memset(value, 0, size);
				(void)snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%d.%d",
					obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
					obj->info.cp_name_and_type.name_idx,
					obj->info.cp_name_and_type.descriptor_idx);
			}
		}
	}
	return value;
}

RZ_API char *rz_bin_java_stringify_cp_utf8(RzBinJavaCPTypeObj *obj) {
	ut32 size = 255, consumed = 0;
	char *utf8_str = rz_hex_bin2strdup(obj->info.cp_utf8.bytes, obj->info.cp_utf8.length);
	char *value = malloc(size + strlen(utf8_str));
	if (value) {
		memset(value, 0, size);
		consumed = snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%d.%s",
			obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
			obj->info.cp_utf8.length,
			utf8_str);
		if (consumed >= size - 1) {
			free(value);
			size += size >> 1;
			value = malloc(size + strlen(utf8_str));
			if (value) {
				memset(value, 0, size);
				(void)snprintf(value, size, "%d.0x%04" PFMT64x ".%s.%d.%s",
					obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name,
					obj->info.cp_utf8.length,
					utf8_str);
			}
		}
	}
	free(utf8_str);
	return value;
}

RZ_API char *rz_bin_java_stringify_cp_null(RzBinJavaCPTypeObj *obj) {
	ut32 size = 255, consumed = 0;
	char *value = malloc(size);
	if (value) {
		memset(value, 0, size);
		consumed = snprintf(value, size, "%d.0x%04" PFMT64x ".%s",
			obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name);
		if (consumed >= size - 1) {
			free(value);
			size += size >> 1;
			value = malloc(size);
			if (value) {
				memset(value, 0, size);
				(void)snprintf(value, size, "%d.0x%04" PFMT64x ".%s",
					obj->metas->ord, obj->file_offset,
					((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name);
			}
		}
	}
	return value;
}

RZ_API char *rz_bin_java_stringify_cp_unknown(RzBinJavaCPTypeObj *obj) {
	ut32 size = 255;
	char *value = malloc(size);
	if (value) {
		memset(value, 0, size);
		snprintf(value, size, "%d.0x%04" PFMT64x ".%s",
			obj->metas->ord, obj->file_offset + obj->loadaddr, ((RzBinJavaCPTypeMetas *)obj->metas->type_info)->name);
	}
	return value;
}

RZ_API RzBinJavaElementValuePair *rz_bin_java_new_element_pair(ut8 *buffer, ut64 sz, ut64 buf_offset) {
	if (!buffer || sz < 4) {
		return NULL;
	}
	RzBinJavaElementValuePair *evp = RZ_NEW0(RzBinJavaElementValuePair);
	if (!evp) {
		return NULL;
	}
	// TODO: What is the signifigance of evp element
	evp->element_name_idx = rz_read_at_be16(buffer, 0);
	ut64 offset = 2;
	evp->file_offset = buf_offset;
	evp->name = rz_bin_java_get_utf8_from_bin_cp_list(RZ_BIN_JAVA_GLOBAL_BIN, evp->element_name_idx);
	if (!evp->name) {
		// TODO: eprintf unable to find the name for the given index
		eprintf("ElementValue Name is invalid.\n");
		evp->name = strdup("UNKNOWN");
	}
	if (offset >= sz) {
		free(evp);
		return NULL;
	}
	evp->value = rz_bin_java_new_element_value(buffer + offset, sz - offset, buf_offset + offset);
	offset += evp->value->size;
	if (offset >= sz) {
		free(evp->value);
		free(evp);
		return NULL;
	}
	evp->size = offset;
	return evp;
}

RZ_API void rz_bin_java_free_element_pair(void /*RzBinJavaElementValuePair*/ *e) {
	RzBinJavaElementValuePair *evp = e;
	if (evp) {
		free(evp->name);
		rz_bin_java_free_element_value(evp->value);
		free(evp);
	}
	evp = NULL;
}

RZ_API void rz_bin_java_free_element_value(void /*RzBinJavaElementValue*/ *e) {
	RzBinJavaElementValue *element_value = e;
	RzListIter *iter = NULL, *iter_tmp = NULL;
	RzBinJavaCPTypeObj *obj = NULL;
	RzBinJavaElementValue *ev_element = NULL;
	if (element_value) {
		RZ_FREE(element_value->metas);
		switch (element_value->tag) {
		case RZ_BIN_JAVA_EV_TAG_BYTE:
		case RZ_BIN_JAVA_EV_TAG_CHAR:
		case RZ_BIN_JAVA_EV_TAG_DOUBLE:
		case RZ_BIN_JAVA_EV_TAG_FLOAT:
		case RZ_BIN_JAVA_EV_TAG_INT:
		case RZ_BIN_JAVA_EV_TAG_LONG:
		case RZ_BIN_JAVA_EV_TAG_SHORT:
		case RZ_BIN_JAVA_EV_TAG_BOOLEAN:
		case RZ_BIN_JAVA_EV_TAG_STRING:
			// Delete the CP Type Object
			obj = element_value->value.const_value.const_value_cp_obj;
			if (obj && obj->metas) {
				((RzBinJavaCPTypeMetas *)obj->metas->type_info)->allocs->delete_obj(obj);
			}
			break;
		case RZ_BIN_JAVA_EV_TAG_ENUM:
			// Delete the CP Type Objects
			obj = element_value->value.enum_const_value.const_name_cp_obj;
			if (obj && obj->metas) {
				RzBinJavaCPTypeMetas *ti = obj->metas->type_info;
				if (ti && ti->allocs && ti->allocs->delete_obj) {
					ti->allocs->delete_obj(obj);
				}
			}
			obj = element_value->value.enum_const_value.type_name_cp_obj;
			if (obj && obj->metas) {
				RzBinJavaCPTypeMetas *tm = obj->metas->type_info;
				if (tm && tm->allocs && tm->allocs->delete_obj) {
					tm->allocs->delete_obj(obj);
				}
			}
			break;
		case RZ_BIN_JAVA_EV_TAG_CLASS:
			// Delete the CP Type Object
			obj = element_value->value.class_value.class_info_cp_obj;
			if (obj && obj->metas) {
				((RzBinJavaCPTypeMetas *)obj->metas->type_info)->allocs->delete_obj(obj);
			}
			break;
		case RZ_BIN_JAVA_EV_TAG_ARRAY:
			// Delete the Element Value array List
			rz_list_foreach_safe (element_value->value.array_value.values, iter, iter_tmp, ev_element) {
				if (ev_element) {
					rz_bin_java_free_element_value(ev_element);
				} else {
					// TODO eprintf evps value was NULL
				}
				// rz_list_delete (element_value->value.array_value.values, iter);
				ev_element = NULL;
			}
			rz_list_free(element_value->value.array_value.values);
			break;
		case RZ_BIN_JAVA_EV_TAG_ANNOTATION:
			// Delete the Annotations List
			rz_list_free(element_value->value.annotation_value.element_value_pairs);
			break;
		default:
			// eprintf unable to free the tag
			break;
		}
		free(element_value);
	}
}

RZ_API ut64 rz_bin_java_calc_size_annotation_default_attr(RzBinJavaAttrInfo *attr) {
	ut64 size = 0;
	if (attr) {
		// attr = rz_bin_java_new_default_attr (buffer, sz, buf_offset);
		size += 6;
		// attr->info.annotation_default_attr.default_value = rz_bin_java_new_element_value (buffer+offset, sz-offset, buf_offset+offset);
		size += rz_bin_java_calc_size_element_value(attr->info.annotation_default_attr.default_value);
	}
	return size;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_annotation_default_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	ut64 offset = 0;
	RzBinJavaAttrInfo *attr = NULL;
	attr = rz_bin_java_new_default_attr(bin, buffer, sz, buf_offset);
	offset += 6;
	if (attr && sz >= offset) {
		attr->type = RZ_BIN_JAVA_ATTRIBUTE_ANNOTATION_DEFAULT_ATTR;
		attr->info.annotation_default_attr.default_value = rz_bin_java_new_element_value(buffer + offset, sz - offset, buf_offset + offset);
	}
	rz_bin_java_summary_print_annotation_default_attr(attr);
	return attr;
}

static void delete_obj(RzBinJavaCPTypeObj *obj) {
	if (obj && obj->metas && obj->metas->type_info) {
		RzBinJavaCPTypeMetas *ti = obj->metas->type_info;
		if (ti && ti->allocs && ti->allocs->delete_obj) {
			ti->allocs->delete_obj(obj);
		}
	}
}

RZ_API void rz_bin_java_free_annotation_default_attr(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	RzBinJavaElementValue *ev_element = NULL;
	RzListIter *iter = NULL, *iter_tmp = NULL;
	if (!attr || attr->type != RZ_BIN_JAVA_ATTRIBUTE_ANNOTATION_DEFAULT_ATTR) {
		return;
	}
	RzBinJavaElementValue *element_value = attr->info.annotation_default_attr.default_value;
	if (!element_value) {
		return;
	}
	switch (element_value->tag) {
	case RZ_BIN_JAVA_EV_TAG_BYTE:
	case RZ_BIN_JAVA_EV_TAG_CHAR:
	case RZ_BIN_JAVA_EV_TAG_DOUBLE:
	case RZ_BIN_JAVA_EV_TAG_FLOAT:
	case RZ_BIN_JAVA_EV_TAG_INT:
	case RZ_BIN_JAVA_EV_TAG_LONG:
	case RZ_BIN_JAVA_EV_TAG_SHORT:
	case RZ_BIN_JAVA_EV_TAG_BOOLEAN:
	case RZ_BIN_JAVA_EV_TAG_STRING:
		// Delete the CP Type Object
		delete_obj(element_value->value.const_value.const_value_cp_obj);
		break;
	case RZ_BIN_JAVA_EV_TAG_ENUM:
		// Delete the CP Type Objects
		delete_obj(element_value->value.enum_const_value.const_name_cp_obj);
		break;
	case RZ_BIN_JAVA_EV_TAG_CLASS:
		// Delete the CP Type Object
		delete_obj(element_value->value.class_value.class_info_cp_obj);
		break;
	case RZ_BIN_JAVA_EV_TAG_ARRAY:
		// Delete the Element Value array List
		rz_list_foreach_safe (element_value->value.array_value.values, iter, iter_tmp, ev_element) {
			rz_bin_java_free_element_value(ev_element);
			// rz_list_delete (element_value->value.array_value.values, iter);
			ev_element = NULL;
		}
		rz_list_free(element_value->value.array_value.values);
		break;
	case RZ_BIN_JAVA_EV_TAG_ANNOTATION:
		// Delete the Annotations List
		rz_list_free(element_value->value.annotation_value.element_value_pairs);
		break;
	default:
		// eprintf unable to free the tag
		break;
	}
	if (attr) {
		free(attr->name);
		free(attr->metas);
		free(attr);
	}
}

RZ_API RzBinJavaAnnotation *rz_bin_java_new_annotation(ut8 *buffer, ut64 sz, ut64 buf_offset) {
	ut32 i = 0;
	RzBinJavaAnnotation *annotation = NULL;
	RzBinJavaElementValuePair *evps = NULL;
	ut64 offset = 0;
	annotation = RZ_NEW0(RzBinJavaAnnotation);
	if (!annotation) {
		return NULL;
	}
	// (ut16) read and set annotation_value.type_idx;
	annotation->type_idx = rz_read_at_be16(buffer, offset);
	offset += 2;
	// (ut16) read and set annotation_value.num_element_value_pairs;
	annotation->num_element_value_pairs = rz_read_at_be16(buffer, offset);
	offset += 2;
	annotation->element_value_pairs = rz_list_newf(rz_bin_java_free_element_pair);
	// read annotation_value.num_element_value_pairs, and append to annotation_value.element_value_pairs
	for (i = 0; i < annotation->num_element_value_pairs; i++) {
		if (offset > sz) {
			break;
		}
		evps = rz_bin_java_new_element_pair(buffer + offset, sz - offset, buf_offset + offset);
		if (evps) {
			offset += evps->size;
			rz_list_append(annotation->element_value_pairs, (void *)evps);
		}
	}
	annotation->size = offset;
	return annotation;
}

RZ_API ut64 rz_bin_java_calc_size_annotation(RzBinJavaAnnotation *annotation) {
	ut64 sz = 0;
	RzListIter *iter, *iter_tmp;
	RzBinJavaElementValuePair *evps = NULL;
	if (!annotation) {
		// TODO eprintf allocation fail
		return sz;
	}
	// annotation->type_idx = rz_read_at_be16 (buffer, offset);
	sz += 2;
	// annotation->num_element_value_pairs = rz_read_at_be16 (buffer, offset);
	sz += 2;
	rz_list_foreach_safe (annotation->element_value_pairs, iter, iter_tmp, evps) {
		if (evps) {
			sz += rz_bin_java_calc_size_element_pair(evps);
		}
	}
	return sz;
}

RZ_API void rz_bin_java_free_annotation(void /*RzBinJavaAnnotation*/ *a) {
	RzBinJavaAnnotation *annotation = a;
	if (annotation) {
		rz_list_free(annotation->element_value_pairs);
		free(annotation);
	}
}

RZ_API ut64 rz_bin_java_calc_size_element_pair(RzBinJavaElementValuePair *evp) {
	ut64 sz = 0;
	if (evp == NULL) {
		return sz;
	}
	// evp->element_name_idx = rz_bin_java_read_short(bin, bin->b->cur);
	sz += 2;
	// evp->value = rz_bin_java_new_element_value (bin, offset+2);
	if (evp->value) {
		sz += rz_bin_java_calc_size_element_value(evp->value);
	}
	return sz;
}

RZ_API ut64 rz_bin_java_calc_size_element_value(RzBinJavaElementValue *element_value) {
	RzListIter *iter, *iter_tmp;
	RzBinJavaElementValue *ev_element;
	RzBinJavaElementValuePair *evps;
	ut64 sz = 0;
	if (element_value == NULL) {
		return sz;
	}
	// tag
	sz += 1;
	switch (element_value->tag) {
	case RZ_BIN_JAVA_EV_TAG_BYTE:
	case RZ_BIN_JAVA_EV_TAG_CHAR:
	case RZ_BIN_JAVA_EV_TAG_DOUBLE:
	case RZ_BIN_JAVA_EV_TAG_FLOAT:
	case RZ_BIN_JAVA_EV_TAG_INT:
	case RZ_BIN_JAVA_EV_TAG_LONG:
	case RZ_BIN_JAVA_EV_TAG_SHORT:
	case RZ_BIN_JAVA_EV_TAG_BOOLEAN:
	case RZ_BIN_JAVA_EV_TAG_STRING:
		// look up value in bin->cp_list
		// (ut16) read and set const_value.const_value_idx
		// element_value->value.const_value.const_value_idx = rz_bin_java_read_short(bin, bin->b->cur);
		sz += 2;
		break;
	case RZ_BIN_JAVA_EV_TAG_ENUM:
		// (ut16) read and set enum_const_value.type_name_idx
		// element_value->value.enum_const_value.type_name_idx = rz_bin_java_read_short(bin, bin->b->cur);
		sz += 2;
		// (ut16) read and set enum_const_value.const_name_idx
		// element_value->value.enum_const_value.const_name_idx = rz_bin_java_read_short(bin, bin->b->cur);
		sz += 2;
		break;
	case RZ_BIN_JAVA_EV_TAG_CLASS:
		// (ut16) read and set class_value.class_info_idx
		// element_value->value.class_value.class_info_idx = rz_bin_java_read_short(bin, bin->b->cur);
		sz += 2;
		break;
	case RZ_BIN_JAVA_EV_TAG_ARRAY:
		// (ut16) read and set array_value.num_values
		// element_value->value.array_value.num_values = rz_bin_java_read_short(bin, bin->b->cur);
		sz += 2;
		rz_list_foreach_safe (element_value->value.array_value.values, iter, iter_tmp, ev_element) {
			if (ev_element) {
				sz += rz_bin_java_calc_size_element_value(ev_element);
			}
		}
		break;
	case RZ_BIN_JAVA_EV_TAG_ANNOTATION:
		// annotation new is not used here.
		// (ut16) read and set annotation_value.type_idx;
		// element_value->value.annotation_value.type_idx = rz_bin_java_read_short(bin, bin->b->cur);
		sz += 2;
		// (ut16) read and set annotation_value.num_element_value_pairs;
		// element_value->value.annotation_value.num_element_value_pairs = rz_bin_java_read_short(bin, bin->b->cur);
		sz += 2;
		element_value->value.annotation_value.element_value_pairs = rz_list_newf(rz_bin_java_free_element_pair);
		rz_list_foreach_safe (element_value->value.annotation_value.element_value_pairs, iter, iter_tmp, evps) {
			if (evps) {
				sz += rz_bin_java_calc_size_element_pair(evps);
			}
		}
		break;
	default:
		// eprintf unable to handle tag
		break;
	}
	return sz;
}

RZ_API RzBinJavaElementValue *rz_bin_java_new_element_value(ut8 *buffer, ut64 sz, ut64 buf_offset) {
	ut32 i = 0;
	ut64 offset = 0;
	RzBinJavaElementValue *element_value = RZ_NEW0(RzBinJavaElementValue);
	if (!element_value) {
		return NULL;
	}
	RzBinJavaElementValuePair *evps = NULL;
	element_value->metas = RZ_NEW0(RzBinJavaMetaInfo);
	if (!element_value->metas) {
		RZ_FREE(element_value);
		return NULL;
	}
	element_value->file_offset = buf_offset;
	element_value->tag = buffer[offset];
	element_value->size += 1;
	offset += 1;
	element_value->metas->type_info = (void *)rz_bin_java_get_ev_meta_from_tag(element_value->tag);
	switch (element_value->tag) {
	case RZ_BIN_JAVA_EV_TAG_BYTE:
	case RZ_BIN_JAVA_EV_TAG_CHAR:
	case RZ_BIN_JAVA_EV_TAG_DOUBLE:
	case RZ_BIN_JAVA_EV_TAG_FLOAT:
	case RZ_BIN_JAVA_EV_TAG_INT:
	case RZ_BIN_JAVA_EV_TAG_LONG:
	case RZ_BIN_JAVA_EV_TAG_SHORT:
	case RZ_BIN_JAVA_EV_TAG_BOOLEAN:
	case RZ_BIN_JAVA_EV_TAG_STRING:
		// look up value in bin->cp_list
		// (ut16) read and set const_value.const_value_idx
		element_value->value.const_value.const_value_idx = rz_read_at_be16(buffer, offset);
		element_value->size += 2;
		// look-up, deep copy, and set const_value.const_value_cp_obj
		element_value->value.const_value.const_value_cp_obj = rz_bin_java_clone_cp_idx(RZ_BIN_JAVA_GLOBAL_BIN, element_value->value.const_value.const_value_idx);
		break;
	case RZ_BIN_JAVA_EV_TAG_ENUM:
		// (ut16) read and set enum_const_value.type_name_idx
		element_value->value.enum_const_value.type_name_idx = rz_read_at_be16(buffer, offset);
		element_value->size += 2;
		offset += 2;
		// (ut16) read and set enum_const_value.const_name_idx
		element_value->value.enum_const_value.const_name_idx = rz_read_at_be16(buffer, offset);
		element_value->size += 2;
		// look up type_name_index in bin->cp_list
		// look-up, deep copy, and set enum_const_value.const_name_cp_obj
		element_value->value.enum_const_value.const_name_cp_obj = rz_bin_java_clone_cp_idx(RZ_BIN_JAVA_GLOBAL_BIN, element_value->value.enum_const_value.const_name_idx);
		// look-up, deep copy, and set enum_const_value.type_name_cp_obj
		element_value->value.enum_const_value.type_name_cp_obj = rz_bin_java_clone_cp_idx(RZ_BIN_JAVA_GLOBAL_BIN, element_value->value.enum_const_value.type_name_idx);
		break;
	case RZ_BIN_JAVA_EV_TAG_CLASS:
		// (ut16) read and set class_value.class_info_idx
		element_value->value.class_value.class_info_idx = rz_read_at_be16(buffer, offset);
		element_value->size += 2;
		// look up type_name_index in bin->cp_list
		// look-up, deep copy, and set class_value.class_info_cp_obj
		element_value->value.class_value.class_info_cp_obj = rz_bin_java_clone_cp_idx(RZ_BIN_JAVA_GLOBAL_BIN, element_value->value.class_value.class_info_idx);
		break;
	case RZ_BIN_JAVA_EV_TAG_ARRAY:
		// (ut16) read and set array_value.num_values
		element_value->value.array_value.num_values = rz_read_at_be16(buffer, offset);
		element_value->size += 2;
		offset += 2;
		element_value->value.array_value.values = rz_list_new();
		for (i = 0; i < element_value->value.array_value.num_values; i++) {
			if (offset >= sz) {
				break;
			}
			RzBinJavaElementValue *ev_element = rz_bin_java_new_element_value(buffer + offset, sz - offset, buf_offset + offset);
			if (ev_element) {
				element_value->size += ev_element->size;
				offset += ev_element->size;
				// read array_value.num_values, and append to array_value.values
				rz_list_append(element_value->value.array_value.values, (void *)ev_element);
			}
		}
		break;
	case RZ_BIN_JAVA_EV_TAG_ANNOTATION:
		// annotation new is not used here.
		// (ut16) read and set annotation_value.type_idx;
		if (offset + 8 < sz) {
			element_value->value.annotation_value.type_idx = rz_read_at_be16(buffer, offset);
			element_value->size += 2;
			offset += 2;
			// (ut16) read and set annotation_value.num_element_value_pairs;
			element_value->value.annotation_value.num_element_value_pairs = rz_read_at_be16(buffer, offset);
			element_value->size += 2;
			offset += 2;
		}
		element_value->value.annotation_value.element_value_pairs = rz_list_newf(rz_bin_java_free_element_pair);
		// read annotation_value.num_element_value_pairs, and append to annotation_value.element_value_pairs
		for (i = 0; i < element_value->value.annotation_value.num_element_value_pairs; i++) {
			if (offset > sz) {
				break;
			}
			evps = rz_bin_java_new_element_pair(buffer + offset, sz - offset, buf_offset + offset);
			if (evps) {
				element_value->size += evps->size;
				offset += evps->size;
			}
			if (evps == NULL) {
				// TODO: eprintf error when reading element pair
			}
			rz_list_append(element_value->value.annotation_value.element_value_pairs, (void *)evps);
		}
		break;
	default:
		// eprintf unable to handle tag
		break;
	}
	return element_value;
}

RZ_API void rz_bin_java_free_bootstrap_method_argument(void /*RzBinJavaBootStrapArgument*/ *b) {
	RzBinJavaBootStrapArgument *bsm_arg = b;
	if (bsm_arg) {
		RzBinJavaCPTypeMetas *tm = (RzBinJavaCPTypeMetas *)bsm_arg->argument_info_cp_obj;
		if (tm) {
			if (tm && (size_t)(tm->allocs) > 1024 && tm->allocs->delete_obj) {
				tm->allocs->delete_obj(tm);
			}
			bsm_arg->argument_info_cp_obj = NULL;
		}
		free(bsm_arg);
	}
}

RZ_API RzBinJavaBootStrapArgument *rz_bin_java_new_bootstrap_method_argument(ut8 *buffer, ut64 sz, ut64 buf_offset) {
	ut64 offset = 0;
	RzBinJavaBootStrapArgument *bsm_arg = (RzBinJavaBootStrapArgument *)malloc(sizeof(RzBinJavaBootStrapArgument));
	if (!bsm_arg) {
		// TODO eprintf failed to allocate bytes for bootstrap_method.
		return bsm_arg;
	}
	memset(bsm_arg, 0, sizeof(RzBinJavaBootStrapArgument));
	bsm_arg->file_offset = buf_offset;
	bsm_arg->argument_info_idx = rz_read_at_be16(buffer, offset);
	offset += 2;
	bsm_arg->argument_info_cp_obj = rz_bin_java_clone_cp_idx(RZ_BIN_JAVA_GLOBAL_BIN, bsm_arg->argument_info_idx);
	bsm_arg->size = offset;
	return bsm_arg;
}

RZ_API void rz_bin_java_free_bootstrap_method(void /*/RzBinJavaBootStrapMethod*/ *b) {
	RzBinJavaBootStrapMethod *bsm = b;
	RzListIter *iter, *iter_tmp;
	RzBinJavaBootStrapArgument *obj = NULL;
	if (bsm) {
		if (bsm->bootstrap_arguments) {
			rz_list_foreach_safe (bsm->bootstrap_arguments, iter, iter_tmp, obj) {
				if (obj) {
					rz_bin_java_free_bootstrap_method_argument(obj);
				}
				// rz_list_delete (bsm->bootstrap_arguments, iter);
			}
			rz_list_free(bsm->bootstrap_arguments);
			bsm->bootstrap_arguments = NULL;
		}
		free(bsm);
	}
}

RZ_API RzBinJavaBootStrapMethod *rz_bin_java_new_bootstrap_method(ut8 *buffer, ut64 sz, ut64 buf_offset) {
	RzBinJavaBootStrapArgument *bsm_arg = NULL;
	ut32 i = 0;
	ut64 offset = 0;
	RzBinJavaBootStrapMethod *bsm = RZ_NEW0(RzBinJavaBootStrapMethod);
	if (!bsm) {
		// TODO eprintf failed to allocate bytes for bootstrap_method.
		return bsm;
	}
	memset(bsm, 0, sizeof(RzBinJavaBootStrapMethod));
	bsm->file_offset = buf_offset;
	bsm->bootstrap_method_ref = rz_read_at_be16(buffer, offset);
	offset += 2;
	bsm->num_bootstrap_arguments = rz_read_at_be16(buffer, offset);
	offset += 2;
	bsm->bootstrap_arguments = rz_list_new();
	for (i = 0; i < bsm->num_bootstrap_arguments; i++) {
		if (offset >= sz) {
			break;
		}
		// bsm_arg = rz_bin_java_new_bootstrap_method_argument (bin, bin->b->cur);
		bsm_arg = rz_bin_java_new_bootstrap_method_argument(buffer + offset, sz - offset, buf_offset + offset);
		if (bsm_arg) {
			offset += bsm_arg->size;
			rz_list_append(bsm->bootstrap_arguments, (void *)bsm_arg);
		} else {
			// TODO eprintf Failed to read the %d boot strap method.
		}
	}
	bsm->size = offset;
	return bsm;
}

RZ_API void rz_bin_java_free_bootstrap_methods_attr(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	if (attr && attr->type == RZ_BIN_JAVA_ATTRIBUTE_BOOTSTRAP_METHODS_ATTR) {
		free(attr->name);
		free(attr->metas);
		rz_list_free(attr->info.bootstrap_methods_attr.bootstrap_methods);
		free(attr);
	}
}

RZ_API ut64 rz_bin_java_calc_size_bootstrap_methods_attr(RzBinJavaAttrInfo *attr) {
	RzListIter *iter, *iter_tmp;
	RzBinJavaBootStrapMethod *bsm = NULL;
	ut64 size = 0;
	if (attr) {
		size += 6;
		// attr->info.bootstrap_methods_attr.num_bootstrap_methods = rz_read_at_be16 (buffer, offset);
		size += 2;
		rz_list_foreach_safe (attr->info.bootstrap_methods_attr.bootstrap_methods, iter, iter_tmp, bsm) {
			if (bsm) {
				size += rz_bin_java_calc_size_bootstrap_method(bsm);
			} else {
				// TODO eprintf Failed to read the %d boot strap method.
			}
		}
	}
	return size;
}

RZ_API ut64 rz_bin_java_calc_size_bootstrap_arg(RzBinJavaBootStrapArgument *bsm_arg) {
	ut64 size = 0;
	if (bsm_arg) {
		// bsm_arg->argument_info_idx = rz_read_at_be16 (buffer, offset);
		size += 2;
	}
	return size;
}

RZ_API ut64 rz_bin_java_calc_size_bootstrap_method(RzBinJavaBootStrapMethod *bsm) {
	RzListIter *iter, *iter_tmp;
	RzBinJavaBootStrapArgument *bsm_arg = NULL;
	ut64 size = 0;
	if (bsm) {
		size += 6;
		// bsm->bootstrap_method_ref = rz_read_at_be16 (buffer, offset);
		size += 2;
		// bsm->num_bootstrap_arguments = rz_read_at_be16 (buffer, offset);
		size += 2;
		rz_list_foreach_safe (bsm->bootstrap_arguments, iter, iter_tmp, bsm_arg) {
			if (bsm_arg) {
				size += rz_bin_java_calc_size_bootstrap_arg(bsm_arg);
			} else {
				// TODO eprintf Failed to read the %d boot strap method.
			}
		}
	}
	return size;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_bootstrap_methods_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	ut32 i = 0;
	RzBinJavaBootStrapMethod *bsm = NULL;
	ut64 offset = 0;
	RzBinJavaAttrInfo *attr = rz_bin_java_new_default_attr(bin, buffer, sz, buf_offset);
	offset += 6;
	if (attr) {
		attr->type = RZ_BIN_JAVA_ATTRIBUTE_BOOTSTRAP_METHODS_ATTR;
		attr->info.bootstrap_methods_attr.num_bootstrap_methods = rz_read_at_be16(buffer, offset);
		offset += 2;
		attr->info.bootstrap_methods_attr.bootstrap_methods = rz_list_newf(rz_bin_java_free_bootstrap_method);
		for (i = 0; i < attr->info.bootstrap_methods_attr.num_bootstrap_methods; i++) {
			// bsm = rz_bin_java_new_bootstrap_method (bin, bin->b->cur);
			if (offset >= sz) {
				break;
			}
			bsm = rz_bin_java_new_bootstrap_method(buffer + offset, sz - offset, buf_offset + offset);
			if (bsm) {
				offset += bsm->size;
				rz_list_append(attr->info.bootstrap_methods_attr.bootstrap_methods, (void *)bsm);
			} else {
				// TODO eprintf Failed to read the %d boot strap method.
			}
		}
		attr->size = offset;
	}
	return attr;
}

RZ_API void rz_bin_java_free_annotation_array(void /*RzBinJavaAnnotationsArray*/ *a) {
	RzBinJavaAnnotationsArray *annotation_array = a;
	RzListIter *iter = NULL, *iter_tmp = NULL;
	RzBinJavaAnnotation *annotation;
	if (!annotation_array->annotations) {
		// TODO eprintf
		return;
	}
	rz_list_foreach_safe (annotation_array->annotations, iter, iter_tmp, annotation) {
		if (annotation) {
			rz_bin_java_free_annotation(annotation);
		}
		// rz_list_delete (annotation_array->annotations, iter);
	}
	rz_list_free(annotation_array->annotations);
	free(annotation_array);
}

RZ_API RzBinJavaAnnotationsArray *rz_bin_java_new_annotation_array(ut8 *buffer, ut64 sz, ut64 buf_offset) {
	RzBinJavaAnnotation *annotation;
	RzBinJavaAnnotationsArray *annotation_array;
	ut32 i;
	ut64 offset = 0;
	annotation_array = (RzBinJavaAnnotationsArray *)malloc(sizeof(RzBinJavaAnnotationsArray));
	if (!annotation_array) {
		// TODO eprintf
		return NULL;
	}
	annotation_array->num_annotations = rz_read_at_be16(buffer, offset);
	offset += 2;
	annotation_array->annotations = rz_list_new();
	for (i = 0; i < annotation_array->num_annotations; i++) {
		if (offset > sz) {
			break;
		}
		annotation = rz_bin_java_new_annotation(buffer + offset, sz - offset, buf_offset + offset);
		if (annotation) {
			offset += annotation->size;
			rz_list_append(annotation_array->annotations, (void *)annotation);
		}
	}
	annotation_array->size = offset;
	return annotation_array;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_rtv_annotations_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	ut32 i = 0;
	RzBinJavaAttrInfo *attr = NULL;
	ut64 offset = 0;
	attr = rz_bin_java_new_default_attr(bin, buffer, sz, buf_offset);
	offset += 6;
	if (attr) {
		attr->type = RZ_BIN_JAVA_ATTRIBUTE_RUNTIME_VISIBLE_ANNOTATION_ATTR;
		attr->info.annotation_array.num_annotations = rz_read_at_be16(buffer, offset);
		offset += 2;
		attr->info.annotation_array.annotations = rz_list_newf(rz_bin_java_free_annotation);
		for (i = 0; i < attr->info.annotation_array.num_annotations; i++) {
			if (offset >= sz) {
				break;
			}
			RzBinJavaAnnotation *annotation = rz_bin_java_new_annotation(buffer + offset, sz - offset, buf_offset + offset);
			if (annotation) {
				offset += annotation->size;
				rz_list_append(attr->info.annotation_array.annotations, (void *)annotation);
			}
		}
		attr->size = offset;
	}
	return attr;
}

RZ_API ut64 rz_bin_java_calc_size_annotation_array(RzBinJavaAnnotationsArray *annotation_array) {
	ut64 size = 0;
	RzListIter *iter = NULL, *iter_tmp = NULL;
	RzBinJavaAnnotation *annotation;
	if (!annotation_array->annotations) {
		// TODO eprintf
		return size;
	}
	// annotation_array->num_annotations = rz_read_at_be16 (buffer, offset);
	size += 2;
	rz_list_foreach_safe (annotation_array->annotations, iter, iter_tmp, annotation) {
		size += rz_bin_java_calc_size_annotation(annotation);
	}
	return size;
}

RZ_API ut64 rz_bin_java_calc_size_rtv_annotations_attr(RzBinJavaAttrInfo *attr) {
	ut64 size = 0;
	if (!attr) {
		// TODO eprintf allocation fail
		return size;
	}
	size += (6 + rz_bin_java_calc_size_annotation_array(&(attr->info.annotation_array)));
	return size;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_rti_annotations_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	ut32 i = 0;
	RzBinJavaAttrInfo *attr = NULL;
	ut64 offset = 0;
	attr = rz_bin_java_new_default_attr(bin, buffer, sz, buf_offset);
	offset += 6;
	if (attr) {
		attr->type = RZ_BIN_JAVA_ATTRIBUTE_RUNTIME_INVISIBLE_ANNOTATION_ATTR;
		attr->info.annotation_array.num_annotations = rz_read_at_be16(buffer, offset);
		offset += 2;
		attr->info.annotation_array.annotations = rz_list_newf(rz_bin_java_free_annotation);
		for (i = 0; i < attr->info.rtv_annotations_attr.num_annotations; i++) {
			if (offset >= sz) {
				break;
			}
			RzBinJavaAnnotation *annotation = rz_bin_java_new_annotation(buffer + offset, sz - offset, buf_offset + offset);
			if (annotation) {
				offset += annotation->size;
			}
			rz_list_append(attr->info.annotation_array.annotations, (void *)annotation);
		}
		attr->size = offset;
	}
	return attr;
}

RZ_API ut64 rz_bin_java_calc_size_rti_annotations_attr(RzBinJavaAttrInfo *attr) {
	ut64 size = 0;
	if (!attr) {
		// TODO eprintf allocation fail
		return size;
	}
	size += (6 + rz_bin_java_calc_size_annotation_array(&(attr->info.annotation_array)));
	return size;
}

RZ_API void rz_bin_java_free_rtv_annotations_attr(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	if (attr && attr->type == RZ_BIN_JAVA_ATTRIBUTE_RUNTIME_VISIBLE_ANNOTATION_ATTR) {
		rz_list_free(attr->info.annotation_array.annotations);
		free(attr->metas);
		free(attr->name);
		free(attr);
	}
}

RZ_API void rz_bin_java_free_rti_annotations_attr(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	if (attr && attr->type == RZ_BIN_JAVA_ATTRIBUTE_RUNTIME_INVISIBLE_ANNOTATION_ATTR) {
		rz_list_free(attr->info.annotation_array.annotations);
		free(attr->metas);
		free(attr->name);
		free(attr);
	}
}

RZ_API ut64 rz_bin_java_calc_size_rtip_annotations_attr(RzBinJavaAttrInfo *attr) {
	ut64 size = 0;
	RzListIter *iter = NULL, *iter_tmp = NULL;
	RzBinJavaAnnotationsArray *annotation_array;
	if (!attr) {
		// TODO eprintf allocation fail
		return size;
	}
	// attr->info.rtip_annotations_attr.num_parameters = buffer[offset];
	size += (6 + 1);
	rz_list_foreach_safe (attr->info.rtip_annotations_attr.parameter_annotations, iter, iter_tmp, annotation_array) {
		if (annotation_array) {
			size += rz_bin_java_calc_size_annotation_array(annotation_array);
		}
	}
	return size;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_rtip_annotations_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	ut32 i = 0;
	RzBinJavaAttrInfo *attr = NULL;
	ut64 offset = 0;
	attr = rz_bin_java_new_default_attr(bin, buffer, sz, buf_offset);
	offset += 6;
	if (attr) {
		attr->type = RZ_BIN_JAVA_ATTRIBUTE_RUNTIME_INVISIBLE_PARAMETER_ANNOTATION_ATTR;
		attr->info.rtip_annotations_attr.num_parameters = buffer[offset];
		offset += 1;
		attr->info.rtip_annotations_attr.parameter_annotations = rz_list_newf(rz_bin_java_free_annotation_array);
		for (i = 0; i < attr->info.rtip_annotations_attr.num_parameters; i++) {
			if (offset >= sz) {
				break;
			}
			RzBinJavaAnnotationsArray *annotation_array = rz_bin_java_new_annotation_array(
				buffer + offset, sz - offset, buf_offset + offset);
			if (annotation_array) {
				offset += annotation_array->size;
				rz_list_append(attr->info.rtip_annotations_attr.parameter_annotations, (void *)annotation_array);
			}
		}
		attr->size = offset;
	}
	return attr;
}

RZ_API RzBinJavaAttrInfo *rz_bin_java_new_rtvp_annotations_attr(RzBinJavaObj *bin, ut8 *buffer, ut64 sz, ut64 buf_offset) {
	ut32 i = 0;
	RzBinJavaAttrInfo *attr = NULL;
	ut64 offset = 0;
	attr = rz_bin_java_new_default_attr(bin, buffer, sz, buf_offset);
	offset += 6;
	RzBinJavaAnnotationsArray *annotation_array;
	if (attr) {
		attr->type = RZ_BIN_JAVA_ATTRIBUTE_RUNTIME_VISIBLE_PARAMETER_ANNOTATION_ATTR;
		attr->info.rtvp_annotations_attr.num_parameters = buffer[offset];
		offset += 1;
		attr->info.rtvp_annotations_attr.parameter_annotations = rz_list_newf(rz_bin_java_free_annotation_array);
		for (i = 0; i < attr->info.rtvp_annotations_attr.num_parameters; i++) {
			if (offset > sz) {
				break;
			}
			annotation_array = rz_bin_java_new_annotation_array(buffer + offset, sz - offset, buf_offset + offset);
			if (annotation_array) {
				offset += annotation_array->size;
			}
			rz_list_append(attr->info.rtvp_annotations_attr.parameter_annotations, (void *)annotation_array);
		}
		attr->size = offset;
	}
	return attr;
}

RZ_API ut64 rz_bin_java_calc_size_rtvp_annotations_attr(RzBinJavaAttrInfo *attr) {
	ut64 size = 0;
	RzListIter *iter = NULL, *iter_tmp = NULL;
	RzBinJavaAnnotationsArray *annotation_array;
	if (!attr) {
		return size;
	}
	size += (6 + 1);
	rz_list_foreach_safe (attr->info.rtvp_annotations_attr.parameter_annotations,
		iter, iter_tmp, annotation_array) {
		if (annotation_array) {
			size += rz_bin_java_calc_size_annotation_array(
				annotation_array);
		}
	}
	return size;
}

RZ_API void rz_bin_java_free_rtvp_annotations_attr(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	if (attr) {
		if (attr->type == RZ_BIN_JAVA_ATTRIBUTE_RUNTIME_VISIBLE_PARAMETER_ANNOTATION_ATTR) {
			rz_list_free(attr->info.rtvp_annotations_attr.parameter_annotations);
		}
		free(attr->name);
		free(attr->metas);
		free(attr);
	}
}

RZ_API void rz_bin_java_free_rtip_annotations_attr(void /*RzBinJavaAttrInfo*/ *a) {
	RzBinJavaAttrInfo *attr = a;
	if (attr) { // && attr->type == RZ_BIN_JAVA_ATTRIBUTE_RUNTIME_INVISIBLE_PARAMETER_ANNOTATION_ATTR) {
		rz_list_free(attr->info.rtip_annotations_attr.parameter_annotations);
		free(attr->metas);
		free(attr->name);
		free(attr);
	}
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_find_cp_name_and_type_info(RzBinJavaObj *bin, ut16 name_idx, ut16 descriptor_idx) {
	RzListIter *iter, *iter_tmp;
	RzBinJavaCPTypeObj *res = NULL, *obj = NULL;
	// eprintf("Looking for name_idx: %d and descriptor_idx: %d\n", name_idx, descriptor_idx);
	rz_list_foreach_safe (bin->cp_list, iter, iter_tmp, obj) {
		if (obj && obj->tag == RZ_BIN_JAVA_CP_NAMEANDTYPE) {
			// eprintf("RzBinJavaCPTypeNameAndType has name_idx: %d and descriptor_idx: %d\n",
			//	obj->info.cp_name_and_type.name_idx, obj->info.cp_name_and_type.descriptor_idx);
			if (obj->info.cp_name_and_type.name_idx == name_idx &&
				obj->info.cp_name_and_type.descriptor_idx == descriptor_idx) {
				res = obj;
				break;
			}
		}
	}
	return res;
}

RZ_API char *rz_bin_java_resolve_cp_idx_type(RzBinJavaObj *BIN_OBJ, int idx) {
	RzBinJavaCPTypeObj *item = NULL;
	char *str = NULL;
	if (BIN_OBJ && BIN_OBJ->cp_count < 1) {
		// rz_bin_java_new_bin(BIN_OBJ);
		return NULL;
	}
	item = (RzBinJavaCPTypeObj *)rz_bin_java_get_item_from_bin_cp_list(BIN_OBJ, idx);
	if (item) {
		str = strdup(((RzBinJavaCPTypeMetas *)item->metas->type_info)->name);
	} else {
		str = strdup("INVALID");
	}
	return str;
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_find_cp_ref_info_from_name_and_type(RzBinJavaObj *bin, ut16 name_idx, ut16 descriptor_idx) {
	RzBinJavaCPTypeObj *obj = rz_bin_java_find_cp_name_and_type_info(bin, name_idx, descriptor_idx);
	if (obj) {
		return rz_bin_java_find_cp_ref_info(bin, obj->metas->ord);
	}
	return NULL;
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_find_cp_ref_info(RzBinJavaObj *bin, ut16 name_and_type_idx) {
	RzListIter *iter, *iter_tmp;
	RzBinJavaCPTypeObj *res = NULL, *obj = NULL;
	rz_list_foreach_safe (bin->cp_list, iter, iter_tmp, obj) {
		if (obj->tag == RZ_BIN_JAVA_CP_FIELDREF &&
			obj->info.cp_field.name_and_type_idx == name_and_type_idx) {
			res = obj;
			break;
		} else if (obj->tag == RZ_BIN_JAVA_CP_METHODREF &&
			obj->info.cp_method.name_and_type_idx == name_and_type_idx) {
			res = obj;
			break;
		}
	}
	return res;
}

RZ_API char *rz_bin_java_resolve(RzBinJavaObj *BIN_OBJ, int idx, ut8 space_bn_name_type) {
	// TODO XXX FIXME add a size parameter to the str when it is passed in
	RzBinJavaCPTypeObj *item = NULL, *item2 = NULL;
	char *class_str = NULL,
	     *name_str = NULL,
	     *desc_str = NULL,
	     *string_str = NULL,
	     *empty = "",
	     *cp_name = NULL,
	     *str = NULL;
	if (BIN_OBJ && BIN_OBJ->cp_count < 1) {
		// rz_bin_java_new_bin(BIN_OBJ);
		return NULL;
	}
	item = (RzBinJavaCPTypeObj *)rz_bin_java_get_item_from_bin_cp_list(BIN_OBJ, idx);
	if (item) {
		cp_name = ((RzBinJavaCPTypeMetas *)item->metas->type_info)->name;
		// eprintf("java_resolve Resolved: (%d) %s\n", idx, cp_name);
	} else {
		int size = snprintf(NULL, 0, "(%d) INVALID CP_OBJ", idx);
		str = malloc(size + 1);
		if (str) {
			snprintf(str, size + 1, "(%d) INVALID CP_OBJ", idx);
		}
		return str;
	}
	if (strcmp(cp_name, "Class") == 0) {
		item2 = (RzBinJavaCPTypeObj *)rz_bin_java_get_item_from_bin_cp_list(BIN_OBJ, idx);
		// str = rz_bin_java_get_name_from_bin_cp_list (BIN_OBJ, idx-1);
		class_str = rz_bin_java_get_item_name_from_bin_cp_list(BIN_OBJ, item);
		if (!class_str) {
			class_str = empty;
		}
		name_str = rz_bin_java_get_item_name_from_bin_cp_list(BIN_OBJ, item2);
		if (!name_str) {
			name_str = empty;
		}
		desc_str = rz_bin_java_get_item_desc_from_bin_cp_list(BIN_OBJ, item2);
		if (!desc_str) {
			desc_str = empty;
		}
		str = rz_str_newf("%s%s%s", name_str,
			space_bn_name_type ? " " : "", desc_str);
		if (class_str != empty) {
			free(class_str);
		}
		if (name_str != empty) {
			free(name_str);
		}
		if (desc_str != empty) {
			free(desc_str);
		}
	} else if (!strcmp(cp_name, "MethodRef") ||
		!strcmp(cp_name, "FieldRef") ||
		!strcmp(cp_name, "InterfaceMethodRef")) {
		/*
		*  The MethodRef, FieldRef, and InterfaceMethodRef structures
		*/
		class_str = rz_bin_java_get_name_from_bin_cp_list(BIN_OBJ, item->info.cp_method.class_idx);
		if (!class_str) {
			class_str = empty;
		}
		name_str = rz_bin_java_get_item_name_from_bin_cp_list(BIN_OBJ, item);
		if (!name_str) {
			name_str = empty;
		}
		desc_str = rz_bin_java_get_item_desc_from_bin_cp_list(BIN_OBJ, item);
		if (!desc_str) {
			desc_str = empty;
		}
		str = rz_str_newf("%s/%s%s%s", class_str, name_str,
			space_bn_name_type ? " " : "", desc_str);
		if (class_str != empty) {
			free(class_str);
		}
		if (name_str != empty) {
			free(name_str);
		}
		if (desc_str != empty) {
			free(desc_str);
		}
	} else if (!strcmp(cp_name, "String")) {
		string_str = rz_bin_java_get_utf8_from_bin_cp_list(BIN_OBJ, item->info.cp_string.string_idx);
		str = NULL;
		// eprintf("java_resolve String got: (%d) %s\n", item->info.cp_string.string_idx, string_str);
		if (!string_str) {
			string_str = empty;
		}
		str = rz_str_newf("\"%s\"", string_str);
		// eprintf("java_resolve String return: %s\n", str);
		if (string_str != empty) {
			free(string_str);
		}

	} else if (!strcmp(cp_name, "Utf8")) {
		char *tmp_str = sanitize_string((const char *)item->info.cp_utf8.bytes, item->info.cp_utf8.length);
		ut32 tmp_str_len = tmp_str ? strlen(tmp_str) + 4 : 0;
		if (tmp_str) {
			str = malloc(tmp_str_len + 4);
			snprintf(str, tmp_str_len + 4, "\"%s\"", tmp_str);
		}
		free(tmp_str);
	} else if (!strcmp(cp_name, "Long")) {
		str = rz_str_newf("0x%" PFMT64x, rz_read_at_be64(item->info.cp_long.bytes.raw, 0));
	} else if (!strcmp(cp_name, "Double")) {
		str = rz_str_newf("%f", raw_to_double(item->info.cp_double.bytes.raw, 0));
	} else if (!strcmp(cp_name, "Integer")) {
		str = rz_str_newf("0x%08x", rz_read_at_be32(item->info.cp_integer.bytes.raw, 0));
	} else if (!strcmp(cp_name, "Float")) {
		str = rz_str_newf("%f", raw_to_float(item->info.cp_float.bytes.raw, 0));
	} else if (!strcmp(cp_name, "NameAndType")) {
		name_str = rz_bin_java_get_item_name_from_bin_cp_list(BIN_OBJ, item);
		if (!name_str) {
			name_str = empty;
		}
		desc_str = rz_bin_java_get_item_desc_from_bin_cp_list(BIN_OBJ, item);
		if (!desc_str) {
			desc_str = empty;
		}
		str = rz_str_newf("%s%s%s", name_str, space_bn_name_type ? " " : "", desc_str);
		if (name_str != empty) {
			free(name_str);
		}
		if (desc_str != empty) {
			free(desc_str);
		}
	} else {
		str = strdup("(null)");
	}
	return str;
}

RZ_API ut8 rz_bin_java_does_cp_idx_ref_method(RzBinJavaObj *BIN_OBJ, int idx) {
	RzBinJavaField *fm_type = NULL;
	RzListIter *iter;
	ut8 res = 0;
	rz_list_foreach (BIN_OBJ->methods_list, iter, fm_type) {
		if (fm_type->field_ref_cp_obj->metas->ord == idx) {
			res = 1;
			break;
		}
	}
	return res;
}

RZ_API ut8 rz_bin_java_does_cp_idx_ref_field(RzBinJavaObj *BIN_OBJ, int idx) {
	RzBinJavaField *fm_type = NULL;
	RzListIter *iter;
	ut8 res = 0;
	rz_list_foreach (BIN_OBJ->fields_list, iter, fm_type) {
		if (fm_type->field_ref_cp_obj->metas->ord == idx) {
			res = 1;
			break;
		}
	}
	return res;
}

RZ_API char *rz_bin_java_get_method_name(RzBinJavaObj *bin_obj, ut32 idx) {
	char *name = NULL;
	if (idx < rz_list_length(bin_obj->methods_list)) {
		RzBinJavaField *fm_type = rz_list_get_n(bin_obj->methods_list, idx);
		name = strdup(fm_type->name);
	}
	return name;
}

RZ_API RzList *rz_bin_java_get_method_num_name(RzBinJavaObj *bin_obj) {
	ut32 i = 0;
	RzListIter *iter = NULL;
	RzBinJavaField *fm_type;
	RzList *res = rz_list_newf(free);
	rz_list_foreach (bin_obj->methods_list, iter, fm_type) {
		ut32 len = strlen(fm_type->name) + 30;
		char *str = malloc(len);
		snprintf(str, len, "%d %s", i, fm_type->name);
		++i;
		rz_list_append(res, str);
	}
	return res;
}

/*
   RZ_API int rz_bin_java_does_cp_obj_ref_idx (RzBinJavaObj *bin_obj, RzBinJavaCPTypeObj *cp_obj, ut16 idx) {
        int res = false;
        RzBinJavaCPTypeObj *t_obj = NULL;
        if (cp_obj) {
                switch (cp_obj->tag) {
                        case RZ_BIN_JAVA_CP_NULL: break;
                        case RZ_BIN_JAVA_CP_UTF8: break;
                        case RZ_BIN_JAVA_CP_UNKNOWN: break;
                        case RZ_BIN_JAVA_CP_INTEGER: break;
                        case RZ_BIN_JAVA_CP_FLOAT: break;
                        case RZ_BIN_JAVA_CP_LONG: break;
                        case RZ_BIN_JAVA_CP_DOUBLE: break;
                        case RZ_BIN_JAVA_CP_CLASS:
                                res = idx == cp_obj->info.cp_class.name_idx ? true : false;
                                break;
                        case RZ_BIN_JAVA_CP_STRING:
                                res = idx == cp_obj->info.cp_string.string_idx ? true : false;
                                break;
                        case RZ_BIN_JAVA_CP_METHODREF: break;// check if idx is referenced here
                        case RZ_BIN_JAVA_CP_INTERFACEMETHOD_REF: break; // check if idx is referenced here
                        case RZ_BIN_JAVA_CP_FIELDREF:
                                t_obj = rz_bin_java_get_item_from_cp (bin_obj, cp_obj->info.cp_method.class_idx);
                                res = rz_bin_java_does_cp_obj_ref_idx (bin_obj, t_obj, idx);
                                if (res == true) break;
                                t_obj = rz_bin_java_get_item_from_cp (bin_obj, cp_obj->info.cp_method.name_and_type_idx);
                                res = rz_bin_java_does_cp_obj_ref_idx (bin_obj, t_obj, idx);
                                break;
                        case RZ_BIN_JAVA_CP_NAMEANDTYPE: break;// check if idx is referenced here
                                obj->info.cp_name_and_type.name_idx
                        case RZ_BIN_JAVA_CP_METHODHANDLE: break;// check if idx is referenced here
                        case RZ_BIN_JAVA_CP_METHODTYPE: break;// check if idx is referenced here
                        case RZ_BIN_JAVA_CP_INVOKEDYNAMIC: break;// check if idx is referenced here
                }
        }
   }
 */
RZ_API RzList *rz_bin_java_find_cp_const_by_val_long(RzBinJavaObj *bin_obj, const ut8 *bytes, ut32 len) {
	RzList *res = rz_list_newf(free);
	ut32 *v = NULL;
	RzListIter *iter;
	RzBinJavaCPTypeObj *cp_obj;
	eprintf("Looking for 0x%08x\n", rz_read_at_be32(bytes, 0));
	rz_list_foreach (bin_obj->cp_list, iter, cp_obj) {
		if (cp_obj->tag == RZ_BIN_JAVA_CP_LONG) {
			if (len == 8 && rz_read_at_be64(cp_obj->info.cp_long.bytes.raw, 0) == rz_read_at_be64(bytes, 0)) {
				// TODO: we can safely store a ut32 inside the list without having to allocate it
				v = malloc(sizeof(ut32));
				if (!v) {
					rz_list_free(res);
					return NULL;
				}
				*v = cp_obj->idx;
				rz_list_append(res, v);
			}
		}
	}
	return res;
}

RZ_API RzList *rz_bin_java_find_cp_const_by_val_double(RzBinJavaObj *bin_obj, const ut8 *bytes, ut32 len) {
	RzList *res = rz_list_newf(free);
	ut32 *v = NULL;
	RzListIter *iter;
	RzBinJavaCPTypeObj *cp_obj;
	eprintf("Looking for %f\n", raw_to_double(bytes, 0));
	rz_list_foreach (bin_obj->cp_list, iter, cp_obj) {
		if (cp_obj->tag == RZ_BIN_JAVA_CP_DOUBLE) {
			if (len == 8 && raw_to_double(cp_obj->info.cp_long.bytes.raw, 0) == raw_to_double(bytes, 0)) {
				v = malloc(sizeof(ut32));
				if (!v) {
					rz_list_free(res);
					return NULL;
				}
				*v = cp_obj->idx;
				rz_list_append(res, v);
			}
		}
	}
	return res;
}

RZ_API RzList *rz_bin_java_find_cp_const_by_val_float(RzBinJavaObj *bin_obj, const ut8 *bytes, ut32 len) {
	RzList *res = rz_list_newf(free);
	ut32 *v = NULL;
	RzListIter *iter;
	RzBinJavaCPTypeObj *cp_obj;
	eprintf("Looking for %f\n", raw_to_float(bytes, 0));
	rz_list_foreach (bin_obj->cp_list, iter, cp_obj) {
		if (cp_obj->tag == RZ_BIN_JAVA_CP_FLOAT) {
			if (len == 4 && raw_to_float(cp_obj->info.cp_long.bytes.raw, 0) == raw_to_float(bytes, 0)) {
				v = malloc(sizeof(ut32));
				if (!v) {
					rz_list_free(res);
					return NULL;
				}
				*v = cp_obj->idx;
				rz_list_append(res, v);
			}
		}
	}
	return res;
}

RZ_API RzList *rz_bin_java_find_cp_const_by_val(RzBinJavaObj *bin_obj, const ut8 *bytes, ut32 len, const char t) {
	switch (t) {
	case RZ_BIN_JAVA_CP_UTF8: return rz_bin_java_find_cp_const_by_val_utf8(bin_obj, bytes, len);
	case RZ_BIN_JAVA_CP_INTEGER: return rz_bin_java_find_cp_const_by_val_int(bin_obj, bytes, len);
	case RZ_BIN_JAVA_CP_FLOAT: return rz_bin_java_find_cp_const_by_val_float(bin_obj, bytes, len);
	case RZ_BIN_JAVA_CP_LONG: return rz_bin_java_find_cp_const_by_val_long(bin_obj, bytes, len);
	case RZ_BIN_JAVA_CP_DOUBLE: return rz_bin_java_find_cp_const_by_val_double(bin_obj, bytes, len);
	case RZ_BIN_JAVA_CP_UNKNOWN:
	default:
		eprintf("Failed to perform the search for: %s\n", bytes);
		return rz_list_new();
	}
}

// #if 0
// Attempted to clean up these functions and remove them since they are "unused" but without
// them there are some compile time warnings, because other projects actually depend on these
// for some form of information.
RZ_API void add_cp_objs_to_sdb(RzBinJavaObj *bin) {
	/*
	Add Constant Pool Serialized Object to an Array
	the key for this info is:
	Key:
	java.<classname>.cp_obj
	Each Value varies by type:
	In general its:
	<ordinal>.<file_offset>.<type_name>.[type specific stuff]
	Example:
	UTF-8:  <ordinal>.<file_offset>.<type_name>.<strlen>.<hexlified(str)>
	Integer: <ordinal>.<file_offset>.<type_name>.<abs(int)>
	Long: <ordinal>.<file_offset>.<type_name>.abs(long)>
	FieldRef/MethodRef: <ordinal>.<file_offset>.<type_name>.<class_idx>.<name_and_type_idx>
	*/
	ut32 idx = 0, class_name_inheap = 1;
	RzBinJavaCPTypeObj *cp_obj = NULL;
	char *key = NULL,
	     *value = NULL;
	char str_cnt[40];
	char *class_name = rz_bin_java_get_this_class_name(bin);
	ut32 key_buf_size = 0;
	if (!class_name) {
		class_name = "unknown";
		class_name_inheap = 0;
	}
	// 4 - format, 8 number, 1 null byte, 7 "unknown"
	key_buf_size = strlen(class_name) + 4 + 8 + 1;
	key = malloc(key_buf_size);
	if (key == NULL) {
		if (class_name_inheap) {
			free(class_name);
		}
		return;
	}
	snprintf(key, key_buf_size - 1, "%s.cp_count", class_name);
	key[key_buf_size - 1] = 0;
	snprintf(str_cnt, 39, "%d", bin->cp_count);
	str_cnt[39] = 0;
	sdb_set(bin->kv, key, value, 0);
	// sdb_alist(bin->kv, key);
	for (idx = 0; idx < bin->cp_count; idx++) {
		snprintf(key, key_buf_size - 1, "%s.cp.%d", class_name, idx);
		key[key_buf_size - 1] = 0;
		cp_obj = (RzBinJavaCPTypeObj *)rz_bin_java_get_item_from_bin_cp_list(bin, idx);
		// eprintf("Adding %s to the sdb.\n", key);
		if (cp_obj) {
			value = ((RzBinJavaCPTypeMetas *)
					 cp_obj->metas->type_info)
					->allocs->stringify_obj(cp_obj);
			sdb_set(bin->kv, key, value, 0);
			free(value);
		}
	}
	if (class_name_inheap) {
		free(class_name);
	}
	free(key);
}

RZ_API void add_field_infos_to_sdb(RzBinJavaObj *bin) {
	/*
	*** Experimental and May Change ***
	Add field information to an Array
	the key for this info variable depenedent on addr, method ordinal, etc.
	Key 1, mapping to method key:
	java.<file_offset> = <field_key>
	Key 3, method description
	<field_key>.info = [<access str>, <class_name>, <name>, <signature>]
	key 4, method meta
	<field_key>.meta = [<file_offset>, ?]
	*/
	RzListIter *iter = NULL, *iter_tmp = NULL;
	RzBinJavaField *fm_type;
	ut32 key_size = 255,
	     value_buffer_size = 1024,
	     class_name_inheap = 1;
	char *field_key = NULL,
	     *field_key_value = NULL,
	     *value_buffer = NULL;
	char *class_name = rz_bin_java_get_this_class_name(bin);
	if (!class_name) {
		class_name = "unknown";
		class_name_inheap = 0;
	}
	key_size += strlen(class_name);
	value_buffer_size += strlen(class_name);
	field_key = malloc(key_size);
	value_buffer = malloc(value_buffer_size);
	field_key_value = malloc(key_size);
	snprintf(field_key, key_size, "%s.methods", class_name);
	field_key[key_size - 1] = 0;
	rz_list_foreach_safe (bin->fields_list, iter, iter_tmp, fm_type) {
		char number_buffer[80];
		ut64 file_offset = fm_type->file_offset + bin->loadaddr;
		snprintf(number_buffer, sizeof(number_buffer), "0x%04" PFMT64x, file_offset);
		// eprintf("Inserting: []%s = %s\n", field_key, number_buffer);
		sdb_array_push(bin->kv, field_key, number_buffer, 0);
	}
	rz_list_foreach_safe (bin->fields_list, iter, iter_tmp, fm_type) {
		ut64 field_offset = fm_type->file_offset + bin->loadaddr;
		// generate method specific key & value
		snprintf(field_key, key_size, "%s.0x%04" PFMT64x, class_name, field_offset);
		field_key[key_size - 1] = 0;
		snprintf(field_key_value, key_size, "%s.0x%04" PFMT64x ".field", class_name, field_offset);
		field_key_value[key_size - 1] = 0;
		sdb_set(bin->kv, field_key, field_key_value, 0);
		// eprintf("Inserting: %s = %s\n", field_key, field_key_value);
		// generate info key, and place values in method info array
		snprintf(field_key, key_size, "%s.info", field_key_value);
		field_key[key_size - 1] = 0;
		snprintf(value_buffer, value_buffer_size, "%s", fm_type->flags_str);
		value_buffer[value_buffer_size - 1] = 0;
		sdb_array_push(bin->kv, field_key, value_buffer, 0);
		// eprintf("Inserting: []%s = %s\n", field_key, value_buffer);
		snprintf(value_buffer, value_buffer_size, "%s", fm_type->class_name);
		value_buffer[value_buffer_size - 1] = 0;
		sdb_array_push(bin->kv, field_key, value_buffer, 0);
		// eprintf("Inserting: []%s = %s\n", field_key, value_buffer);
		snprintf(value_buffer, value_buffer_size, "%s", fm_type->name);
		value_buffer[value_buffer_size - 1] = 0;
		sdb_array_push(bin->kv, field_key, value_buffer, 0);
		// eprintf("Inserting: []%s = %s\n", field_key, value_buffer);
		snprintf(value_buffer, value_buffer_size, "%s", fm_type->descriptor);
		value_buffer[value_buffer_size - 1] = 0;
		sdb_array_push(bin->kv, field_key, value_buffer, 0);
		// eprintf("Inserting: []%s = %s\n", field_key, value_buffer);
	}
	free(field_key);
	free(field_key_value);
	free(value_buffer);
	if (class_name_inheap) {
		free(class_name);
	}
}

RZ_API void add_method_infos_to_sdb(RzBinJavaObj *bin) {
	/*
	*** Experimental and May Change ***
	Add Mehtod information to an Array
	the key for this info variable depenedent on addr, method ordinal, etc.
	Key 1, mapping to method key:
	java.<file_offset> = <method_key>
	Key 2, basic code information
	<method_key>.code = [<addr>, <size>]
	Key 3, method description
	<method_key>.info = [<access str>, <class_name>, <name>, <signature>,]
	key 4, method meta
	<method_key>.meta = [<file_offset>, ?]
	// TODO in key 3 add <class_name>?
	e.g. <access str>.<name>.<signature>
	Note: method name not used because of collisions with operator overloading
	also take note that code offset and the method offset are not the same
	values.
	*/
	RzListIter *iter = NULL, *iter_tmp = NULL;
	RzBinJavaField *fm_type;
	ut32 key_size = 255,
	     value_buffer_size = 1024,
	     class_name_inheap = 1;
	char *method_key = NULL,
	     *method_key_value = NULL,
	     *value_buffer = NULL;
	char *class_name = rz_bin_java_get_this_class_name(bin);
	ut64 baddr = bin->loadaddr;
	if (!class_name) {
		class_name = "unknown";
		class_name_inheap = 0;
	}
	key_size += strlen(class_name);
	value_buffer_size += strlen(class_name);
	method_key = malloc(key_size);
	value_buffer = malloc(value_buffer_size);
	method_key_value = malloc(key_size);
	snprintf(method_key, key_size, "%s.methods", class_name);
	method_key[key_size - 1] = 0;
	rz_list_foreach_safe (bin->methods_list, iter, iter_tmp, fm_type) {
		char number_buffer[80];
		ut64 file_offset = fm_type->file_offset + baddr;
		snprintf(number_buffer, sizeof(number_buffer), "0x%04" PFMT64x, file_offset);
		sdb_array_push(bin->kv, method_key, number_buffer, 0);
	}
	rz_list_foreach_safe (bin->methods_list, iter, iter_tmp, fm_type) {
		ut64 code_offset = rz_bin_java_get_method_code_offset(fm_type) + baddr,
		     code_size = rz_bin_java_get_method_code_size(fm_type),
		     method_offset = fm_type->file_offset + baddr;
		// generate method specific key & value
		snprintf(method_key, key_size, "%s.0x%04" PFMT64x, class_name, code_offset);
		method_key[key_size - 1] = 0;
		snprintf(method_key_value, key_size, "%s.0x%04" PFMT64x ".method", class_name, method_offset);
		method_key_value[key_size - 1] = 0;
		// eprintf("Adding %s to sdb_array: %s\n", method_key_value, method_key);
		sdb_set(bin->kv, method_key, method_key_value, 0);
		// generate code key and values
		snprintf(method_key, key_size, "%s.code", method_key_value);
		method_key[key_size - 1] = 0;
		snprintf(value_buffer, value_buffer_size, "0x%04" PFMT64x, code_offset);
		value_buffer[value_buffer_size - 1] = 0;
		sdb_array_push(bin->kv, method_key, value_buffer, 0);
		snprintf(value_buffer, value_buffer_size, "0x%04" PFMT64x, code_size);
		value_buffer[value_buffer_size - 1] = 0;
		sdb_array_push(bin->kv, method_key, value_buffer, 0);
		// generate info key, and place values in method info array
		snprintf(method_key, key_size, "%s.info", method_key_value);
		method_key[key_size - 1] = 0;
		snprintf(value_buffer, value_buffer_size, "%s", fm_type->flags_str);
		value_buffer[value_buffer_size - 1] = 0;
		// eprintf("Adding %s to sdb_array: %s\n", value_buffer, method_key);
		sdb_array_push(bin->kv, method_key, value_buffer, 0);
		snprintf(value_buffer, value_buffer_size, "%s", fm_type->class_name);
		value_buffer[value_buffer_size - 1] = 0;
		// eprintf("Adding %s to sdb_array: %s\n", value_buffer, method_key);
		sdb_array_push(bin->kv, method_key, value_buffer, 0);
		snprintf(value_buffer, value_buffer_size, "%s", fm_type->name);
		value_buffer[value_buffer_size - 1] = 0;
		// eprintf("Adding %s to sdb_array: %s\n", value_buffer, method_key);
		sdb_array_push(bin->kv, method_key, value_buffer, 0);
		snprintf(value_buffer, value_buffer_size, "%s", fm_type->descriptor);
		value_buffer[value_buffer_size - 1] = 0;
		// eprintf("Adding %s to sdb_array: %s\n", value_buffer, method_key);
		sdb_array_push(bin->kv, method_key, value_buffer, 0);
	}
	free(method_key);
	free(method_key_value);
	free(value_buffer);
	if (class_name_inheap) {
		free(class_name);
	}
}

RZ_API RzList *rz_bin_java_get_args_from_bin(RzBinJavaObj *bin_obj, ut64 addr) {
	RzBinJavaField *fm_type = rz_bin_java_get_method_code_attribute_with_addr(bin_obj, addr);
	return fm_type ? rz_bin_java_get_args(fm_type) : NULL;
}

RZ_API RzList *rz_bin_java_get_ret_from_bin(RzBinJavaObj *bin_obj, ut64 addr) {
	RzBinJavaField *fm_type = rz_bin_java_get_method_code_attribute_with_addr(bin_obj, addr);
	return fm_type ? rz_bin_java_get_ret(fm_type) : NULL;
}

RZ_API char *rz_bin_java_get_fcn_name_from_bin(RzBinJavaObj *bin_obj, ut64 addr) {
	RzBinJavaField *fm_type = rz_bin_java_get_method_code_attribute_with_addr(bin_obj, addr);
	return fm_type && fm_type->name ? strdup(fm_type->name) : NULL;
}

RZ_API int rz_bin_java_is_method_static(RzBinJavaObj *bin_obj, ut64 addr) {
	RzBinJavaField *fm_type = rz_bin_java_get_method_code_attribute_with_addr(bin_obj, addr);
	return fm_type && fm_type->flags & RZ_BIN_JAVA_METHOD_ACC_STATIC;
}

RZ_API int rz_bin_java_is_method_private(RzBinJavaObj *bin_obj, ut64 addr) {
	return rz_bin_java_is_fm_type_private(rz_bin_java_get_method_code_attribute_with_addr(bin_obj, addr));
}

RZ_API int rz_bin_java_is_method_protected(RzBinJavaObj *bin_obj, ut64 addr) {
	return rz_bin_java_is_fm_type_protected(
		rz_bin_java_get_method_code_attribute_with_addr(bin_obj, addr));
}

RZ_API bool rz_bin_java_summary_print_method_idx(RzBinJavaObj *bin_obj, ut32 idx) {
	if (idx < rz_list_length(bin_obj->methods_list)) {
		RzBinJavaField *fm_type = rz_list_get_n(bin_obj->methods_list, idx);
		rz_bin_java_summary_print_method(fm_type);
		return true;
	}
	return false;
}

RZ_API ut32 rz_bin_java_get_method_count(RzBinJavaObj *bin_obj) {
	return rz_list_length(bin_obj->methods_list);
}

RZ_API RzList *rz_bin_java_get_interface_names(RzBinJavaObj *bin) {
	RzList *interfaces_names = rz_list_new();
	RzListIter *iter;
	RzBinJavaInterfaceInfo *ifobj;
	rz_list_foreach (bin->interfaces_list, iter, ifobj) {
		if (ifobj && ifobj->name) {
			rz_list_append(interfaces_names, strdup(ifobj->name));
		}
	}
	return interfaces_names;
}

RZ_API ut64 rz_bin_java_get_main(RzBinJavaObj *bin) {
	if (bin->main_code_attr) {
		return bin->main_code_attr->info.code_attr.code_offset + bin->loadaddr;
	}
	return 0;
}

RZ_API RzBinJavaObj *rz_bin_java_new(const char *file, ut64 loadaddr, Sdb *kv) {
	RzBinJavaObj *bin = RZ_NEW0(RzBinJavaObj);
	if (!bin) {
		return NULL;
	}
	bin->file = strdup(file);
	size_t sz;
	ut8 *buf = (ut8 *)rz_file_slurp(file, &sz);
	bin->size = sz;
	if (!buf) {
		return rz_bin_java_free(bin);
	}
	if (!rz_bin_java_new_bin(bin, loadaddr, kv, buf, bin->size)) {
		rz_bin_java_free(bin);
		bin = NULL;
	}
	free(buf);
	return bin;
}

RZ_API ut64 rz_bin_java_get_class_entrypoint(RzBinJavaObj *bin) {
	if (bin->cf2.this_class_entrypoint_code_attr) {
		return bin->cf2.this_class_entrypoint_code_attr->info.code_attr.code_offset;
	}
	return 0;
}

RZ_API RzList *rz_bin_java_get_method_exception_table_with_addr(RzBinJavaObj *bin, ut64 addr) {
	RzListIter *iter = NULL, *iter_tmp = NULL;
	RzBinJavaField *fm_type, *res = NULL;
	if (!bin && RZ_BIN_JAVA_GLOBAL_BIN) {
		bin = RZ_BIN_JAVA_GLOBAL_BIN;
	}
	if (!bin) {
		eprintf("Attempting to analyse function when the RZ_BIN_JAVA_GLOBAL_BIN has not been set.\n");
		return NULL;
	}
	rz_list_foreach_safe (bin->methods_list, iter, iter_tmp, fm_type) {
		ut64 offset = rz_bin_java_get_method_code_offset(fm_type) + bin->loadaddr,
		     size = rz_bin_java_get_method_code_size(fm_type);
		if (addr >= offset && addr <= size + offset) {
			res = fm_type;
		}
	}
	if (res) {
		RzBinJavaAttrInfo *code_attr = rz_bin_java_get_method_code_attribute(res);
		return code_attr->info.code_attr.exception_table;
	}
	return NULL;
}

RZ_API const RzList *rz_bin_java_get_methods_list(RzBinJavaObj *bin) {
	if (bin) {
		return bin->methods_list;
	}
	if (RZ_BIN_JAVA_GLOBAL_BIN) {
		return RZ_BIN_JAVA_GLOBAL_BIN->methods_list;
	}
	return NULL;
}

RZ_API RzList *rz_bin_java_get_bin_obj_list_thru_obj(RzBinJavaObj *bin_obj) {
	RzList *the_list;
	Sdb *sdb;
	if (!bin_obj) {
		return NULL;
	}
	sdb = bin_obj->AllJavaBinObjs;
	if (!sdb) {
		return NULL;
	}
	the_list = rz_list_new();
	if (!the_list) {
		return NULL;
	}
	sdb_foreach(sdb, sdb_iterate_build_list, (void *)the_list);
	return the_list;
}

RZ_API RzList *rz_bin_java_extract_all_bin_type_values(RzBinJavaObj *bin_obj) {
	RzListIter *fm_type_iter;
	RzList *all_types = rz_list_new();
	RzBinJavaField *fm_type;
	// get all field types
	rz_list_foreach (bin_obj->fields_list, fm_type_iter, fm_type) {
		char *desc = NULL;
		if (!extract_type_value(fm_type->descriptor, &desc)) {
			return NULL;
		}
		// eprintf("Adding field type: %s\n", desc);
		rz_list_append(all_types, desc);
	}
	// get all method types
	rz_list_foreach (bin_obj->methods_list, fm_type_iter, fm_type) {
		RzList *the_list = rz_bin_java_extract_type_values(fm_type->descriptor);
		RzListIter *desc_iter;
		char *str;
		rz_list_foreach (the_list, desc_iter, str) {
			if (str && *str != '(' && *str != ')') {
				rz_list_append(all_types, strdup(str));
				// eprintf("Adding method type: %s\n", str);
			}
		}
		rz_list_free(the_list);
	}
	return all_types;
}

RZ_API RzList *rz_bin_java_get_method_definitions(RzBinJavaObj *bin) {
	RzBinJavaField *fm_type = NULL;
	RzList *the_list = rz_list_new();
	if (!the_list) {
		return NULL;
	}
	RzListIter *iter = NULL;
	if (!bin) {
		return the_list;
	}
	rz_list_foreach (bin->methods_list, iter, fm_type) {
		char *method_proto = rz_bin_java_get_method_definition(fm_type);
		// eprintf ("Method prototype: %s\n", method_proto);
		rz_list_append(the_list, method_proto);
	}
	return the_list;
}

RZ_API RzList *rz_bin_java_get_field_definitions(RzBinJavaObj *bin) {
	RzBinJavaField *fm_type = NULL;
	RzList *the_list = rz_list_new();
	if (!the_list) {
		return NULL;
	}
	RzListIter *iter = NULL;
	if (!bin) {
		return the_list;
	}
	rz_list_foreach (bin->fields_list, iter, fm_type) {
		char *field_def = rz_bin_java_get_field_definition(fm_type);
		// eprintf ("Field def: %s, %s, %s, %s\n", fm_type->name, fm_type->descriptor, fm_type->flags_str, field_def);
		rz_list_append(the_list, field_def);
	}
	return the_list;
}

RZ_API RzList *rz_bin_java_get_import_definitions(RzBinJavaObj *bin) {
	RzList *the_list = rz_bin_java_get_lib_names(bin);
	RzListIter *iter = NULL;
	char *new_str;
	if (!bin || !the_list) {
		return the_list;
	}
	rz_list_foreach (the_list, iter, new_str) {
		while (*new_str) {
			if (*new_str == '/') {
				*new_str = '.';
			}
			new_str++;
		}
	}
	return the_list;
}

RZ_API RzList *rz_bin_java_get_field_offsets(RzBinJavaObj *bin) {
	RzBinJavaField *fm_type = NULL;
	RzList *the_list = rz_list_new();
	RzListIter *iter = NULL;
	ut64 *paddr = NULL;
	if (!bin) {
		return the_list;
	}
	the_list->free = free;
	rz_list_foreach (bin->fields_list, iter, fm_type) {
		paddr = RZ_NEW0(ut64);
		*paddr = fm_type->file_offset + bin->loadaddr;
		rz_list_append(the_list, paddr);
	}
	return the_list;
}

RZ_API RzList *rz_bin_java_get_method_offsets(RzBinJavaObj *bin) {
	RzBinJavaField *fm_type = NULL;
	RzList *the_list = rz_list_new();
	RzListIter *iter = NULL;
	ut64 *paddr = NULL;
	if (!bin) {
		return the_list;
	}
	the_list->free = free;
	rz_list_foreach (bin->methods_list, iter, fm_type) {
		paddr = RZ_NEW0(ut64);
		*paddr = fm_type->file_offset + bin->loadaddr;
		rz_list_append(the_list, paddr);
	}
	return the_list;
}

RZ_API ut16 rz_bin_java_calculate_field_access_value(const char *access_flags_str) {
	return calculate_access_value(access_flags_str, FIELD_ACCESS_FLAGS);
}

RZ_API ut16 rz_bin_java_calculate_class_access_value(const char *access_flags_str) {
	return calculate_access_value(access_flags_str, CLASS_ACCESS_FLAGS);
}

RZ_API ut16 rz_bin_java_calculate_method_access_value(const char *access_flags_str) {
	return calculate_access_value(access_flags_str, METHOD_ACCESS_FLAGS);
}

RZ_API RzList *retrieve_all_method_access_string_and_value(void) {
	return retrieve_all_access_string_and_value(METHOD_ACCESS_FLAGS);
}

RZ_API RzList *retrieve_all_field_access_string_and_value(void) {
	return retrieve_all_access_string_and_value(FIELD_ACCESS_FLAGS);
}

RZ_API RzList *retrieve_all_class_access_string_and_value(void) {
	return retrieve_all_access_string_and_value(CLASS_ACCESS_FLAGS);
}

RZ_API char *rz_bin_java_resolve_with_space(RzBinJavaObj *obj, int idx) {
	return rz_bin_java_resolve(obj, idx, 1);
}

RZ_API char *rz_bin_java_resolve_without_space(RzBinJavaObj *obj, int idx) {
	return rz_bin_java_resolve(obj, idx, 0);
}

RZ_API char *rz_bin_java_resolve_b64_encode(RzBinJavaObj *BIN_OBJ, ut16 idx) {
	RzBinJavaCPTypeObj *item = NULL, *item2 = NULL;
	char *class_str = NULL,
	     *name_str = NULL,
	     *desc_str = NULL,
	     *string_str = NULL,
	     *empty = "",
	     *cp_name = NULL,
	     *str = NULL, *out = NULL;
	int memory_alloc = 0;
	if (BIN_OBJ && BIN_OBJ->cp_count < 1) {
		// rz_bin_java_new_bin(BIN_OBJ);
		return NULL;
	}
	item = (RzBinJavaCPTypeObj *)rz_bin_java_get_item_from_bin_cp_list(BIN_OBJ, idx);
	if (item) {
		cp_name = ((RzBinJavaCPTypeMetas *)item->metas->type_info)->name;
		// eprintf("java_resolve Resolved: (%d) %s\n", idx, cp_name);
	} else {
		return NULL;
	}
	if (!strcmp(cp_name, "Class")) {
		item2 = (RzBinJavaCPTypeObj *)rz_bin_java_get_item_from_bin_cp_list(BIN_OBJ, idx);
		// str = rz_bin_java_get_name_from_bin_cp_list (BIN_OBJ, idx-1);
		class_str = rz_bin_java_get_item_name_from_bin_cp_list(BIN_OBJ, item);
		if (!class_str) {
			class_str = empty;
		}
		name_str = rz_bin_java_get_item_name_from_bin_cp_list(BIN_OBJ, item2);
		if (!name_str) {
			name_str = empty;
		}
		desc_str = rz_bin_java_get_item_desc_from_bin_cp_list(BIN_OBJ, item2);
		if (!desc_str) {
			desc_str = empty;
		}
		memory_alloc = strlen(class_str) + strlen(name_str) + strlen(desc_str) + 3;
		if (memory_alloc) {
			str = malloc(memory_alloc);
			if (str) {
				snprintf(str, memory_alloc, "%s%s", name_str, desc_str);
				out = rz_base64_encode_dyn((const ut8 *)str, strlen(str));
				free(str);
				str = out;
			}
		}
		if (class_str != empty) {
			free(class_str);
		}
		if (name_str != empty) {
			free(name_str);
		}
		if (desc_str != empty) {
			free(desc_str);
		}
	} else if (strcmp(cp_name, "MethodRef") == 0 ||
		strcmp(cp_name, "FieldRef") == 0 ||
		strcmp(cp_name, "InterfaceMethodRef") == 0) {
		/*
		*  The MethodRef, FieldRef, and InterfaceMethodRef structures
		*/
		class_str = rz_bin_java_get_name_from_bin_cp_list(BIN_OBJ, item->info.cp_method.class_idx);
		if (!class_str) {
			class_str = empty;
		}
		name_str = rz_bin_java_get_item_name_from_bin_cp_list(BIN_OBJ, item);
		if (!name_str) {
			name_str = empty;
		}
		desc_str = rz_bin_java_get_item_desc_from_bin_cp_list(BIN_OBJ, item);
		if (!desc_str) {
			desc_str = empty;
		}
		memory_alloc = strlen(class_str) + strlen(name_str) + strlen(desc_str) + 3;
		if (memory_alloc) {
			str = malloc(memory_alloc);
			if (str) {
				snprintf(str, memory_alloc, "%s/%s%s", class_str, name_str, desc_str);
				out = rz_base64_encode_dyn((const ut8 *)str, strlen(str));
				free(str);
				str = out;
			}
		}
		if (class_str != empty) {
			free(class_str);
		}
		if (name_str != empty) {
			free(name_str);
		}
		if (desc_str != empty) {
			free(desc_str);
		}
	} else if (strcmp(cp_name, "String") == 0) {
		ut32 length = rz_bin_java_get_utf8_len_from_bin_cp_list(BIN_OBJ, item->info.cp_string.string_idx);
		string_str = rz_bin_java_get_utf8_from_bin_cp_list(BIN_OBJ, item->info.cp_string.string_idx);
		str = NULL;
		// eprintf("java_resolve String got: (%d) %s\n", item->info.cp_string.string_idx, string_str);
		if (!string_str) {
			string_str = empty;
			length = strlen(empty);
		}
		memory_alloc = length + 3;
		if (memory_alloc) {
			str = malloc(memory_alloc);
			if (str) {
				snprintf(str, memory_alloc, "\"%s\"", string_str);
				out = rz_base64_encode_dyn((const ut8 *)str, strlen(str));
				free(str);
				str = out;
			}
		}
		// eprintf("java_resolve String return: %s\n", str);
		if (string_str != empty) {
			free(string_str);
		}
	} else if (strcmp(cp_name, "Utf8") == 0) {
		ut64 sz = item->info.cp_utf8.length ? item->info.cp_utf8.length + 10 : 10;
		str = malloc(sz);
		memset(str, 0, sz);
		if (sz > 10) {
			rz_base64_encode(str, item->info.cp_utf8.bytes, item->info.cp_utf8.length);
		}
	} else if (strcmp(cp_name, "Long") == 0) {
		str = malloc(34);
		if (str) {
			snprintf(str, 34, "0x%" PFMT64x, rz_read_at_be64(item->info.cp_long.bytes.raw, 0));
			out = rz_base64_encode_dyn((const ut8 *)str, strlen(str));
			free(str);
			str = out;
		}
	} else if (strcmp(cp_name, "Double") == 0) {
		str = malloc(1000);
		if (str) {
			snprintf(str, 1000, "%f", raw_to_double(item->info.cp_double.bytes.raw, 0));
			out = rz_base64_encode_dyn((const ut8 *)str, strlen(str));
			free(str);
			str = out;
		}
	} else if (strcmp(cp_name, "Integer") == 0) {
		str = calloc(34, 1);
		if (str) {
			snprintf(str, 34, "0x%08x", rz_read_at_be32(item->info.cp_integer.bytes.raw, 0));
			out = rz_base64_encode_dyn((const ut8 *)str, strlen(str));
			free(str);
			str = out;
		}
	} else if (strcmp(cp_name, "Float") == 0) {
		str = malloc(34);
		if (str) {
			snprintf(str, 34, "%f", raw_to_float(item->info.cp_float.bytes.raw, 0));
			out = rz_base64_encode_dyn((const ut8 *)str, strlen(str));
			free(str);
			str = out;
		}
	} else if (!strcmp(cp_name, "NameAndType")) {
		name_str = rz_bin_java_get_item_name_from_bin_cp_list(BIN_OBJ, item);
		if (!name_str) {
			name_str = empty;
		}
		desc_str = rz_bin_java_get_item_desc_from_bin_cp_list(BIN_OBJ, item);
		if (!desc_str) {
			desc_str = empty;
		}
		memory_alloc = strlen(name_str) + strlen(desc_str) + 3;
		if (memory_alloc) {
			str = malloc(memory_alloc);
			if (str) {
				snprintf(str, memory_alloc, "%s %s", name_str, desc_str);
				out = rz_base64_encode_dyn((const ut8 *)str, strlen(str));
				free(str);
				str = out;
			}
		}
		if (name_str != empty) {
			free(name_str);
		}
		if (desc_str != empty) {
			free(desc_str);
		}
	} else {
		str = rz_base64_encode_dyn((const ut8 *)"(null)", 6);
	}
	return str;
}

RZ_API ut64 rz_bin_java_resolve_cp_idx_address(RzBinJavaObj *BIN_OBJ, int idx) {
	RzBinJavaCPTypeObj *item = NULL;
	ut64 addr = -1;
	if (BIN_OBJ && BIN_OBJ->cp_count < 1) {
		return -1;
	}
	item = (RzBinJavaCPTypeObj *)rz_bin_java_get_item_from_bin_cp_list(BIN_OBJ, idx);
	if (item) {
		addr = item->file_offset + item->loadaddr;
	}
	return addr;
}

RZ_API char *rz_bin_java_resolve_cp_idx_to_string(RzBinJavaObj *BIN_OBJ, int idx) {
	RzBinJavaCPTypeObj *item = NULL;
	char *value = NULL;
	if (BIN_OBJ && BIN_OBJ->cp_count < 1) {
		return NULL;
	}
	item = (RzBinJavaCPTypeObj *)rz_bin_java_get_item_from_bin_cp_list(BIN_OBJ, idx);
	if (item) {
		value = ((RzBinJavaCPTypeMetas *)
				 item->metas->type_info)
				->allocs->stringify_obj(item);
	}
	return value;
}

RZ_API int rz_bin_java_summary_resolve_cp_idx_print(RzBinJavaObj *BIN_OBJ, int idx) {
	RzBinJavaCPTypeObj *item = NULL;
	if (BIN_OBJ && BIN_OBJ->cp_count < 1) {
		return false;
	}
	item = (RzBinJavaCPTypeObj *)rz_bin_java_get_item_from_bin_cp_list(BIN_OBJ, idx);
	if (item) {
		((RzBinJavaCPTypeMetas *)
				item->metas->type_info)
			->allocs->print_summary(item);
	} else {
		eprintf("Error: Invalid CP Object.\n");
	}
	return item ? true : false;
}

RZ_API _ConstJavaValue *rz_bin_java_resolve_to_const_value(RzBinJavaObj *bin_obj, int idx) {
	// TODO XXX FIXME add a size parameter to the str when it is passed in
	RzBinJavaCPTypeObj *item = NULL, *item2 = NULL;
	_ConstJavaValue *result = RZ_NEW0(_ConstJavaValue);
	if (!result) {
		return NULL;
	}
	char *class_str = NULL,
	     *name_str = NULL,
	     *desc_str = NULL,
	     *string_str = NULL,
	     *empty = "",
	     *cp_name = NULL;
	result->type = "unknown";
	if (bin_obj && bin_obj->cp_count < 1) {
		// rz_bin_java_new_bin(bin_obj);
		return result;
	}
	item = (RzBinJavaCPTypeObj *)rz_bin_java_get_item_from_bin_cp_list(bin_obj, idx);
	if (!item) {
		return result;
	}
	cp_name = ((RzBinJavaCPTypeMetas *)item->metas->type_info)->name;
	// eprintf("java_resolve Resolved: (%d) %s\n", idx, cp_name);
	if (strcmp(cp_name, "Class") == 0) {
		item2 = (RzBinJavaCPTypeObj *)rz_bin_java_get_item_from_bin_cp_list(bin_obj, idx);
		// str = rz_bin_java_get_name_from_bin_cp_list (bin_obj, idx-1);
		class_str = rz_bin_java_get_item_name_from_bin_cp_list(bin_obj, item);
		if (!class_str) {
			class_str = empty;
		}
		name_str = rz_bin_java_get_item_name_from_bin_cp_list(bin_obj, item2);
		if (!name_str) {
			name_str = empty;
		}
		desc_str = rz_bin_java_get_item_desc_from_bin_cp_list(bin_obj, item2);
		if (!desc_str) {
			desc_str = empty;
		}
		result->value._ref = RZ_NEW0(_JavaRef);
		result->type = "ref";
		result->value._ref->class_name = strdup(class_str);
		result->value._ref->name = strdup(name_str);
		result->value._ref->desc = strdup(desc_str);
		if (class_str != empty) {
			free(class_str);
		}
		if (name_str != empty) {
			free(name_str);
		}
		if (desc_str != empty) {
			free(desc_str);
		}
	} else if (strcmp(cp_name, "MethodRef") == 0 ||
		strcmp(cp_name, "FieldRef") == 0 ||
		strcmp(cp_name, "InterfaceMethodRef") == 0) {
		/*
		*  The MethodRef, FieldRef, and InterfaceMethodRef structures
		*/
		class_str = rz_bin_java_get_name_from_bin_cp_list(bin_obj, item->info.cp_method.class_idx);
		if (!class_str) {
			class_str = empty;
		}
		name_str = rz_bin_java_get_item_name_from_bin_cp_list(bin_obj, item);
		if (!name_str) {
			name_str = empty;
		}
		desc_str = rz_bin_java_get_item_desc_from_bin_cp_list(bin_obj, item);
		if (!desc_str) {
			desc_str = empty;
		}
		result->value._ref = RZ_NEW0(_JavaRef);
		result->type = "ref";
		result->value._ref->class_name = strdup(class_str);
		result->value._ref->name = strdup(name_str);
		result->value._ref->desc = strdup(desc_str);
		if (class_str != empty) {
			free(class_str);
		}
		if (name_str != empty) {
			free(name_str);
		}
		if (desc_str != empty) {
			free(desc_str);
		}
	} else if (strcmp(cp_name, "String") == 0) {
		ut32 length = rz_bin_java_get_utf8_len_from_bin_cp_list(bin_obj, item->info.cp_string.string_idx);
		string_str = rz_bin_java_get_utf8_from_bin_cp_list(bin_obj, item->info.cp_string.string_idx);
		// eprintf("java_resolve String got: (%d) %s\n", item->info.cp_string.string_idx, string_str);
		if (!string_str) {
			string_str = empty;
			length = strlen(empty);
		}
		result->type = "str";
		result->value._str = RZ_NEW0(_JavaStr);
		result->value._str->len = length;
		if (length > 0) {
			result->value._str->str = rz_str_ndup(string_str, length);
		} else {
			result->value._str->str = strdup("");
		}
		if (string_str != empty) {
			free(string_str);
		}
	} else if (strcmp(cp_name, "Utf8") == 0) {
		if (!item->info.cp_utf8.bytes) {
			free(result);
			return NULL;
		}
		result->type = "str";
		result->value._str = RZ_NEW0(_JavaStr);
		if (result->value._str) {
			result->value._str->str = malloc(item->info.cp_utf8.length);
			if (result->value._str->str) {
				result->value._str->len = item->info.cp_utf8.length;
				memcpy(result->value._str->str, item->info.cp_utf8.bytes, item->info.cp_utf8.length);
			} else {
				free(result->value._str);
				free(result);
				return NULL;
			}
		} else {
			free(result);
			return NULL;
		}
	} else if (strcmp(cp_name, "Long") == 0) {
		result->type = "long";
		result->value._long = rz_read_at_be64(item->info.cp_long.bytes.raw, 0);
	} else if (strcmp(cp_name, "Double") == 0) {
		result->type = "double";
		result->value._double = raw_to_double(item->info.cp_double.bytes.raw, 0);
	} else if (strcmp(cp_name, "Integer") == 0) {
		result->type = "int";
		result->value._int = rz_read_at_be32(item->info.cp_integer.bytes.raw, 0);
	} else if (strcmp(cp_name, "Float") == 0) {
		result->type = "float";
		result->value._float = raw_to_float(item->info.cp_float.bytes.raw, 0);
	} else if (strcmp(cp_name, "NameAndType") == 0) {
		result->value._ref = RZ_NEW0(_JavaRef);
		result->type = "ref";
		name_str = rz_bin_java_get_item_name_from_bin_cp_list(bin_obj, item);
		if (!name_str) {
			name_str = empty;
		}
		desc_str = rz_bin_java_get_item_desc_from_bin_cp_list(bin_obj, item);
		if (!desc_str) {
			desc_str = empty;
		}
		result->value._ref->class_name = strdup(empty);
		result->value._ref->name = strdup(name_str);
		result->value._ref->desc = strdup(desc_str);
		if (name_str != empty) {
			free(name_str);
		}
		if (desc_str != empty) {
			free(desc_str);
		}
		result->value._ref->is_method = rz_bin_java_does_cp_idx_ref_method(bin_obj, idx);
		result->value._ref->is_field = rz_bin_java_does_cp_idx_ref_field(bin_obj, idx);
	}
	return result;
}

RZ_API void rz_bin_java_free_const_value(_ConstJavaValue *cp_value) {
	char first_char = cp_value && cp_value->type ? *cp_value->type : 0,
	     second_char = cp_value && cp_value->type ? *(cp_value->type + 1) : 0;
	switch (first_char) {
	case 'r':
		if (cp_value && cp_value->value._ref) {
			free(cp_value->value._ref->class_name);
			free(cp_value->value._ref->name);
			free(cp_value->value._ref->desc);
		}
		break;
	case 's':
		if (second_char == 't' && cp_value->value._str) {
			free(cp_value->value._str->str);
		}
		break;
	}
	free(cp_value);
}

RZ_API char *rz_bin_java_get_field_name(RzBinJavaObj *bin_obj, ut32 idx) {
	char *name = NULL;
	if (idx < rz_list_length(bin_obj->fields_list)) {
		RzBinJavaField *fm_type = rz_list_get_n(bin_obj->fields_list, idx);
		name = strdup(fm_type->name);
	}
	return name;
}

RZ_API int rz_bin_java_summary_print_field_idx(RzBinJavaObj *bin_obj, ut32 idx) {
	int res = false;
	if (idx < rz_list_length(bin_obj->fields_list)) {
		RzBinJavaField *fm_type = rz_list_get_n(bin_obj->fields_list, idx);
		rz_bin_java_summary_print_field(fm_type);
		res = true;
	}
	return res;
}

RZ_API ut32 rz_bin_java_get_field_count(RzBinJavaObj *bin_obj) {
	return rz_list_length(bin_obj->fields_list);
}

RZ_API RzList *rz_bin_java_get_field_num_name(RzBinJavaObj *bin_obj) {
	ut32 i = 0;
	RzBinJavaField *fm_type;
	RzListIter *iter = NULL;
	RzList *res = rz_list_newf(free);
	rz_list_foreach (bin_obj->fields_list, iter, fm_type) {
		ut32 len = strlen(fm_type->name) + 30;
		char *str = malloc(len);
		if (!str) {
			rz_list_free(res);
			return NULL;
		}
		snprintf(str, len, "%d %s", i, fm_type->name);
		++i;
		rz_list_append(res, str);
	}
	return res;
}
RZ_API RzList *rz_bin_java_find_cp_const_by_val_utf8(RzBinJavaObj *bin_obj, const ut8 *bytes, ut32 len) {
	RzList *res = rz_list_newf(free);
	ut32 *v = NULL;
	RzListIter *iter;
	RzBinJavaCPTypeObj *cp_obj;
	// eprintf("In UTF-8 Looking for %s\n", bytes);
	rz_list_foreach (bin_obj->cp_list, iter, cp_obj) {
		if (cp_obj->tag == RZ_BIN_JAVA_CP_UTF8) {
			// eprintf("In UTF-8 Looking @ %s\n", cp_obj->info.cp_utf8.bytes);
			// eprintf("UTF-8 len = %d and memcmp = %d\n", cp_obj->info.cp_utf8.length, memcmp(bytes, cp_obj->info.cp_utf8.bytes, len));
			if (len == cp_obj->info.cp_utf8.length && !memcmp(bytes, cp_obj->info.cp_utf8.bytes, len)) {
				v = malloc(sizeof(ut32));
				if (!v) {
					rz_list_free(res);
					return NULL;
				}
				*v = cp_obj->metas->ord;
				// eprintf("Found a match adding idx: %d\n", *v);
				rz_list_append(res, v);
			}
		}
	}
	return res;
}
RZ_API RzList *rz_bin_java_find_cp_const_by_val_int(RzBinJavaObj *bin_obj, const ut8 *bytes, ut32 len) {
	RzList *res = rz_list_newf(free);
	ut32 *v = NULL;
	RzListIter *iter;
	RzBinJavaCPTypeObj *cp_obj;
	eprintf("Looking for 0x%08x\n", (ut32)rz_read_at_be32(bytes, 0));
	rz_list_foreach (bin_obj->cp_list, iter, cp_obj) {
		if (cp_obj->tag == RZ_BIN_JAVA_CP_INTEGER) {
			if (len == 4 && rz_read_at_be32(bytes, 0) == rz_read_at_be32(cp_obj->info.cp_integer.bytes.raw, 0)) {
				v = malloc(sizeof(ut32));
				if (!v) {
					rz_list_free(res);
					return NULL;
				}
				*v = cp_obj->idx;
				rz_list_append(res, v);
			}
		}
	}
	return res;
}

RZ_API char rz_bin_java_resolve_cp_idx_tag(RzBinJavaObj *BIN_OBJ, int idx) {
	RzBinJavaCPTypeObj *item = NULL;
	if (BIN_OBJ && BIN_OBJ->cp_count < 1) {
		// rz_bin_java_new_bin(BIN_OBJ);
		return RZ_BIN_JAVA_CP_UNKNOWN;
	}
	item = (RzBinJavaCPTypeObj *)rz_bin_java_get_item_from_bin_cp_list(BIN_OBJ, idx);
	if (item) {
		return item->tag;
	}
	return RZ_BIN_JAVA_CP_UNKNOWN;
}

RZ_API int rz_bin_java_integer_cp_set(RzBinJavaObj *bin, ut16 idx, ut32 val) {
	RzBinJavaCPTypeObj *cp_obj = rz_bin_java_get_item_from_bin_cp_list(bin, idx);
	if (!cp_obj) {
		return false;
	}
	ut8 bytes[4] = {
		0
	};
	if (cp_obj->tag != RZ_BIN_JAVA_CP_INTEGER && cp_obj->tag != RZ_BIN_JAVA_CP_FLOAT) {
		eprintf("Not supporting the overwrite of CP Objects with one of a different size.\n");
		return false;
	}
	rz_bin_java_check_reset_cp_obj(cp_obj, RZ_BIN_JAVA_CP_INTEGER);
	cp_obj->tag = RZ_BIN_JAVA_CP_INTEGER;
	memcpy(bytes, (const char *)&val, 4);
	val = rz_read_at_be32(bytes, 0);
	memcpy(&cp_obj->info.cp_integer.bytes.raw, (const char *)&val, 4);
	return true;
}

RZ_API int rz_bin_java_float_cp_set(RzBinJavaObj *bin, ut16 idx, float val) {
	RzBinJavaCPTypeObj *cp_obj = rz_bin_java_get_item_from_bin_cp_list(bin, idx);
	if (!cp_obj) {
		return false;
	}
	ut8 bytes[4] = {
		0
	};
	if (cp_obj->tag != RZ_BIN_JAVA_CP_INTEGER && cp_obj->tag != RZ_BIN_JAVA_CP_FLOAT) {
		eprintf("Not supporting the overwrite of CP Objects with one of a different size.\n");
		return false;
	}
	rz_bin_java_check_reset_cp_obj(cp_obj, RZ_BIN_JAVA_CP_FLOAT);
	cp_obj->tag = RZ_BIN_JAVA_CP_FLOAT;
	memcpy(bytes, (const char *)&val, 4);
	float *foo = (float *)bytes;
	val = *foo; //(float)rz_read_at_be32 (bytes, 0);
	memcpy(&cp_obj->info.cp_float.bytes.raw, (const char *)&val, 4);
	return true;
}

RZ_API int rz_bin_java_long_cp_set(RzBinJavaObj *bin, ut16 idx, ut64 val) {
	RzBinJavaCPTypeObj *cp_obj = rz_bin_java_get_item_from_bin_cp_list(bin, idx);
	if (!cp_obj) {
		return false;
	}
	ut8 bytes[8] = {
		0
	};
	if (cp_obj->tag != RZ_BIN_JAVA_CP_LONG && cp_obj->tag != RZ_BIN_JAVA_CP_DOUBLE) {
		eprintf("Not supporting the overwrite of CP Objects with one of a different size.\n");
		return false;
	}
	rz_bin_java_check_reset_cp_obj(cp_obj, RZ_BIN_JAVA_CP_LONG);
	cp_obj->tag = RZ_BIN_JAVA_CP_LONG;
	memcpy(bytes, (const char *)&val, 8);
	val = rz_read_at_be64(bytes, 0);
	memcpy(&cp_obj->info.cp_long.bytes.raw, (const char *)&val, 8);
	return true;
}

RZ_API int rz_bin_java_double_cp_set(RzBinJavaObj *bin, ut16 idx, ut32 val) {
	RzBinJavaCPTypeObj *cp_obj = rz_bin_java_get_item_from_bin_cp_list(bin, idx);
	if (!cp_obj) {
		return false;
	}
	ut8 bytes[8] = {
		0
	};
	if (cp_obj->tag != RZ_BIN_JAVA_CP_LONG && cp_obj->tag != RZ_BIN_JAVA_CP_DOUBLE) {
		eprintf("Not supporting the overwrite of CP Objects with one of a different size.\n");
		return false;
	}
	rz_bin_java_check_reset_cp_obj(cp_obj, RZ_BIN_JAVA_CP_DOUBLE);
	cp_obj->tag = RZ_BIN_JAVA_CP_DOUBLE;
	ut64 val64 = val;
	memcpy(bytes, (const char *)&val64, 8);
	val64 = rz_read_at_be64(bytes, 0);
	memcpy(&cp_obj->info.cp_double.bytes.raw, (const char *)&val64, 8);
	return true;
}

RZ_API int rz_bin_java_utf8_cp_set(RzBinJavaObj *bin, ut16 idx, const ut8 *buffer, ut32 len) {
	RzBinJavaCPTypeObj *cp_obj = rz_bin_java_get_item_from_bin_cp_list(bin, idx);
	if (!cp_obj) {
		return false;
	}
	eprintf("Writing %d byte(s) (%s)\n", len, buffer);
	// rz_bin_java_check_reset_cp_obj(cp_obj, RZ_BIN_JAVA_CP_INTEGER);
	if (cp_obj->tag != RZ_BIN_JAVA_CP_UTF8) {
		eprintf("Not supporting the overwrite of CP Objects with one of a different size.\n");
		return false;
	}
	if (cp_obj->info.cp_utf8.length != len) {
		eprintf("Not supporting the resize, rewriting utf8 string up to %d byte(s).\n", cp_obj->info.cp_utf8.length);
		if (cp_obj->info.cp_utf8.length > len) {
			eprintf("Remaining %d byte(s) will be filled with \\x00.\n", cp_obj->info.cp_utf8.length - len);
		}
	}
	memcpy(cp_obj->info.cp_utf8.bytes, buffer, cp_obj->info.cp_utf8.length);
	if (cp_obj->info.cp_utf8.length > len) {
		memset(cp_obj->info.cp_utf8.bytes + len, 0, cp_obj->info.cp_utf8.length - len);
	}
	return true;
}

RZ_API ut8 *rz_bin_java_cp_get_bytes(ut8 tag, ut32 *out_sz, const ut8 *buf, const ut64 len) {
	if (!out_sz) {
		return NULL;
	}
	if (out_sz) {
		*out_sz = 0;
	}
	switch (tag) {
	case RZ_BIN_JAVA_CP_INTEGER:
	case RZ_BIN_JAVA_CP_FLOAT:
		return rz_bin_java_cp_get_4bytes(tag, out_sz, buf, len);
	case RZ_BIN_JAVA_CP_LONG:
	case RZ_BIN_JAVA_CP_DOUBLE:
		return rz_bin_java_cp_get_8bytes(tag, out_sz, buf, len);
	case RZ_BIN_JAVA_CP_UTF8:
		return rz_bin_java_cp_get_utf8(tag, out_sz, buf, len);
	}
	return NULL;
}

RZ_API ut32 rz_bin_java_cp_get_size(RzBinJavaObj *bin, ut16 idx) {
	RzBinJavaCPTypeObj *cp_obj = rz_bin_java_get_item_from_bin_cp_list(bin, idx);
	switch (cp_obj->tag) {
	case RZ_BIN_JAVA_CP_INTEGER:
	case RZ_BIN_JAVA_CP_FLOAT:
		return 1 + 4;
	case RZ_BIN_JAVA_CP_LONG:
	case RZ_BIN_JAVA_CP_DOUBLE:
		return 1 + 8;
	case RZ_BIN_JAVA_CP_UTF8:
		return 1 + 2 + cp_obj->info.cp_utf8.length;
	}
	return 0;
}

RZ_API ut64 rz_bin_java_get_method_start(RzBinJavaObj *bin, RzBinJavaField *fm_type) {
	return rz_bin_java_get_method_code_offset(fm_type) + bin->loadaddr;
}

RZ_API ut64 rz_bin_java_get_method_end(RzBinJavaObj *bin, RzBinJavaField *fm_type) {
	return rz_bin_java_get_method_code_offset(fm_type) + bin->loadaddr +
		+rz_bin_java_get_method_code_size(fm_type);
}

RZ_API ut8 *rz_bin_java_cp_append_method_ref(RzBinJavaObj *bin, ut32 *out_sz, ut16 cn_idx, ut16 fn_idx, ut16 ft_idx) {
	return rz_bin_java_cp_get_fref_bytes(bin, out_sz, RZ_BIN_JAVA_CP_METHODREF, cn_idx, fn_idx, ft_idx);
}

RZ_API ut8 *rz_bin_java_cp_append_field_ref(RzBinJavaObj *bin, ut32 *out_sz, ut16 cn_idx, ut16 fn_idx, ut16 ft_idx) {
	return rz_bin_java_cp_get_fref_bytes(bin, out_sz, RZ_BIN_JAVA_CP_FIELDREF, cn_idx, fn_idx, ft_idx);
}

RZ_API char *rz_bin_java_unmangle_without_flags(const char *name, const char *descriptor) {
	return rz_bin_java_unmangle(NULL, name, descriptor);
}

RZ_API void rz_bin_java_free_stack_frame_default(void *s) {
	RzBinJavaStackMapFrame *stack_frame = s;
	if (stack_frame) {
		free(stack_frame->metas);
		free(stack_frame);
	}
}
RZ_API void rz_bin_java_free_stack_frame_do_nothing(void /*RzBinJavaStackMapFrame*/ *stack_frame) {}
RZ_API void rz_bin_java_new_stack_frame_do_nothing(RzBinJavaObj *bin, RzBinJavaStackMapFrame *stack_frame, ut64 offset) {}
RZ_API RzBinJavaCPTypeMetas *rz_bin_java_get_cp_meta_from_tag(ut8 tag) {
	ut16 i = 0;
	// set default to unknown.
	RzBinJavaCPTypeMetas *res = &RZ_BIN_JAVA_CP_METAS[2];
	for (i = 0; i < RZ_BIN_JAVA_CP_METAS_SZ; i++) {
		if (tag == RZ_BIN_JAVA_CP_METAS[i].tag) {
			res = &RZ_BIN_JAVA_CP_METAS[i];
			break;
		}
	}
	return res;
}

RZ_API ut8 *rz_bin_java_cp_append_ref_cname_fname_ftype(RzBinJavaObj *bin, ut32 *out_sz, ut8 tag, const char *cname, const ut32 c_len, const char *fname, const ut32 f_len, const char *tname, const ut32 t_len) {
	ut32 cn_len = 0, fn_len = 0, ft_len = 0, total_len;
	ut16 cn_idx = 0, fn_idx = 0, ft_idx = 0;
	ut8 *bytes = NULL, *cn_bytes = NULL, *fn_bytes = NULL, *ft_bytes = NULL, *cref_bytes = NULL, *fref_bytes = NULL, *fnt_bytes = NULL;
	*out_sz = 0;
	cn_bytes = rz_bin_java_cp_get_utf8(RZ_BIN_JAVA_CP_UTF8, &cn_len, (const ut8 *)cname, c_len);
	cn_idx = bin->cp_idx + 1;
	if (cn_bytes) {
		fn_bytes = rz_bin_java_cp_get_utf8(RZ_BIN_JAVA_CP_UTF8, &fn_len, (const ut8 *)fname, f_len);
		fn_idx = bin->cp_idx + 2;
	}
	if (fn_bytes) {
		ft_bytes = rz_bin_java_cp_get_utf8(RZ_BIN_JAVA_CP_UTF8, &ft_len, (const ut8 *)tname, t_len);
		ft_idx = bin->cp_idx + 3;
	}
	if (cn_bytes && fn_bytes && ft_bytes) {
		ut32 cref_len = 0, fnt_len = 0, fref_len = 0;
		ut32 cref_idx = 0, fnt_idx = 0;
		cref_bytes = rz_bin_java_cp_get_classref(bin, &cref_len, NULL, 0, cn_idx);
		cref_idx = bin->cp_idx + 3;
		fnt_bytes = rz_bin_java_cp_get_name_type(bin, &fnt_len, fn_idx, ft_idx);
		fnt_idx = bin->cp_idx + 4;
		fref_bytes = rz_bin_java_cp_get_2_ut16(bin, &fref_len, tag, cref_idx, fnt_idx);
		if (cref_bytes && fref_bytes && fnt_bytes) {
			total_len = cn_len + fn_len + ft_len + cref_len + fnt_len + fref_len + 2;
			if (total_len < cn_len) {
				goto beach;
			}
			bytes = calloc(1, total_len);
			// class name bytes
			if (*out_sz + cn_len >= total_len) {
				goto beach;
			}
			memcpy(bytes, cn_bytes + *out_sz, cn_len);
			*out_sz += cn_len;
			// field name bytes
			if (*out_sz + fn_len >= total_len) {
				goto beach;
			}
			memcpy(bytes, fn_bytes + *out_sz, fn_len);
			*out_sz += fn_len;
			// field type bytes
			if (*out_sz + ft_len >= total_len) {
				goto beach;
			}
			memcpy(bytes, ft_bytes + *out_sz, ft_len);
			*out_sz += ft_len;
			// class ref bytes
			if (*out_sz + cref_len >= total_len) {
				goto beach;
			}
			memcpy(bytes, cref_bytes + *out_sz, cref_len);
			*out_sz += fn_len;
			// field name and type bytes
			if (*out_sz + fnt_len >= total_len) {
				goto beach;
			}
			memcpy(bytes, fnt_bytes + *out_sz, fnt_len);
			*out_sz += fnt_len;
			// field ref bytes
			if (*out_sz + fref_len >= total_len) {
				goto beach;
			}
			memcpy(bytes, fref_bytes + *out_sz, fref_len);
			*out_sz += fref_len;
		}
	}
beach:
	free(cn_bytes);
	free(ft_bytes);
	free(fn_bytes);
	free(fnt_bytes);
	free(fref_bytes);
	free(cref_bytes);
	return bytes;
}
RZ_API ut8 *rz_bin_java_cp_get_method_ref(RzBinJavaObj *bin, ut32 *out_sz, ut16 class_idx, ut16 name_and_type_idx) {
	return rz_bin_java_cp_get_fm_ref(bin, out_sz, RZ_BIN_JAVA_CP_METHODREF, class_idx, name_and_type_idx);
}
RZ_API ut8 *rz_bin_java_cp_get_field_ref(RzBinJavaObj *bin, ut32 *out_sz, ut16 class_idx, ut16 name_and_type_idx) {
	return rz_bin_java_cp_get_fm_ref(bin, out_sz, RZ_BIN_JAVA_CP_FIELDREF, class_idx, name_and_type_idx);
}

RZ_API void deinit_java_type_null(void) {
	free(RZ_BIN_JAVA_NULL_TYPE.metas);
}

RZ_API RzBinJavaCPTypeObj *rz_bin_java_get_item_from_cp(RzBinJavaObj *bin, int i) {
	if (i < 1 || i > bin->cf.cp_count) {
		return &RZ_BIN_JAVA_NULL_TYPE;
	}
	RzBinJavaCPTypeObj *obj = (RzBinJavaCPTypeObj *)rz_list_get_n(bin->cp_list, i);
	return obj ? obj : &RZ_BIN_JAVA_NULL_TYPE;
}

RZ_API void copy_type_info_to_stack_frame_list(RzList *type_list, RzList *sf_list) {
	RzListIter *iter, *iter_tmp;
	RzBinJavaVerificationObj *ver_obj, *new_ver_obj;
	if (!type_list || !sf_list) {
		return;
	}
	rz_list_foreach_safe (type_list, iter, iter_tmp, ver_obj) {
		new_ver_obj = (RzBinJavaVerificationObj *)malloc(sizeof(RzBinJavaVerificationObj));
		// FIXME: how to handle failed memory allocation?
		if (new_ver_obj && ver_obj) {
			memcpy(new_ver_obj, ver_obj, sizeof(RzBinJavaVerificationObj));
			if (!rz_list_append(sf_list, (void *)new_ver_obj)) {
				RZ_FREE(new_ver_obj);
			}
		} else {
			RZ_FREE(new_ver_obj);
		}
	}
}

RZ_API void copy_type_info_to_stack_frame_list_up_to_idx(RzList *type_list, RzList *sf_list, ut64 idx) {
	RzListIter *iter, *iter_tmp;
	RzBinJavaVerificationObj *ver_obj, *new_ver_obj;
	ut32 pos = 0;
	if (!type_list || !sf_list) {
		return;
	}
	rz_list_foreach_safe (type_list, iter, iter_tmp, ver_obj) {
		new_ver_obj = (RzBinJavaVerificationObj *)malloc(sizeof(RzBinJavaVerificationObj));
		// FIXME: how to handle failed memory allocation?
		if (new_ver_obj && ver_obj) {
			memcpy(new_ver_obj, ver_obj, sizeof(RzBinJavaVerificationObj));
			if (!rz_list_append(sf_list, (void *)new_ver_obj)) {
				RZ_FREE(new_ver_obj);
			}
		} else {
			RZ_FREE(new_ver_obj);
		}
		pos++;
		if (pos == idx) {
			break;
		}
	}
}

RZ_API ut8 *rz_bin_java_cp_get_idx_bytes(RzBinJavaObj *bin, ut16 idx, ut32 *out_sz) {
	RzBinJavaCPTypeObj *cp_obj = rz_bin_java_get_item_from_bin_cp_list(bin, idx);
	if (!cp_obj || !out_sz) {
		return NULL;
	}
	if (out_sz) {
		*out_sz = 0;
	}
	switch (cp_obj->tag) {
	case RZ_BIN_JAVA_CP_INTEGER:
	case RZ_BIN_JAVA_CP_FLOAT:
		return rz_bin_java_cp_get_4bytes(cp_obj->tag, out_sz, cp_obj->info.cp_integer.bytes.raw, 5);
	case RZ_BIN_JAVA_CP_LONG:
	case RZ_BIN_JAVA_CP_DOUBLE:
		return rz_bin_java_cp_get_4bytes(cp_obj->tag, out_sz, cp_obj->info.cp_long.bytes.raw, 9);
	case RZ_BIN_JAVA_CP_UTF8:
		// eprintf ("Getting idx: %d = %p (3+0x%"PFMT64x")\n", idx, cp_obj, cp_obj->info.cp_utf8.length);
		if (cp_obj->info.cp_utf8.length > 0) {
			return rz_bin_java_cp_get_utf8(cp_obj->tag, out_sz,
				cp_obj->info.cp_utf8.bytes, cp_obj->info.cp_utf8.length);
		}
	}
	return NULL;
}

RZ_API int rz_bin_java_valid_class(const ut8 *buf, ut64 buf_sz) {
	RzBinJavaObj *bin = RZ_NEW0(RzBinJavaObj), *cur_bin = RZ_BIN_JAVA_GLOBAL_BIN;
	if (!bin) {
		return false;
	}
	int res = rz_bin_java_load_bin(bin, buf, buf_sz);
	if (bin->calc_size == buf_sz) {
		res = true;
	}
	rz_bin_java_free(bin);
	RZ_BIN_JAVA_GLOBAL_BIN = cur_bin;
	return res;
}

RZ_API ut64 rz_bin_java_calc_class_size(ut8 *bytes, ut64 size) {
	RzBinJavaObj *bin = RZ_NEW0(RzBinJavaObj);
	if (!bin) {
		return false;
	}
	RzBinJavaObj *cur_bin = RZ_BIN_JAVA_GLOBAL_BIN;
	ut64 bin_size = UT64_MAX;
	if (bin) {
		if (rz_bin_java_load_bin(bin, bytes, size)) {
			bin_size = bin->calc_size;
		}
		rz_bin_java_free(bin);
		RZ_BIN_JAVA_GLOBAL_BIN = cur_bin;
	}
	return bin_size;
}

RZ_API int rz_bin_java_get_cp_idx_with_name(RzBinJavaObj *bin_obj, const char *name, ut32 len) {
	RzListIter *iter;
	RzBinJavaCPTypeObj *obj;
	rz_list_foreach (bin_obj->cp_list, iter, obj) {
		if (obj->tag == RZ_BIN_JAVA_CP_UTF8) {
			if (!strncmp(name, (const char *)obj->info.cp_utf8.bytes, len)) {
				return obj->metas->ord;
			}
		}
	}
	return 0;
}
