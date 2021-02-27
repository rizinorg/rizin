// SPDX-License-Identifier: LGPL-3.0-only
#include "print.h"
#include "internals.h"

extern char *sanitize_string(const char *bytes, ut32 len);

static double custom_pow(ut64 base, int exp) {
	ut8 flag = 0;
	ut64 res = 1;
	if (exp < 0) {
		flag = 1;
		exp *= -1;
	}
	while (exp) {
		if (exp & 1) {
			res *= base;
		}
		exp >>= 1;
		base *= base;
		// eprintf("Result: %" PFMT64d ", base: %" PFMT64d ", exp: %d\n", res, base, exp);
	}
	if (flag == 0) {
		return 1.0 * res;
	}
	return (1.0 / res);
}

double raw_to_double(const ut8 *raw, ut64 offset) {
	ut64 bits = rz_read_at_be64(raw, offset);
	int s = ((bits >> 63) == 0) ? 1 : -1;
	int e = (int)((bits >> 52) & 0x7ffL);
	long m = (e == 0) ? (bits & 0xfffffffffffffLL) << 1 : (bits & 0xfffffffffffffLL) | 0x10000000000000LL;
	double res = 0.0;
	// eprintf("Convert Long to Double: %08" PFMT64x "\n", bits);
	if (bits == 0x7ff0000000000000LL) {
		return INFINITY;
	}
	if (bits == 0xfff0000000000000LL) {
		return -INFINITY;
	}
	if (0x7ff0000000000001LL <= bits && bits <= 0x7fffffffffffffffLL) {
		return NAN;
	}
	if (0xfff0000000000001LL <= bits && bits <= 0xffffffffffffffffLL) {
		return NAN;
	}
	res = s * m * custom_pow(2, e - 1075); // XXXX TODO Get double to work correctly here
	// eprintf("	High-bytes = %02x %02x %02x %02x\n", raw[0], raw[1], raw[2], raw[3]);
	// eprintf("	Low-bytes = %02x %02x %02x %02x\n", raw[4], raw[5], raw[6], raw[7]);
	// eprintf("Convert Long to Double s: %d, m: 0x%08lx, e: 0x%08x, res: %f\n", s, m, e, res);
	return res;
}

RZ_API void rz_bin_java_summary_cp_print_utf8(RzBinJavaCPTypeObj *obj) {
	if (obj == NULL) {
		printf("Attempting to print an invalid RzBinJavaCPTypeObj*  Utf8.\n");
		return;
	}
	char *str = sanitize_string((const char *)obj->info.cp_utf8.bytes, obj->info.cp_utf8.length);
	printf("UTF8 ConstantPool Type (%d) ", obj->metas->ord);
	printf("	Offset: 0x%08" PFMT64x "", obj->file_offset);
	printf("	length = %d\n", obj->info.cp_utf8.length);
	printf("	utf8 = %s\n", str);
	free(str);
}

RZ_API void rz_bin_java_summary_print_attr(RzBinJavaAttrInfo *attr) {
	if (attr == NULL) {
		printf("Attempting to print an invalid RzBinJavaAttrInfo *.\n");
		return;
	}
	((RzBinJavaAttrMetas *)attr->metas->type_info)->allocs->print_summary(attr);
}

RZ_API void rz_bin_java_summary_print_source_debug_attr(RzBinJavaAttrInfo *attr) {
	ut32 i = 0;
	if (attr == NULL) {
		printf("Attempting to print an invalid RzBinJavaSourceDebugExtensionAttr *.\n");
		return;
	}
	printf("Source Debug Extension Attribute Information:\n");
	printf("  Attribute Offset: 0x%08" PFMT64x "\n", attr->file_offset);
	printf("  Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf("  Extension Length: %d\n", attr->length);
	printf("  Source Debug Extension value: \n");
	for (i = 0; i < attr->length; i++) {
		printf("%c", attr->info.debug_extensions.debug_extension[i]);
	}
	printf("\n  Source Debug Extension End\n");
}

RZ_API void rz_bin_java_summary_print_unknown_attr(RzBinJavaAttrInfo *attr) {
	if (attr == NULL) {
		printf("Attempting to print an invalid RzBinJavaAttrInfo *Unknown.\n");
		return;
	}
	printf("Unknown Attribute Information:\n");
	printf("  Attribute Offset: 0x%08" PFMT64x "\n", attr->file_offset);
	printf("  Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf("  Attribute Length: %d\n", attr->length);
}

RZ_API void rz_bin_java_summary_print_code_exceptions_attr(RzBinJavaExceptionEntry *exc_entry) {
	if (exc_entry == NULL) {
		printf("Attempting to print an invalid RzBinJavaExceptionEntry *.\n");
		return;
	}
	printf("  Exception Table Entry Information\n");
	printf("    offset:	0x%08" PFMT64x "\n", exc_entry->file_offset);
	printf("    catch_type: %d\n", exc_entry->catch_type);
	printf("    start_pc:   0x%04x\n", exc_entry->start_pc);
	printf("    end_pc:	0x%04x\n", exc_entry->end_pc);
	printf("    handler_pc: 0x%04x\n", exc_entry->handler_pc);
}
// End free Constant Pool types
RZ_API void rz_bin_java_summary_print_code_attr(RzBinJavaAttrInfo *attr) {
	RzListIter *iter = NULL, *iter_tmp = NULL;
	RzBinJavaExceptionEntry *exc_entry = NULL;
	RzBinJavaAttrInfo *_attr = NULL;
	if (!attr) {
		printf("Attempting to print an invalid RzBinJavaAttrInfo *Code.\n");
		return;
	}
	printf("Code Attribute Information:\n");
	printf("  Attribute Offset: 0x%08" PFMT64x "\n", attr->file_offset);
	printf("  Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf("  Attribute Length: %d, Attribute Count: %d\n", attr->length, attr->info.code_attr.attributes_count);
	printf("    Max Stack: %d\n", attr->info.code_attr.max_stack);
	printf("    Max Locals: %d\n", attr->info.code_attr.max_locals);
	printf("    Code Length: %d\n", attr->info.code_attr.code_length);
	printf("    Code At Offset: 0x%08" PFMT64x "\n", (ut64)attr->info.code_attr.code_offset);
	printf("Code Attribute Exception Table Information:\n");
	printf("  Exception Table Length: %d\n", attr->info.code_attr.exception_table_length);
	if (attr->info.code_attr.exception_table) {
		// Delete the attr entries
		rz_list_foreach_safe (attr->info.code_attr.exception_table, iter, iter_tmp, exc_entry) {
			rz_bin_java_summary_print_code_exceptions_attr(exc_entry);
		}
	}
	printf("  Implicit Method Stack Frame:\n");
	rz_bin_java_summary_print_stack_map_frame(attr->info.code_attr.implicit_frame);
	printf("Code Attribute Attributes Information:\n");
	if (attr->info.code_attr.attributes && attr->info.code_attr.attributes_count > 0) {
		printf("  Code Attribute Attributes Count: %d\n", attr->info.code_attr.attributes_count);
		rz_list_foreach_safe (attr->info.code_attr.attributes, iter, iter_tmp, _attr) {
			rz_bin_java_summary_print_attr(_attr);
		}
	}
}

RZ_API void rz_bin_java_summary_print_constant_value_attr(RzBinJavaAttrInfo *attr) {
	if (!attr) {
		printf("Attempting to print an invalid RzBinJavaAttrInfo *ConstantValue.\n");
		return;
	}
	printf("Constant Value Attribute Information:\n");
	printf("  Attribute Offset: 0x%08" PFMT64x "\n", attr->file_offset);
	printf("  Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf("  Attribute Length: %d\n", attr->length);
	printf("  ConstantValue Index: %d\n", attr->info.constant_value_attr.constantvalue_idx);
}

RZ_API void rz_bin_java_summary_print_deprecated_attr(RzBinJavaAttrInfo *attr) {
	if (!attr) {
		printf("Attempting to print an invalid RzBinJavaAttrInfo *Deperecated.\n");
		return;
	}
	printf("Deperecated Attribute Information:\n");
	printf("  Attribute Offset: 0x%08" PFMT64x "\n", attr->file_offset);
	printf("  Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf("  Attribute Length: %d\n", attr->length);
}

RZ_API void rz_bin_java_summary_print_enclosing_methods_attr(RzBinJavaAttrInfo *attr) {
	if (!attr) {
		printf("Attempting to print an invalid RzBinJavaAttrInfo *Deperecated.\n");
		return;
	}
	printf("Enclosing Method Attribute Information:\n");
	printf("  Attribute Offset: 0x%08" PFMT64x "\n", attr->file_offset);
	printf("  Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf("  Attribute Length: %d\n", attr->length);
	printf("  Class Info Index : 0x%02x\n", attr->info.enclosing_method_attr.class_idx);
	printf("  Method Name and Type Index : 0x%02x\n", attr->info.enclosing_method_attr.method_idx);
	printf("  Class Name : %s\n", attr->info.enclosing_method_attr.class_name);
	printf("  Method Name and Desc : %s %s\n", attr->info.enclosing_method_attr.method_name, attr->info.enclosing_method_attr.method_descriptor);
}

RZ_API void rz_bin_java_summary_print_exceptions_attr(RzBinJavaAttrInfo *attr) {
	ut32 i = 0;
	if (!attr) {
		printf("Attempting to print an invalid RzBinJavaAttrInfo *Exceptions.\n");
		return;
	}
	printf("Exceptions Attribute Information:\n");
	printf("  Attribute Offset: 0x%08" PFMT64x "\n", attr->file_offset);
	printf("  Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf("  Attribute Length: %d\n", attr->length);
	for (i = 0; i < attr->info.exceptions_attr.number_of_exceptions; i++) {
		printf("  Exceptions Attribute Index[%d]: %d\n", i, attr->info.exceptions_attr.exception_idx_table[i]);
	}
}

RZ_API void rz_bin_java_summary_print_classes_attr(RzBinJavaClassesAttribute *icattr) {
	if (!icattr) {
		printf("Attempting to print an invalid RzBinJavaClassesAttribute* (InnerClasses element).\n");
		return;
	}
	printf("   Inner Classes Class Attribute Offset: 0x%08" PFMT64x "\n", icattr->file_offset);
	printf("   Inner Classes Class Attribute Class Name (%d): %s\n", icattr->inner_name_idx, icattr->name);
	printf("   Inner Classes Class Attribute Class inner_class_info_idx: %d\n", icattr->inner_class_info_idx);
	printf("   Inner Classes Class Attribute Class inner_class_access_flags: 0x%02x %s\n", icattr->inner_class_access_flags, icattr->flags_str);
	printf("   Inner Classes Class Attribute Class outer_class_info_idx: %d\n", icattr->outer_class_info_idx);
	printf("   Inner Classes Class Field Information:\n");
	rz_bin_java_summary_print_field(icattr->clint_field);
	printf("   Inner Classes Class Field Information:\n");
	rz_bin_java_summary_print_field(icattr->clint_field);
	printf("   Inner Classes Class Attr Info Information:\n");
	rz_bin_java_summary_print_attr(icattr->clint_attr);
}

RZ_API void rz_bin_java_summary_print_inner_classes_attr(RzBinJavaAttrInfo *attr) {
	RzBinJavaClassesAttribute *icattr;
	RzListIter *iter, *iter_tmp;
	if (!attr) {
		printf("Attempting to print an invalid RzBinJavaAttrInfo *InnerClasses.\n");
		return;
	}
	printf("Inner Classes Attribute Information:\n");
	printf("  Attribute Offset: 0x%08" PFMT64x "\n", attr->file_offset);
	printf("  Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf("  Attribute Length: %d\n", attr->length);
	rz_list_foreach_safe (attr->info.inner_classes_attr.classes, iter, iter_tmp, icattr) {
		rz_bin_java_summary_print_classes_attr(icattr);
	}
}

RZ_API void rz_bin_java_summary_print_line_number_attr(RzBinJavaLineNumberAttribute *lnattr) {
	if (!lnattr) {
		printf("Attempting to print an invalid RzBinJavaLineNumberAttribute *.\n");
		return;
	}
	printf("  Line Number Attribute Offset: 0x%08" PFMT64x "\n", lnattr->file_offset);
	printf("  Line Number Attribute StartPC: %d\n", lnattr->start_pc);
	printf("  Line Number Attribute LineNumber: %d\n", lnattr->line_number);
}

RZ_API void rz_bin_java_summary_print_line_number_table_attr(RzBinJavaAttrInfo *attr) {
	RzBinJavaLineNumberAttribute *lnattr;
	RzListIter *iter, *iter_tmp;
	if (!attr) {
		printf("Attempting to print an invalid RzBinJavaAttrInfo *LineNumberTable.\n");
		return;
	}
	printf("Line Number Table Attribute Information:\n");
	printf("  Attribute Offset: 0x%08" PFMT64x "\n", attr->file_offset);
	printf("  Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf("  Attribute Length: %d\n", attr->length);
	rz_list_foreach_safe (attr->info.line_number_table_attr.line_number_table, iter, iter_tmp, lnattr) {
		rz_bin_java_summary_print_line_number_attr(lnattr);
	}
}

RZ_API void rz_bin_java_summary_print_local_variable_attr(RzBinJavaLocalVariableAttribute *lvattr) {
	if (!lvattr) {
		printf("Attempting to print an invalid RzBinJavaLocalVariableAttribute *.\n");
		return;
	}
	printf("  Local Variable Attribute offset: 0x%08" PFMT64x "\n", lvattr->file_offset);
	printf("  Local Variable Attribute start_pc: %d\n", lvattr->start_pc);
	printf("  Local Variable Attribute Length: %d\n", lvattr->length);
	printf("  Local Variable Attribute name_idx: %d\n", lvattr->name_idx);
	printf("  Local Variable Attribute name: %s\n", lvattr->name);
	printf("  Local Variable Attribute descriptor_idx: %d\n", lvattr->descriptor_idx);
	printf("  Local Variable Attribute descriptor: %s\n", lvattr->descriptor);
	printf("  Local Variable Attribute index: %d\n", lvattr->index);
}

RZ_API void rz_bin_java_summary_print_local_variable_table_attr(RzBinJavaAttrInfo *attr) {
	RzBinJavaLocalVariableAttribute *lvattr;
	RzListIter *iter, *iter_tmp;
	if (attr == NULL) {
		printf("Attempting to print an invalid RzBinJavaAttrInfo *LocalVariableTable.\n");
		return;
	}
	printf("Local Variable Table Attribute Information:\n");
	printf("  Attribute Offset: 0x%08" PFMT64x "\n", attr->file_offset);
	printf("  Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf("  Attribute Length: %d\n", attr->length);
	rz_list_foreach_safe (attr->info.local_variable_table_attr.local_variable_table, iter, iter_tmp, lvattr) {
		rz_bin_java_summary_print_local_variable_attr(lvattr);
	}
}

RZ_API void rz_bin_java_summary_print_local_variable_type_attr(RzBinJavaLocalVariableTypeAttribute *lvattr) {
	if (!lvattr) {
		printf("Attempting to print an invalid RzBinJavaLocalVariableTypeAttribute *.\n");
		return;
	}
	printf("   Local Variable Type Attribute offset: 0x%08" PFMT64x "\n", lvattr->file_offset);
	printf("   Local Variable Type Attribute start_pc: %d\n", lvattr->start_pc);
	printf("   Local Variable Type Attribute Length: %d\n", lvattr->length);
	printf("   Local Variable Type Attribute name_idx: %d\n", lvattr->name_idx);
	printf("   Local Variable Type Attribute name: %s\n", lvattr->name);
	printf("   Local Variable Type Attribute signature_idx: %d\n", lvattr->signature_idx);
	printf("   Local Variable Type Attribute signature: %s\n", lvattr->signature);
	printf("   Local Variable Type Attribute index: %d\n", lvattr->index);
}

RZ_API void rz_bin_java_summary_print_local_variable_type_table_attr(RzBinJavaAttrInfo *attr) {
	RzBinJavaLocalVariableTypeAttribute *lvtattr;
	RzListIter *iter, *iter_tmp;
	if (!attr) {
		printf("Attempting to print an invalid RzBinJavaAttrInfo *LocalVariableTable.\n");
		return;
	}
	printf("Local Variable Type Table Attribute Information:\n");
	printf("   Attribute Offset: 0x%08" PFMT64x "\n", attr->file_offset);
	printf("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf("   Attribute Length: %d\n", attr->length);
	rz_list_foreach_safe (attr->info.local_variable_type_table_attr.local_variable_table, iter, iter_tmp, lvtattr) {
		rz_bin_java_summary_print_local_variable_type_attr(lvtattr);
	}
}

RZ_API void rz_bin_java_summary_print_signature_attr(RzBinJavaAttrInfo *attr) {
	if (!attr) {
		printf("Attempting to print an invalid RzBinJavaAttrInfo *SignatureAttr.\n");
		return;
	}
	printf("Signature Attribute Information:\n");
	printf("  Attribute Offset: 0x%08" PFMT64x "\n", attr->file_offset);
	printf("  Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf("  Attribute Length: %d\n", attr->length);
	printf("  Signature UTF8 Index: %d\n", attr->info.signature_attr.signature_idx);
	printf("  Signature string: %s\n", attr->info.signature_attr.signature);
}

RZ_API void rz_bin_java_summary_print_source_code_file_attr(RzBinJavaAttrInfo *attr) {
	if (!attr) {
		printf("Attempting to print an invalid RzBinJavaAttrInfo *SourceFile.\n");
		return;
	}
	printf("Source File Attribute Information:\n");
	printf("  Attribute Offset: 0x%08" PFMT64x "\n", attr->file_offset);
	printf("  Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf("  Attribute Length: %d\n", attr->length);
	printf("  Source File Index: %d\n", attr->info.source_file_attr.sourcefile_idx);
}

RZ_API void rz_bin_java_summary_print_synthetic_attr(RzBinJavaAttrInfo *attr) {
	if (attr == NULL) {
		printf("Attempting to print an invalid RzBinJavaAttrInfo *Synthetic.\n");
		return;
	}
	printf("Synthetic Attribute Information:\n");
	printf("  Attribute Offset: 0x%08" PFMT64x "\n", attr->file_offset);
	printf("  Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf("  Attribute Length: %d\n", attr->length);
	printf("  Attribute Index: %d\n", attr->info.source_file_attr.sourcefile_idx);
}

RZ_API void rz_bin_java_summary_print_stack_map_table_attr(RzBinJavaAttrInfo *attr) {
	RzListIter *iter, *iter_tmp;
	RzList *ptrList;
	RzBinJavaStackMapFrame *frame;
	if (attr == NULL) {
		printf("Attempting to print an invalid RzBinJavaStackMapTableAttr*  .\n");
		return;
	}
	printf("StackMapTable Attribute Information:\n");
	printf("  Attribute Offset: 0x%08" PFMT64x "\n", attr->file_offset);
	printf("  Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf("  Attribute Length: %d\n", attr->length);
	printf("  StackMapTable Method Code Size: 0x%08x\n", attr->info.stack_map_table_attr.code_size);
	printf("  StackMapTable Frame Entries: 0x%08x\n", attr->info.stack_map_table_attr.number_of_entries);
	printf("  StackMapTable Frames:\n");
	ptrList = attr->info.stack_map_table_attr.stack_map_frame_entries;
	if (ptrList) {
		rz_list_foreach_safe (ptrList, iter, iter_tmp, frame) {
			rz_bin_java_summary_print_stack_map_frame(frame);
		}
	}
}

RZ_API void rz_bin_java_summary_print_stack_map_frame(RzBinJavaStackMapFrame *obj) {
	RzListIter *iter, *iter_tmp;
	RzList *ptrList;
	RzBinJavaVerificationObj *ver_obj;
	if (obj == NULL) {
		printf("Attempting to print an invalid RzBinJavaStackMapFrame*  .\n");
		return;
	}
	printf("Stack Map Frame Information\n");
	printf("  Tag Value = 0x%02x Name: %s\n", obj->tag, ((RzBinJavaStackMapFrameMetas *)obj->metas->type_info)->name);
	printf("  Offset: 0x%08" PFMT64x "\n", obj->file_offset);
	printf("  Local Variable Count = 0x%04x\n", obj->number_of_locals);
	printf("  Stack Items Count = 0x%04x\n", obj->number_of_stack_items);
	printf("  Local Variables:\n");
	ptrList = obj->local_items;
	rz_list_foreach_safe (ptrList, iter, iter_tmp, ver_obj) {
		rz_bin_java_summary_print_verification_info(ver_obj);
	}
	printf("  Stack Items:\n");
	ptrList = obj->stack_items;
	rz_list_foreach_safe (ptrList, iter, iter_tmp, ver_obj) {
		rz_bin_java_summary_print_verification_info(ver_obj);
	}
}

RZ_API void rz_bin_java_summary_print_verification_info(RzBinJavaVerificationObj *obj) {
	ut8 tag_value = RZ_BIN_JAVA_STACKMAP_UNKNOWN;
	if (obj == NULL) {
		printf("Attempting to print an invalid RzBinJavaVerificationObj*  .\n");
		return;
	}
	if (obj->tag < RZ_BIN_JAVA_STACKMAP_UNKNOWN) {
		tag_value = obj->tag;
	}
	printf("Verification Information\n");
	printf("  Offset: 0x%08" PFMT64x "", obj->file_offset);
	printf("  Tag Value = 0x%02x\n", obj->tag);
	printf("  Name = %s\n", RZ_BIN_JAVA_VERIFICATION_METAS[tag_value].name);
	if (obj->tag == RZ_BIN_JAVA_STACKMAP_OBJECT) {
		printf("  Object Constant Pool Index = 0x%x\n", obj->info.obj_val_cp_idx);
	} else if (obj->tag == RZ_BIN_JAVA_STACKMAP_UNINIT) {
		printf("  Uninitialized Object offset in code = 0x%x\n", obj->info.uninit_offset);
	}
}

RZ_API void rz_bin_java_summary_print_field(RzBinJavaField *field) {
	RzBinJavaAttrInfo *attr;
	RzListIter *iter, *iter_tmp;
	if (field) {
		if (field->type == RZ_BIN_JAVA_FIELD_TYPE_METHOD) {
			rz_bin_java_summary_print_method(field);
		} else {
#if 0
			rz_bin_java_summary_print_interface (field);
			return;
		} * /
#endif
			printf("Field Summary Information:\n");
			printf("  File Offset: 0x%08" PFMT64x "\n", field->file_offset);
			printf("  Name Index: %d (%s)\n", field->name_idx, field->name);
			printf("  Descriptor Index: %d (%s)\n", field->descriptor_idx, field->descriptor);
			printf("  Access Flags: 0x%02x (%s)\n", field->flags, field->flags_str);
			printf("  Field Attributes Count: %d\n", field->attr_count);
			printf("  Field Attributes:\n");
			rz_list_foreach_safe (field->attributes, iter, iter_tmp, attr) {
				rz_bin_java_summary_print_attr(attr);
			}
		}
	} else {
		printf("Attempting to print an invalid RzBinJavaField* Field.\n");
	}
}

RZ_API void rz_bin_java_summary_print_method(RzBinJavaField *field) {
	RzBinJavaAttrInfo *attr;
	RzListIter *iter, *iter_tmp;
	if (field == NULL) {
		printf("Attempting to print an invalid RzBinJavaField* Method.\n");
		return;
	}
	printf("Method Summary Information:\n");
	printf("  File Offset: 0x%08" PFMT64x "\n", field->file_offset);
	printf("  Name Index: %d (%s)\n", field->name_idx, field->name);
	printf("  Descriptor Index: %d (%s)\n", field->descriptor_idx, field->descriptor);
	printf("  Access Flags: 0x%02x (%s)\n", field->flags, field->flags_str);
	printf("  Method Attributes Count: %d\n", field->attr_count);
	printf("  Method Attributes:\n");
	rz_list_foreach_safe (field->attributes, iter, iter_tmp, attr) {
		rz_bin_java_summary_print_attr(attr);
	}
}

RZ_API void rz_bin_java_summary_cp_print_interfacemethodref(RzBinJavaCPTypeObj *obj) {
	if (obj == NULL) {
		printf("Attempting to print an invalid RzBinJavaCPTypeObj*  InterfaceMethodRef.\n");
		return;
	}
	printf("InterfaceMethodRef ConstantPool Type (%d) ", obj->metas->ord);
	printf("	Offset: 0x%08" PFMT64x "", obj->file_offset);
	printf("	Class Index = %d\n", obj->info.cp_interface.class_idx);
	printf("	Name and type Index = %d\n", obj->info.cp_interface.name_and_type_idx);
}

RZ_API void rz_bin_java_summary_cp_print_methodhandle(RzBinJavaCPTypeObj *obj) {
	ut8 ref_kind;
	if (obj == NULL) {
		printf("Attempting to print an invalid RzBinJavaCPTypeObj*  RzBinJavaCPTypeMethodHandle.\n");
		return;
	}
	ref_kind = obj->info.cp_method_handle.reference_kind;
	printf("MethodHandle ConstantPool Type (%d) ", obj->metas->ord);
	printf("	Offset: 0x%08" PFMT64x "", obj->file_offset);
	printf("	Reference Kind = (0x%02x) %s\n", ref_kind, RZ_BIN_JAVA_REF_METAS[ref_kind].name);
	printf("	Reference Index = %d\n", obj->info.cp_method_handle.reference_index);
}

RZ_API void rz_bin_java_summary_cp_print_methodtype(RzBinJavaCPTypeObj *obj) {
	if (obj == NULL) {
		printf("Attempting to print an invalid RzBinJavaCPTypeObj*  RzBinJavaCPTypeMethodType.\n");
		return;
	}
	printf("MethodType ConstantPool Type (%d) ", obj->metas->ord);
	printf("  Offset: 0x%08" PFMT64x "", obj->file_offset);
	printf("  Descriptor Index = 0x%02x\n", obj->info.cp_method_type.descriptor_index);
}

RZ_API void rz_bin_java_summary_cp_print_invokedynamic(RzBinJavaCPTypeObj *obj) {
	if (obj == NULL) {
		printf("Attempting to print an invalid RzBinJavaCPTypeObj*  RzBinJavaCPTypeInvokeDynamic.\n");
		return;
	}
	printf("InvokeDynamic ConstantPool Type (%d) ", obj->metas->ord);
	printf("	Offset: 0x%08" PFMT64x "", obj->file_offset);
	printf("	Bootstrap Method Attr Index = (0x%02x)\n", obj->info.cp_invoke_dynamic.bootstrap_method_attr_index);
	printf("	Bootstrap Name and Type Index = (0x%02x)\n", obj->info.cp_invoke_dynamic.name_and_type_index);
}

RZ_API void rz_bin_java_summary_cp_print_methodref(RzBinJavaCPTypeObj *obj) {
	if (obj == NULL) {
		printf("Attempting to print an invalid RzBinJavaCPTypeObj*  MethodRef.\n");
		return;
	}
	printf("MethodRef ConstantPool Type (%d) ", obj->metas->ord);
	printf("	Offset: 0x%08" PFMT64x "", obj->file_offset);
	printf("	Class Index = %d\n", obj->info.cp_method.class_idx);
	printf("	Name and type Index = %d\n", obj->info.cp_method.name_and_type_idx);
}

RZ_API void rz_bin_java_summary_cp_print_fieldref(RzBinJavaCPTypeObj *obj) {
	if (obj == NULL) {
		printf("Attempting to print an invalid RzBinJavaCPTypeObj*  FieldRef.\n");
		return;
	}
	printf("FieldRef ConstantPool Type (%d) ", obj->metas->ord);
	printf("	Offset: 0x%08" PFMT64x "", obj->file_offset);
	printf("	Class Index = %d\n", obj->info.cp_field.class_idx);
	printf("	Name and type Index = %d\n", obj->info.cp_field.name_and_type_idx);
}

RZ_API void rz_bin_java_summary_cp_print_classref(RzBinJavaCPTypeObj *obj) {
	if (obj == NULL) {
		printf("Attempting to print an invalid RzBinJavaCPTypeObj*  ClassRef.\n");
		return;
	}
	printf("ClassRef ConstantPool Type (%d) ", obj->metas->ord);
	printf("	Offset: 0x%08" PFMT64x "", obj->file_offset);
	printf("	Name Index = %d\n", obj->info.cp_class.name_idx);
}

RZ_API void rz_bin_java_summary_cp_print_string(RzBinJavaCPTypeObj *obj) {
	if (!obj) {
		printf("Attempting to print an invalid RzBinJavaCPTypeObj*  String.\n");
		return;
	}
	printf("String ConstantPool Type (%d) ", obj->metas->ord);
	printf("  Offset: 0x%08" PFMT64x "", obj->file_offset);
	printf("  String Index = %d\n", obj->info.cp_string.string_idx);
}

RZ_API void rz_bin_java_summary_cp_print_integer(RzBinJavaCPTypeObj *obj) {
	ut8 *b = NULL;
	if (obj == NULL) {
		printf("Attempting to print an invalid RzBinJavaCPTypeObj*  Integer.\n");
		return;
	}
	b = obj->info.cp_integer.bytes.raw;
	printf("Integer ConstantPool Type (%d) ", obj->metas->ord);
	printf("	Offset: 0x%08" PFMT64x "", obj->file_offset);
	printf("	bytes = %02x %02x %02x %02x\n", b[0], b[1], b[2], b[3]);
	printf("	integer = %d\n", rz_read_at_be32(obj->info.cp_integer.bytes.raw, 0));
}

RZ_API void rz_bin_java_summary_cp_print_float(RzBinJavaCPTypeObj *obj) {
	ut8 *b = NULL;
	if (obj == NULL) {
		printf("Attempting to print an invalid RzBinJavaCPTypeObj*  Double.\n");
		return;
	}
	b = obj->info.cp_float.bytes.raw;
	printf("Float ConstantPool Type (%d) ", obj->metas->ord);
	printf("  Offset: 0x%08" PFMT64x "", obj->file_offset);
	printf("  Bytes = %02x %02x %02x %02x\n", b[0], b[1], b[2], b[3]);
	printf("  Float = %f\n", raw_to_float(obj->info.cp_float.bytes.raw, 0));
}

RZ_API void rz_bin_java_summary_cp_print_long(RzBinJavaCPTypeObj *obj) {
	ut8 *b = NULL;
	if (obj == NULL) {
		printf("Attempting to print an invalid RzBinJavaCPTypeObj*  Long.\n");
		return;
	}
	b = obj->info.cp_long.bytes.raw;
	printf("Long ConstantPool Type (%d) ", obj->metas->ord);
	printf("  Offset: 0x%08" PFMT64x "", obj->file_offset);
	printf("  High-Bytes = %02x %02x %02x %02x\n", b[0], b[1], b[2], b[3]);
	printf("  Low-Bytes = %02x %02x %02x %02x\n", b[4], b[5], b[6], b[7]);
	printf("  Long = %08" PFMT64x "\n", rz_read_at_be64(obj->info.cp_long.bytes.raw, 0));
}

RZ_API void rz_bin_java_summary_cp_print_double(RzBinJavaCPTypeObj *obj) {
	ut8 *b = NULL;
	if (!obj) {
		printf("Attempting to print an invalid RzBinJavaCPTypeObj*  Double.\n");
		return;
	}
	b = obj->info.cp_double.bytes.raw;
	printf("Double ConstantPool Type (%d) ", obj->metas->ord);
	printf("  Offset: 0x%08" PFMT64x "", obj->file_offset);
	printf("  High-Bytes = %02x %02x %02x %02x\n", b[0], b[1], b[2], b[3]);
	printf("  Low-Bytes = %02x %02x %02x %02x\n", b[4], b[5], b[6], b[7]);
	printf("  Double = %f\n", raw_to_double(obj->info.cp_double.bytes.raw, 0));
}

RZ_API void rz_bin_java_summary_cp_print_name_and_type(RzBinJavaCPTypeObj *obj) {
	if (obj == NULL) {
		printf("Attempting to print an invalid RzBinJavaCPTypeObj*  Name_And_Type.\n");
		return;
	}
	printf("Name_And_Type ConstantPool Type (%d) ", obj->metas->ord);
	printf("  Offset: 0x%08" PFMT64x "", obj->file_offset);
	printf("  name_idx = (%d)\n", obj->info.cp_name_and_type.name_idx);
	printf("  descriptor_idx = (%d)\n", obj->info.cp_name_and_type.descriptor_idx);
}

RZ_API void rz_bin_java_summary_cp_print_null(RzBinJavaCPTypeObj *obj) {
	printf("Unknown ConstantPool Type Tag: 0x%04x .\n", obj->tag);
}

RZ_API void rz_bin_java_summary_cp_print_unknown(RzBinJavaCPTypeObj *obj) {
	printf("NULL ConstantPool Type.\n");
}

RZ_API void rz_bin_java_summary_print_element_pair(RzBinJavaElementValuePair *evp) {
	if (!evp) {
		printf("Attempting to print an invalid RzBinJavaElementValuePair *pair.\n");
		return;
	}
	printf("Element Value Pair information:\n");
	printf("  EV Pair File Offset: 0x%08" PFMT64x "\n", evp->file_offset);
	printf("  EV Pair Element Name index: 0x%02x\n", evp->element_name_idx);
	printf("  EV Pair Element Name: %s\n", evp->name);
	printf("  EV Pair Element Value:\n");
	rz_bin_java_summary_print_element_value(evp->value);
}

RZ_API void rz_bin_java_summary_print_element_value(RzBinJavaElementValue *element_value) {
	RzBinJavaCPTypeObj *obj;
	RzBinJavaElementValue *ev_element = NULL;
	RzListIter *iter = NULL, *iter_tmp = NULL;
	char *name;
	if (!element_value) {
		printf("Attempting to print an invalid RzBinJavaElementValuePair *pair.\n");
		return;
	}
	name = ((RzBinJavaElementValueMetas *)element_value->metas->type_info)->name;
	printf("Element Value information:\n");
	printf("   EV Pair File Offset: 0x%08" PFMT64x "\n", element_value->file_offset);
	printf("   EV Value Type (%d): %s\n", element_value->tag, name);
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
		printf("   EV Value Constant Value index: 0x%02x\n", element_value->value.const_value.const_value_idx);
		printf("   EV Value Constant Value Information:\n");
		obj = element_value->value.const_value.const_value_cp_obj;
		if (obj && obj->metas && obj->metas->type_info) {
			((RzBinJavaCPTypeMetas *)obj->metas->type_info)->allocs->print_summary(obj);
		}
		break;
	case RZ_BIN_JAVA_EV_TAG_ENUM:
		printf("   EV Value Enum Constant Value Const Name Index: 0x%02x\n", element_value->value.enum_const_value.const_name_idx);
		printf("   EV Value Enum Constant Value Type Name Index: 0x%02x\n", element_value->value.enum_const_value.type_name_idx);
		printf("   EV Value Enum Constant Value Const CP Information:\n");
		obj = element_value->value.enum_const_value.const_name_cp_obj;
		if (obj && obj->metas && obj->metas->type_info) {
			((RzBinJavaCPTypeMetas *)obj->metas->type_info)->allocs->print_summary(obj);
		}
		printf("   EV Value Enum Constant Value Type CP Information:\n");
		obj = element_value->value.enum_const_value.type_name_cp_obj;
		if (obj && obj->metas && obj->metas->type_info) {
			((RzBinJavaCPTypeMetas *)obj->metas->type_info)->allocs->print_summary(obj);
		}
		break;
	case RZ_BIN_JAVA_EV_TAG_CLASS:
		printf("   EV Value Class Info Index: 0x%02x\n", element_value->value.class_value.class_info_idx);
		printf("   EV Value Class Info CP Information:\n");
		obj = element_value->value.class_value.class_info_cp_obj;
		if (obj && obj->metas && obj->metas->type_info) {
			((RzBinJavaCPTypeMetas *)obj->metas->type_info)->allocs->print_summary(obj);
		}
		break;
	case RZ_BIN_JAVA_EV_TAG_ARRAY:
		printf("   EV Value Array Value Number of Values: 0x%04x\n", element_value->value.array_value.num_values);
		printf("   EV Value Array Values\n");
		rz_list_foreach_safe (element_value->value.array_value.values, iter, iter_tmp, ev_element) {
			rz_bin_java_summary_print_element_value(ev_element);
		}
		break;
	case RZ_BIN_JAVA_EV_TAG_ANNOTATION:
		printf("   EV Annotation Information:\n");
		rz_bin_java_summary_print_annotation(&element_value->value.annotation_value);
		break;
	default:
		// printf unable to handle tag
		break;
	}
}

RZ_API void rz_bin_java_summary_print_annotation(RzBinJavaAnnotation *annotation) {
	RzListIter *iter = NULL, *iter_tmp = NULL;
	RzBinJavaElementValuePair *evp = NULL;
	if (!annotation) {
		// TODO printf invalid annotation
		return;
	}
	printf("  Annotation Type Index: 0x%02x\n", annotation->type_idx);
	printf("  Annotation Number of EV Pairs: 0x%04x\n", annotation->num_element_value_pairs);
	printf("  Annotation EV Pair Values:\n");
	if (annotation->element_value_pairs) {
		rz_list_foreach_safe (annotation->element_value_pairs, iter, iter_tmp, evp) {
			rz_bin_java_summary_print_element_pair(evp);
		}
	}
}

RZ_API void rz_bin_java_summary_print_bootstrap_method_argument(RzBinJavaBootStrapArgument *bsm_arg) {
	if (!bsm_arg) {
		printf("Attempting to print an invalid RzBinJavaBootStrapArgument *.\n");
		return;
	}
	printf("Bootstrap Method Argument Information:\n");
	printf("	Offset: 0x%08" PFMT64x "", bsm_arg->file_offset);
	printf("	Name_And_Type Index = (0x%02x)\n", bsm_arg->argument_info_idx);
	if (bsm_arg->argument_info_cp_obj) {
		printf("	Bootstrap Method Argument Type and Name Info:\n");
		((RzBinJavaCPTypeMetas *)bsm_arg->argument_info_cp_obj)->allocs->print_summary(bsm_arg->argument_info_cp_obj);
	} else {
		printf("	Bootstrap Method Argument Type and Name Info: INVALID\n");
	}
}

RZ_API void rz_bin_java_summary_print_bootstrap_method(RzBinJavaBootStrapMethod *bsm) {
	RzBinJavaBootStrapArgument *bsm_arg = NULL;
	RzListIter *iter = NULL, *iter_tmp = NULL;
	if (!bsm) {
		printf("Attempting to print an invalid RzBinJavaBootStrapArgument *.\n");
		return;
	}
	printf("Bootstrap Method Information:\n");
	printf("	Offset: 0x%08" PFMT64x "", bsm->file_offset);
	printf("	Method Reference Index = (0x%02x)\n", bsm->bootstrap_method_ref);
	printf("	Number of Method Arguments = (0x%02x)\n", bsm->num_bootstrap_arguments);
	if (bsm->bootstrap_arguments) {
		rz_list_foreach_safe (bsm->bootstrap_arguments, iter, iter_tmp, bsm_arg) {
			if (bsm_arg) {
				rz_bin_java_summary_print_bootstrap_method_argument(bsm_arg);
			}
		}
	} else {
		printf("	Bootstrap Method Argument: NONE \n");
	}
}

RZ_API void rz_bin_java_summary_print_bootstrap_methods_attr(RzBinJavaAttrInfo *attr) {
	RzListIter *iter, *iter_tmp;
	RzBinJavaBootStrapMethod *obj = NULL;
	if (!attr || attr->type == RZ_BIN_JAVA_ATTRIBUTE_BOOTSTRAP_METHODS_ATTR) {
		printf("Unable to print attribue summary for RzBinJavaAttrInfo *RzBinJavaBootstrapMethodsAttr");
		return;
	}
	printf("Bootstrap Methods Attribute Information Information:\n");
	printf("	Attribute Offset: 0x%08" PFMT64x "", attr->file_offset);
	printf("	Length: 0x%08x", attr->length);
	printf("	Number of Method Arguments = (0x%02x)\n", attr->info.bootstrap_methods_attr.num_bootstrap_methods);
	if (attr->info.bootstrap_methods_attr.bootstrap_methods) {
		rz_list_foreach_safe (attr->info.bootstrap_methods_attr.bootstrap_methods, iter, iter_tmp, obj) {
			if (obj) {
				rz_bin_java_summary_print_bootstrap_method(obj);
			}
		}
	} else {
		printf("	Bootstrap Methods: NONE \n");
	}
}

RZ_API void rz_bin_java_summary_print_annotation_default_attr(RzBinJavaAttrInfo *attr) {
	if (attr && attr->type == RZ_BIN_JAVA_ATTRIBUTE_ANNOTATION_DEFAULT_ATTR) {
		printf("Annotation Default Attribute Information:\n");
		printf("   Attribute Offset: 0x%08" PFMT64x "\n", attr->file_offset);
		printf("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
		printf("   Attribute Length: %d\n", attr->length);
		rz_bin_java_summary_print_element_value((attr->info.annotation_default_attr.default_value));
	} else {
		// TODO: printf attr is invalid
	}
}

RZ_API void rz_bin_java_summary_print_annotation_array(RzBinJavaAnnotationsArray *annotation_array) {
	RzListIter *iter = NULL, *iter_tmp = NULL;
	RzBinJavaAnnotation *annotation;
	if (!annotation_array->annotations) {
		// TODO printf
		return;
	}
	printf("   Annotation Array Information:\n");
	printf("   Number of Annotation Array Elements: %d\n", annotation_array->num_annotations);
	rz_list_foreach_safe (annotation_array->annotations, iter, iter_tmp, annotation) {
		rz_bin_java_summary_print_annotation(annotation);
	}
}

RZ_API void rz_bin_java_summary_print_rtv_annotations_attr(RzBinJavaAttrInfo *attr) {
	if (attr && attr->type == RZ_BIN_JAVA_ATTRIBUTE_RUNTIME_VISIBLE_ANNOTATION_ATTR) {
		printf("Runtime Visible Annotations Attribute Information:\n");
		printf("   Attribute Offset: 0x%08" PFMT64x "\n", attr->file_offset);
		printf("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
		printf("   Attribute Length: %d\n", attr->length);
		rz_bin_java_summary_print_annotation_array(&attr->info.annotation_array);
	}
}

RZ_API void rz_bin_java_summary_print_rti_annotations_attr(RzBinJavaAttrInfo *attr) {
	if (attr && attr->type == RZ_BIN_JAVA_ATTRIBUTE_RUNTIME_INVISIBLE_ANNOTATION_ATTR) {
		printf("Runtime Invisible Annotations Attribute Information:\n");
		printf("   Attribute Offset: 0x%08" PFMT64x "\n", attr->file_offset);
		printf("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
		printf("   Attribute Length: %d\n", attr->length);
		rz_bin_java_summary_print_annotation_array(&attr->info.annotation_array);
	}
}

RZ_API void rz_bin_java_summary_print_rtvp_annotations_attr(RzBinJavaAttrInfo *attr) {
	RzBinJavaAnnotationsArray *annotation_array = NULL;
	RzListIter *iter = NULL, *iter_tmp = NULL;
	if (attr && attr->type == RZ_BIN_JAVA_ATTRIBUTE_RUNTIME_VISIBLE_PARAMETER_ANNOTATION_ATTR) {
		printf("Runtime Visible Parameter Annotations Attribute Information:\n");
		printf("  Attribute Offset: 0x%08" PFMT64x "\n", attr->file_offset);
		printf("  Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
		printf("  Attribute Length: %d\n", attr->length);
		printf("  Number of Runtime Invisible Parameters: %d\n", attr->info.rtvp_annotations_attr.num_parameters);
		rz_list_foreach_safe (attr->info.rtvp_annotations_attr.parameter_annotations, iter, iter_tmp, annotation_array) {
			rz_bin_java_summary_print_annotation_array(annotation_array);
		}
	}
}

RZ_API void rz_bin_java_summary_print_rtip_annotations_attr(RzBinJavaAttrInfo *attr) {
	RzBinJavaAnnotationsArray *annotation_array = NULL;
	RzListIter *iter = NULL, *iter_tmp = NULL;
	if (attr && attr->type == RZ_BIN_JAVA_ATTRIBUTE_RUNTIME_INVISIBLE_PARAMETER_ANNOTATION_ATTR) {
		printf("Runtime Invisible Parameter Annotations Attribute Information:\n");
		printf("  Attribute Offset: 0x%08" PFMT64x "\n", attr->file_offset);
		printf("  Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
		printf("  Attribute Length: %d\n", attr->length);
		printf("  Number of Runtime Invisible Parameters: %d\n", attr->info.rtip_annotations_attr.num_parameters);
		rz_list_foreach_safe (attr->info.rtip_annotations_attr.parameter_annotations, iter, iter_tmp, annotation_array) {
			rz_bin_java_summary_print_annotation_array(annotation_array);
		}
	}
}

RZ_API void rz_bin_java_summary_print_stack_map_append_frame(RzBinJavaStackMapFrame *obj) {
	RzListIter *iter, *iter_tmp;
	RzList *ptrList;
	RzBinJavaVerificationObj *ver_obj;
	printf("Stack Map Frame Information\n");
	printf("  Tag Value = 0x%02x Name: %s\n", obj->tag, ((RzBinJavaStackMapFrameMetas *)obj->metas->type_info)->name);
	printf("  Offset: 0x%08" PFMT64x "\n", obj->file_offset);
	printf("  Local Variable Count = 0x%04x\n", obj->number_of_locals);
	printf("  Local Variables:\n");
	ptrList = obj->local_items;
	rz_list_foreach_safe (ptrList, iter, iter_tmp, ver_obj) {
		rz_bin_java_summary_print_verification_info(ver_obj);
	}
	printf("  Stack Items Count = 0x%04x\n", obj->number_of_stack_items);
	printf("  Stack Items:\n");
	ptrList = obj->stack_items;
	rz_list_foreach_safe (ptrList, iter, iter_tmp, ver_obj) {
		rz_bin_java_summary_print_verification_info(ver_obj);
	}
}
