// SPDX-FileCopyrightText: 2026 historicattle <sirigere.naren@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "analysis_private.h"

#define DLANG_CLASS_FLAG_COM 0x001 ///< Class uses the COM ABI
#define DLANG_CLASS_FLAG_CPP 0x080 ///< Class uses the C++ ABI

// https://github.com/dlang/dmd/blob/master/druntime/src/object.d#L2314-L2410
#define DLANG_MODULE_FLAG_TLS_CTOR         0x008
#define DLANG_MODULE_FLAG_UNITTEST         0x200
#define DLANG_MODULE_FLAG_IMPORTED_MODULES 0x400
#define DLANG_MODULE_FLAG_LOCAL_CLASSES    0x800

typedef struct dlang_class_info_t {
	ut64 addr;
	ut64 init_size;
	ut64 init_addr;
	ut64 vtable_count;
	ut64 vtable_addr;
	ut64 interfaces_count;
	ut64 interfaces_addr;
	ut64 base_addr;
	ut64 destructor;
	ut64 flags;
	ut64 constructor;
	char *name;
	bool is_interface;
} DlangClassInfo;

typedef struct dlang_interface_t {
	ut64 class_info_addr;
	ut64 vtable_count;
	ut64 vtable_addr;
	ut64 offset;
} DlangInterface;

static void class_info_free(void *ptr) {
	DlangClassInfo *info = ptr;
	RZ_FREE(info->name);
	RZ_FREE(info);
}

static bool addr_has_perm(RzAnalysis *analysis, ut64 addr, int perm) {
	RzBinSection *section = analysis->binb.get_vsect_at(analysis->binb.bin, addr);
	return section && (section->perm & perm) == perm;
}

static bool range_is_readable(RzAnalysis *analysis, ut64 addr, ut64 count, ut64 element_size) {
	if (!count) {
		return false;
	}
	ut64 size = count * element_size;
	RzBinSection *section = analysis->binb.get_vsect_at(analysis->binb.bin, addr);
	if (!section || !(section->perm & RZ_PERM_R)) {
		return false;
	}
	ut64 start = rz_bin_object_addr_with_base(rz_bin_cur_object(analysis->binb.bin), section->vaddr);
	if (start > addr) {
		return false;
	}
	ut64 offset = addr - start;
	return offset <= section->vsize && size <= section->vsize - offset;
}

static bool read_word(RVTableContext *context, ut64 base, ut64 index, RZ_OUT ut64 *value) {
	return context->read_addr(context->analysis, base + index * context->word_size, value);
}

static char *read_name(RVTableContext *context, ut64 addr, ut64 length) {
	if (!addr || !range_is_readable(context->analysis, addr, length, 1)) {
		return NULL;
	}
	char *name = RZ_NEWS(char, (size_t)length + 1);
	if (!name) {
		return NULL;
	}
	if (!context->analysis->iob.read_at(context->analysis->iob.io, addr, (ut8 *)name, length)) {
		RZ_FREE(name);
		return NULL;
	}
	for (ut64 i = 0; i < length; i++) {
		ut8 ch = name[i];
		if (!ch || ch < 0x20 || ch == 0x7f) {
			RZ_FREE(name);
			return NULL;
		}
	}
	name[length] = 0;
	return name;
}

static bool vtable_is_valid(RVTableContext *context, ut64 class_info_addr, ut64 vtable_addr, ut64 count) {
	if (!range_is_readable(context->analysis, vtable_addr, count, context->word_size)) {
		return false;
	}
	ut64 value = 0;
	if (!context->read_addr(context->analysis, vtable_addr, &value) || value != class_info_addr) {
		return false;
	}
	for (ut64 i = 1; i < count; i++) {
		if (!read_word(context, vtable_addr, i, &value)) {
			return false;
		}
		if (value && !addr_has_perm(context->analysis, value, RZ_PERM_X)) {
			return false;
		}
	}
	return true;
}

static bool interface_read(RVTableContext *context, ut64 addr, RZ_OUT DlangInterface *interface) {
	return read_word(context, addr, 0, &interface->class_info_addr) &&
		read_word(context, addr, 1, &interface->vtable_count) &&
		read_word(context, addr, 2, &interface->vtable_addr) &&
		read_word(context, addr, 3, &interface->offset);
}

static bool interfaces_are_valid(RVTableContext *context, DlangClassInfo *info) {
	if (!info->interfaces_count) {
		return true;
	}
	ut64 descriptor_size = 4 * context->word_size;
	if (!info->interfaces_addr || !range_is_readable(context->analysis, info->interfaces_addr, info->interfaces_count, descriptor_size)) {
		return false;
	}
	for (ut64 i = 0; i < info->interfaces_count; i++) {
		DlangInterface interface = { 0 };
		ut64 addr = info->interfaces_addr + i * descriptor_size;
		if (!interface_read(context, addr, &interface) || !interface.class_info_addr) {
			return false;
		}
		if (info->is_interface) {
			if (interface.vtable_addr || interface.vtable_count) {
				return false;
			}
			continue;
		}
		if (!interface.vtable_addr || !interface.vtable_count ||
			!range_is_readable(context->analysis, interface.vtable_addr,
				interface.vtable_count, context->word_size) ||
			interface.offset % context->word_size || interface.offset > info->init_size - context->word_size) {
			return false;
		}
		ut64 actual_vtable = 0;
		if (!context->read_addr(context->analysis, info->init_addr + interface.offset, &actual_vtable) ||
			!vtable_is_valid(context, addr, actual_vtable, interface.vtable_count)) {
			return false;
		}
	}
	return true;
}

static DlangClassInfo *class_info_parse_layout(RVTableContext *context, ut64 addr, bool has_monitor) {
	ut64 field = 1;
	if (has_monitor) {
		field++;
	}
	ut64 name_length = 0;
	ut64 name_addr = 0;
	DlangClassInfo *info = RZ_NEW0(DlangClassInfo);
	if (!info) {
		return NULL;
	}
	info->addr = addr;
	bool ok = read_word(context, addr, field, &info->init_size) &&
		read_word(context, addr, field + 1, &info->init_addr) &&
		read_word(context, addr, field + 2, &name_length) &&
		read_word(context, addr, field + 3, &name_addr) &&
		read_word(context, addr, field + 4, &info->vtable_count) &&
		read_word(context, addr, field + 5, &info->vtable_addr) &&
		read_word(context, addr, field + 6, &info->interfaces_count) &&
		read_word(context, addr, field + 7, &info->interfaces_addr) &&
		read_word(context, addr, field + 8, &info->base_addr) &&
		read_word(context, addr, field + 9, &info->destructor) &&
		read_word(context, addr, field + 11, &info->flags) &&
		read_word(context, addr, field + 15, &info->constructor);
	if (!ok) {
		class_info_free(info);
		return NULL;
	}

	info->name = read_name(context, name_addr, name_length);
	if (!info->name) {
		class_info_free(info);
		return NULL;
	}

	info->is_interface = !info->init_size && !info->vtable_count && !info->base_addr;
	if (!info->is_interface) {
		if (info->init_size < 2 * context->word_size || !info->init_addr ||
			!vtable_is_valid(context, addr, info->vtable_addr, info->vtable_count)) {
			class_info_free(info);
			return NULL;
		}
		ut64 initial_vtable = 0;
		if (!context->read_addr(context->analysis, info->init_addr, &initial_vtable) || initial_vtable != info->vtable_addr) {
			class_info_free(info);
			return NULL;
		}
	}
	if ((info->destructor && !addr_has_perm(context->analysis, info->destructor, RZ_PERM_X)) ||
		(info->constructor && !addr_has_perm(context->analysis, info->constructor, RZ_PERM_X)) ||
		!interfaces_are_valid(context, info)) {
		class_info_free(info);
		return NULL;
	}
	return info;
}

static DlangClassInfo *class_info_parse(RVTableContext *context, ut64 addr) {
	if (!addr || !addr_has_perm(context->analysis, addr, RZ_PERM_R)) {
		return NULL;
	}
	ut64 own_vtable = 0;
	if (!context->read_addr(context->analysis, addr, &own_vtable) || !own_vtable ||
		!addr_has_perm(context->analysis, own_vtable, RZ_PERM_R)) {
		return NULL;
	}
	DlangClassInfo *info = class_info_parse_layout(context, addr, true);
	if (!info) {
		info = class_info_parse_layout(context, addr, false);
	}
	return info;
}

static void info_add(RVTableContext *context, RzList /*<DlangClassInfo *>*/ *infos, HtUP *by_addr, ut64 addr) {
	if (ht_up_find(by_addr, addr, NULL)) {
		return;
	}
	DlangClassInfo *info = class_info_parse(context, addr);
	if (!info) {
		return;
	}
	if (info->flags & (DLANG_CLASS_FLAG_COM | DLANG_CLASS_FLAG_CPP)) {
		class_info_free(info);
		return;
	}
	if (!rz_list_append(infos, info)) {
		class_info_free(info);
		return;
	}
	if (!ht_up_insert(by_addr, addr, info)) {
		rz_list_delete_val(infos, info);
	}
}

static void discover_symbols(RVTableContext *context, RzBinObject *obj, RzList *infos, HtUP *by_addr) {
	const RzPVector *symbols = rz_bin_object_get_symbols(obj);
	void **iter;
	rz_pvector_foreach (symbols, iter) {
		RzBinSymbol *symbol = *iter;
		if (!symbol || RZ_STR_ISEMPTY(symbol->name)) {
			continue;
		}
		if (rz_str_endswith(symbol->name, "7__ClassZ") || rz_str_endswith(symbol->name, "11__InterfaceZ")) {
			info_add(context, infos, by_addr, rz_bin_object_addr_with_base(obj, symbol->vaddr));
		}
	}
}

static bool read_u32(RzAnalysis *analysis, ut64 addr, RZ_OUT ut32 *value) {
	ut8 bytes[4];
	if (!analysis->iob.read_at(analysis->iob.io, addr, bytes, sizeof(bytes))) {
		return false;
	}
	*value = rz_read_ble32(bytes, analysis->big_endian);
	return true;
}

static void discover_module(RVTableContext *context, RzList *infos, HtUP *by_addr, ut64 addr) {
	ut32 flags = 0;
	if (!read_u32(context->analysis, addr, &flags) || !(flags & DLANG_MODULE_FLAG_LOCAL_CLASSES)) {
		return;
	}
	ut64 cursor = addr + 8;
	for (ut32 bit = DLANG_MODULE_FLAG_TLS_CTOR; bit <= DLANG_MODULE_FLAG_UNITTEST; bit <<= 1) {
		if (flags & bit) {
			cursor += context->word_size;
		}
	}
	if (flags & DLANG_MODULE_FLAG_IMPORTED_MODULES) {
		ut64 count = 0;
		if (!context->read_addr(context->analysis, cursor, &count)) {
			return;
		}
		cursor += context->word_size;
		if (count && !range_is_readable(context->analysis, cursor, count, context->word_size)) {
			return;
		}
		cursor += count * context->word_size;
	}
	ut64 count = 0;
	if (!context->read_addr(context->analysis, cursor, &count)) {
		return;
	}
	cursor += context->word_size;
	if (count && !range_is_readable(context->analysis, cursor, count, context->word_size)) {
		return;
	}
	for (ut64 i = 0; i < count; i++) {
		ut64 class_info_addr = 0;
		if (!read_word(context, cursor, i, &class_info_addr)) {
			return;
		}
		info_add(context, infos, by_addr, class_info_addr);
	}
}

static void discover_modules(RVTableContext *context, RzBinObject *obj, RzList *infos, HtUP *by_addr) {
	const RzPVector *sections = context->analysis->binb.get_sections(obj);
	void **iter;
	rz_pvector_foreach (sections, iter) {
		RzBinSection *section = *iter;
		if (!section || section->is_segment || RZ_STR_ISEMPTY(section->name) ||
			(strcmp(section->name, "minfo") && // https://github.com/dlang/dmd/blob/master/compiler/src/dmd/backend/elfobj.d#L3420-L3431
				strcmp(section->name, ".minfo") && // https://github.com/dlang/dmd/blob/master/compiler/src/dmd/backend/mscoffobj.d#L2400-L2415
				strcmp(section->name, "__minfodata"))) { // https://github.com/dlang/dmd/blob/master/compiler/src/dmd/backend/machobj.d#L3381-L3390
			continue;
		}
		if (section->vsize < context->word_size) {
			continue;
		}
		ut64 start = rz_bin_object_addr_with_base(obj, section->vaddr);
		ut64 end = start + section->vsize;
		for (ut64 cursor = start; cursor <= end - context->word_size; cursor += context->word_size) {
			ut64 module_addr = 0;
			if (context->read_addr(context->analysis, cursor, &module_addr) && module_addr) {
				discover_module(context, infos, by_addr, module_addr);
			}
		}
	}
}

static char *method_name(RzAnalysis *analysis, ut64 addr, const char *kind, st64 offset) {
	RzAnalysisFunction *function = rz_analysis_get_function_at(analysis, addr);
	if (function && RZ_STR_ISNOTEMPTY(function->name)) {
		return rz_str_dup(function->name);
	}
	RzBinSymbol *symbol = rz_bin_object_get_symbol_at(rz_bin_cur_object(analysis->binb.bin), addr, true);
	if (symbol && RZ_STR_ISNOTEMPTY(symbol->dname)) {
		return rz_str_dup(symbol->dname);
	}
	if (symbol && RZ_STR_ISNOTEMPTY(symbol->name)) {
		char *name = analysis->binb.demangle(analysis->binb.bin, "dlang", symbol->name);
		if (name) {
			return name;
		}
		return rz_str_dup(symbol->name);
	}
	if (offset < 0) {
		return rz_str_dup(kind);
	}
	return rz_str_newf("%s_0x%" PFMT64x, kind, (ut64)offset);
}

static void add_method(RVTableContext *context, DlangClassInfo *info, ut64 addr, st64 offset, RzAnalysisMethodType type, const char *kind) {
	if (!addr || rz_analysis_class_method_exists_by_addr(context->analysis, info->name, addr)) {
		return;
	}
	char *real_name = method_name(context->analysis, addr, kind, offset);
	if (!real_name) {
		return;
	}
	char *name = rz_str_dup(real_name);
	if (!name) {
		RZ_FREE(real_name);
		return;
	}
	real_name = rz_str_replace(real_name, ",", "#_#", 1);
	if (!real_name) {
		free(name);
		return;
	}
	RzAnalysisMethod method = {
		.name = name,
		.real_name = real_name,
		.addr = addr,
		.vtable_offset = offset,
		.method_type = type,
	};
	rz_analysis_class_method_set(context->analysis, info->name, &method);
	rz_analysis_class_method_fini(&method);
}

static void add_vtable(RVTableContext *context, DlangClassInfo *info, ut64 addr, ut64 count, ut64 object_offset, const char *kind) {
	RzAnalysisVTable vtable = {
		.addr = addr,
		.offset = object_offset,
		.size = count * context->word_size,
	};
	rz_analysis_class_vtable_set(context->analysis, info->name, &vtable);
	rz_analysis_class_vtable_fini(&vtable);
	char *offset_kind = NULL;
	const char *method_kind = kind;
	if (object_offset) {
		offset_kind = rz_str_newf("%s_0x%" PFMT64x, kind, object_offset);
		if (offset_kind) {
			method_kind = offset_kind;
		}
	}
	for (ut64 slot = 1; slot < count; slot++) {
		ut64 method_addr = 0;
		if (!read_word(context, addr, slot, &method_addr)) {
			break;
		}
		add_method(context, info, method_addr, slot * context->word_size,
			RZ_ANALYSIS_CLASS_METHOD_VIRTUAL, method_kind);
	}
	free(offset_kind);
}

static void add_base(RzAnalysis *analysis, DlangClassInfo *info, DlangClassInfo *base_info, ut64 offset) {
	if (!base_info || !strcmp(info->name, base_info->name)) {
		return;
	}
	RzAnalysisBaseClass base = {
		.class_name = rz_str_dup(base_info->name),
		.offset = offset,
	};
	rz_analysis_class_base_set(analysis, info->name, &base);
	rz_analysis_class_base_fini(&base);
}

static void apply_interfaces(RVTableContext *context, HtUP *by_addr, DlangClassInfo *info) {
	DlangClassInfo *owner = info;
	RzSetU *offsets = rz_set_u_new();
	RzSetU *owners = rz_set_u_new();
	if (!offsets || !owners) {
		rz_set_u_free(offsets);
		rz_set_u_free(owners);
		return;
	}
	ut64 descriptor_size = 4 * context->word_size;
	while (owner && !rz_set_u_contains(owners, owner->addr)) {
		rz_set_u_add(owners, owner->addr);
		for (ut64 i = 0; i < owner->interfaces_count; i++) {
			DlangInterface interface = { 0 };
			ut64 descriptor_addr = owner->interfaces_addr + i * descriptor_size;
			if (!interface_read(context, descriptor_addr, &interface) ||
				rz_set_u_contains(offsets, interface.offset)) {
				continue;
			}
			ut64 actual_vtable = 0;
			if (!context->read_addr(context->analysis, info->init_addr + interface.offset, &actual_vtable) ||
				!vtable_is_valid(context, descriptor_addr, actual_vtable, interface.vtable_count)) {
				continue;
			}
			rz_set_u_add(offsets, interface.offset);
			DlangClassInfo *interface_info = ht_up_find(by_addr, interface.class_info_addr, NULL);
			add_base(context->analysis, info, interface_info, interface.offset);
			add_vtable(context, info, actual_vtable, interface.vtable_count, interface.offset, "interface");
		}
		owner = ht_up_find(by_addr, owner->base_addr, NULL);
	}
	rz_set_u_free(owners);
	rz_set_u_free(offsets);
}

static void apply(RVTableContext *context, RzList *infos, HtUP *by_addr) {
	RzListIter *iter;
	DlangClassInfo *info;
	rz_list_foreach (infos, iter, info) {
		rz_analysis_class_create(context->analysis, info->name);
	}
	rz_list_foreach (infos, iter, info) {
		add_base(context->analysis, info, ht_up_find(by_addr, info->base_addr, NULL), 0);
		if (info->is_interface) {
			for (ut64 i = 0; i < info->interfaces_count; i++) {
				DlangInterface interface = { 0 };
				if (interface_read(context, info->interfaces_addr + i * 4 * context->word_size, &interface)) {
					add_base(context->analysis, info, ht_up_find(by_addr, interface.class_info_addr, NULL), interface.offset);
				}
			}
			continue;
		}
		add_vtable(context, info, info->vtable_addr, info->vtable_count, 0, "virtual");
		apply_interfaces(context, by_addr, info);
		add_method(context, info, info->destructor, -1, RZ_ANALYSIS_CLASS_METHOD_DESTRUCTOR, "destructor");
		add_method(context, info, info->constructor, -1, RZ_ANALYSIS_CLASS_METHOD_CONSTRUCTOR, "constructor");
	}
}

/**
 * \brief Recover classes from D runtime type information.
 */
RZ_API void rz_analysis_rtti_dlang(RZ_NONNULL RzAnalysis *analysis) {
	RVTableContext context;
	if (!rz_analysis_vtable_begin(analysis, &context)) {
		return;
	}
	RzBinObject *obj = rz_bin_cur_object(analysis->binb.bin);
	if (!obj) {
		return;
	}
	RzList *infos = rz_list_newf(class_info_free);
	HtUP *by_addr = ht_up_new(NULL, NULL);
	if (!infos || !by_addr) {
		rz_list_free(infos);
		ht_up_free(by_addr);
		return;
	}

	discover_symbols(&context, obj, infos, by_addr);
	discover_modules(&context, obj, infos, by_addr);

	for (ut64 i = 0; i < rz_list_length(infos); i++) {
		DlangClassInfo *info = rz_list_get_n(infos, i);
		info_add(&context, infos, by_addr, info->base_addr);
		for (ut64 n = 0; n < info->interfaces_count; n++) {
			ut64 class_info_addr = 0;
			if (read_word(&context, info->interfaces_addr, n * 4, &class_info_addr)) {
				info_add(&context, infos, by_addr, class_info_addr);
			}
		}
	}
	apply(&context, infos, by_addr);

	ht_up_free(by_addr);
	rz_list_free(infos);
}
