// SPDX-FileCopyrightText: 2026 historicattle <sirigere.naren@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_core.h>
#include "core_private.h"

#define DLANG_MAX_CALL_ARGS  8
#define DLANG_TRACK_MEM_ADDR 0x10000000
#define DLANG_TRACK_MEM_SIZE 0x50000
#define DLANG_STACK_PTR      (DLANG_TRACK_MEM_ADDR + (DLANG_TRACK_MEM_SIZE / 2))
#define DLANG_OBJECT_ADDR    (DLANG_TRACK_MEM_ADDR + 0x30000)

typedef struct dlang_call_seed_t {
	const char *regs[DLANG_MAX_CALL_ARGS]; ///< Calling convention arg regs.
	ut64 vtables[DLANG_MAX_CALL_ARGS]; ///< Vtable seeded for each argument.
	bool has_vtable[DLANG_MAX_CALL_ARGS];
	ut64 count; ///< Number of regs.
} DlangCallSeed;

typedef struct dlang_known_vtable_t {
	ut64 addr;
	RzVector /*<DlangKnownMethod>*/ *methods;
} DlangKnownVTable;

typedef struct dlang_known_method_t {
	ut64 addr;
	ut64 offset;
	char *name;
} DlangKnownMethod;

typedef struct dlang_vtable_index_t {
	RzVector /*<DlangKnownVTable>*/ *vtables; ///< All known vtables.
	HtUP *by_addr;
} DlangVTableIndex;

typedef struct dlang_caller_replay_context_t {
	DlangVTableIndex *vtable_index;
	RzSetU *allocator_calls;
	HtUP *known_classes;
	const DlangCallSeed *argument_regs;
} DlangCallerReplayContext;

static ut64 ptr_size(RzCore *core) {
	return rz_asm_get_bits(core->rasm) == 64 ? 8 : 4;
}

static bool addr_is_executable(RzCore *core, ut64 addr) {
	RzBinSection *section = rz_bin_get_section_at(rz_bin_cur_object(core->bin), addr, true);
	return section && (section->perm & RZ_PERM_X);
}

static bool range_is_readable(RzCore *core, ut64 addr, ut64 count, ut64 element_size) {
	if (!count || !element_size) {
		return false;
	}
	ut64 size = count * element_size;
	RzBinSection *section = rz_bin_get_section_at(rz_bin_cur_object(core->bin), addr, true);
	if (!section || !(section->perm & RZ_PERM_R)) {
		return false;
	}
	ut64 start = rz_bin_object_addr_with_base(rz_bin_cur_object(core->bin), section->vaddr);
	if (start > addr) {
		return false;
	}
	ut64 offset = addr - start;
	return offset <= section->vsize && size <= section->vsize - offset;
}

static RZ_OWN ut8 *read_mapped_range(RzCore *core, ut64 start, ut64 end) {
	if (end <= start) {
		return NULL;
	}
	size_t size = end - start;
	ut8 *bytes = malloc(size);
	if (!bytes) {
		return NULL;
	}
	if (!rz_io_read_at_mapped(core->io, start, bytes, size)) {
		RZ_FREE(bytes);
	}
	return bytes;
}

typedef struct dlang_class_info_t {
	ut64 init_size;
	ut64 init_addr;
	ut64 vtable_count;
	ut64 vtable_addr;
} DlangClassInfo;

static bool class_info(RzCore *core, ut64 addr, RZ_OUT DlangClassInfo *info) {
	if (!addr) {
		return false;
	}
	ut64 psize = ptr_size(core);
	bool big_endian = rz_asm_is_big_endian_set(core->rasm);
	ut64 back_pointer = 0;

	return rz_io_read_i(core->io, addr + 2 * psize, &info->init_size, psize, big_endian) &&
		rz_io_read_i(core->io, addr + 3 * psize, &info->init_addr, psize, big_endian) &&
		rz_io_read_i(core->io, addr + 6 * psize, &info->vtable_count, psize, big_endian) &&
		rz_io_read_i(core->io, addr + 7 * psize, &info->vtable_addr, psize, big_endian) &&
		info->vtable_count && info->vtable_addr &&
		range_is_readable(core, info->vtable_addr, info->vtable_count, psize) &&
		rz_io_read_i(core->io, info->vtable_addr, &back_pointer, psize, big_endian) && back_pointer == addr;
}

static void known_method_fini(void *e, void *user) {
	DlangKnownMethod *method = e;
	RZ_FREE(method->name);
}

static void known_vtable_fini(void *e, void *user) {
	DlangKnownVTable *vtable = e;
	rz_vector_free(vtable->methods);
}

static RzAnalysisMethod *analysis_method_by_addr(RzVector /*<RzAnalysisMethod>*/ *methods, ut64 addr) {
	RzAnalysisMethod *method;
	rz_vector_foreach (methods, method) {
		if (method->addr == addr) {
			return method;
		}
	}
	return NULL;
}

static RZ_OWN DlangVTableIndex *vtable_index_new(RzCore *core) {
	RzPVector *classes = rz_analysis_class_get_all(core->analysis, false);
	if (!classes) {
		return NULL;
	}
	DlangVTableIndex *index = RZ_NEW(DlangVTableIndex);
	if (!index) {
		rz_pvector_free(classes);
		return NULL;
	}
	index->vtables = rz_vector_new(sizeof(DlangKnownVTable), known_vtable_fini, NULL);
	index->by_addr = ht_up_new(NULL, NULL);
	if (!index->vtables || !index->by_addr) {
		rz_vector_free(index->vtables);
		ht_up_free(index->by_addr);
		free(index);
		rz_pvector_free(classes);
		return NULL;
	}

	void **iter;
	rz_pvector_foreach (classes, iter) {
		SdbKv *kv = *iter;
		const char *class_name = sdbkv_key(kv);
		RzVector *class_methods = rz_analysis_class_method_get_all(core->analysis, class_name);
		RzVector *class_vtables = rz_analysis_class_vtable_get_all(core->analysis, class_name);
		RzAnalysisVTable *analysis_vtable;
		rz_vector_foreach (class_vtables, analysis_vtable) {
			DlangKnownVTable vtable = {
				.addr = analysis_vtable->addr,
				.methods = rz_vector_new(sizeof(DlangKnownMethod), known_method_fini, NULL),
			};
			if (!vtable.methods) {
				continue;
			}
			ut64 psize = ptr_size(core);
			bool big_endian = rz_asm_is_big_endian_set(core->rasm);

			for (ut64 offset = psize; offset < analysis_vtable->size; offset += psize) {
				ut64 method_addr = 0;
				if (!rz_io_read_i(core->io, vtable.addr + offset, &method_addr, psize, big_endian) ||
					!method_addr || !addr_is_executable(core, method_addr)) {
					continue;
				}
				RzAnalysisMethod *analysis_method = analysis_method_by_addr(class_methods, method_addr);
				if (!analysis_method) {
					continue;
				}
				const char *name = analysis_method->name;
				if (RZ_STR_ISNOTEMPTY(analysis_method->real_name)) {
					name = analysis_method->real_name;
				}
				DlangKnownMethod method = {
					.addr = method_addr,
					.offset = offset,
					.name = rz_str_dup(name),
				};
				if (!method.name || !rz_vector_push(vtable.methods, &method)) {
					known_method_fini(&method, NULL);
				}
			}
			if (!rz_vector_push(index->vtables, &vtable)) {
				known_vtable_fini(&vtable, NULL);
			}
		}
		rz_vector_free(class_vtables);
		rz_vector_free(class_methods);
	}
	rz_pvector_free(classes);

	DlangKnownVTable *vtable;
	rz_vector_foreach (index->vtables, vtable) {
		ht_up_insert(index->by_addr, vtable->addr, vtable);
	}
	return index;
}

static void vtable_index_free(DlangVTableIndex *index) {
	ht_up_free(index->by_addr);
	rz_vector_free(index->vtables);
	free(index);
}

static DlangKnownVTable *vtable_by_addr(DlangVTableIndex *index, ut64 addr) {
	return ht_up_find(index->by_addr, addr, NULL);
}

static DlangKnownMethod *method_at_offset(DlangKnownVTable *vtable, ut64 offset) {
	DlangKnownMethod *method;
	rz_vector_foreach (vtable->methods, method) {
		if (method->offset == offset) {
			return method;
		}
	}
	return NULL;
}

static ut64 il_value_to_ut64(RZ_NULLABLE RzILVal *value) {
	if (!value) {
		return UT64_MAX;
	}
	RzBitVector *bv = rz_il_value_to_bv(value);
	if (!bv) {
		return UT64_MAX;
	}
	ut64 result = rz_bv_to_ut64(bv);
	rz_bv_free(bv);
	return result;
}

static ut64 get_reg_value(RzAnalysis *analysis, const char *reg_name) {
	if (RZ_STR_ISEMPTY(reg_name)) {
		return UT64_MAX;
	}
	RzAnalysisILVM *vm = rz_analysis_get_il_vm(analysis);
	if (!vm) {
		return UT64_MAX;
	}
	RzILVal *value = rz_il_vm_get_var_value(vm->vm, RZ_IL_VAR_KIND_GLOBAL, reg_name);
	return il_value_to_ut64(value);
}

static bool is_valid_reg(RzCore *core, const char *reg_name) {
	if (RZ_STR_ISEMPTY(reg_name)) {
		return false;
	}
	RzReg *reg = rz_analysis_get_reg(core->analysis);
	return reg && rz_reg_get(reg, reg_name, RZ_REG_TYPE_ANY);
}

static void advance_il_pc(RzCore *core, ut64 addr) {
	RzReg *reg = rz_analysis_get_reg(core->analysis);
	if (reg) {
		rz_reg_set_value_by_role(reg, RZ_REG_NAME_PC, addr);
	}
}

static bool analysis_value_addr(RzCore *core, RZ_NULLABLE const RzAnalysisOp *op, RzAnalysisValue *value, RZ_OUT ut64 *addr) {
	ut64 result = value->base;
	const char *base_reg = NULL;
	if (value->reg) {
		base_reg = value->reg->name;
	}
	if (base_reg) {
		ut64 base = UT64_MAX;
		RzReg *reg = rz_analysis_get_reg(core->analysis);
		const char *pc = NULL;
		if (reg) {
			pc = rz_reg_get_name(reg, RZ_REG_NAME_PC);
		}
		if (op && pc && !strcmp(base_reg, pc)) {
			base = op->addr + op->size;
		} else {
			base = get_reg_value(core->analysis, base_reg);
		}
		if (!base || base == UT64_MAX) {
			return false;
		}
		result += base;
	}
	if (value->regdelta) {
		ut64 index = get_reg_value(core->analysis, value->regdelta->name);
		ut64 scale = value->mul;
		if (!scale) {
			scale = 1;
		}
		if (index == UT64_MAX) {
			return false;
		}
		result += index * scale;
	}
	result += value->delta;
	if (!result) {
		return false;
	}
	*addr = result;
	return true;
}

static bool value_mem_access_is_safe(RzCore *core, RzAnalysisOp *op, RzAnalysisValue *value, bool write) {
	ut64 addr = UT64_MAX;
	if (!analysis_value_addr(core, op, value, &addr)) {
		return false;
	}

	ut64 access_size = value->memref;
	if (addr >= DLANG_TRACK_MEM_ADDR) {
		ut64 offset = addr - DLANG_TRACK_MEM_ADDR;
		if (offset < DLANG_TRACK_MEM_SIZE && access_size <= DLANG_TRACK_MEM_SIZE - offset) {
			return true;
		}
	}
	return !write && rz_io_is_valid_offset(core->io, addr, RZ_PERM_R);
}

static bool op_memory_access_is_safe(RzCore *core, RzAnalysisOp *op) {
	if ((op->type & RZ_ANALYSIS_OP_TYPE_MASK) == RZ_ANALYSIS_OP_TYPE_LEA) {
		return true;
	}
	if (op->dst && op->dst->memref > 0 && !value_mem_access_is_safe(core, op, op->dst, true)) {
		return false;
	}
	for (ut64 i = 0; i < RZ_ARRAY_SIZE(op->src); i++) {
		if (op->src[i] && op->src[i]->memref > 0 &&
			!value_mem_access_is_safe(core, op, op->src[i], false)) {
			return false;
		}
	}
	return true;
}

static const char *op_dst_reg_name(RzAnalysisOp *op) {
	if (!op->dst || op->dst->type != RZ_ANALYSIS_VAL_REG || !op->dst->reg) {
		return NULL;
	}
	return op->dst->reg->name;
}

static bool op_is_vtable_slot_dispatch(RzCore *core, RzAnalysisOp *op) {
	return is_valid_reg(core, op->reg) && op->disp >= (st64)ptr_size(core) &&
		!(op->disp % (st64)ptr_size(core)) &&
		(op->type & (RZ_ANALYSIS_OP_TYPE_IND | RZ_ANALYSIS_OP_TYPE_MEM)) &&
		(rz_analysis_op_is_call(op) || rz_analysis_op_is_eob(op));
}

static bool op_is_register_target_dispatch(RzCore *core, RzAnalysisOp *op) {
	return is_valid_reg(core, op->reg) && (op->type & RZ_ANALYSIS_OP_TYPE_REG) &&
		!(op->type & (RZ_ANALYSIS_OP_TYPE_IND | RZ_ANALYSIS_OP_TYPE_MEM)) &&
		(rz_analysis_op_is_call(op) || rz_analysis_op_is_eob(op));
}

static void track_init(RzCore *core, RZ_NULLABLE const DlangCallSeed *seed) {
	rz_core_analysis_esil_init_mem(core, NULL, DLANG_TRACK_MEM_ADDR, DLANG_TRACK_MEM_SIZE);
	rz_core_analysis_il_reinit(core);
	if (rz_asm_is_arch(core->rasm, "x86")) {
		rz_analysis_il_vm_set_unsigned(core->analysis, "rbp", DLANG_STACK_PTR);
		rz_analysis_il_vm_set_unsigned(core->analysis, "rsp", DLANG_STACK_PTR);
	} else if (rz_asm_is_arch(core->rasm, "arm")) {
		rz_analysis_il_vm_set_unsigned(core->analysis, "x29", DLANG_STACK_PTR);
		rz_analysis_il_vm_set_unsigned(core->analysis, "sp", DLANG_STACK_PTR);
	} else {
		RZ_LOG_WARN("arch %s is not supported\n", rz_core_get_arch(core));
	}
	if (!seed) {
		return;
	}

	ut64 psize = ptr_size(core);
	bool big_endian = rz_asm_is_big_endian_set(core->rasm);
	for (ut64 i = 0; i < seed->count; i++) {
		if (!seed->has_vtable[i]) {
			continue;
		}
		ut64 object_addr = DLANG_OBJECT_ADDR + i * 2 * psize;
		rz_analysis_il_vm_set_unsigned(core->analysis, seed->regs[i], object_addr);
		ut64 vtable_addr = seed->vtables[i];
		rz_io_write_i(core->io, object_addr, &vtable_addr, psize, big_endian);
	}
}

static void track_fini(RzCore *core) {
	rz_core_analysis_il_reinit(core);
	rz_core_analysis_esil_init_mem_del(core, NULL, DLANG_TRACK_MEM_ADDR, DLANG_TRACK_MEM_SIZE);
}

static ut64 allocate_object(RzCore *core, ut64 class_info_addr, ut64 object_addr) {
	DlangClassInfo info = { 0 };
	if (!class_info(core, class_info_addr, &info) || !info.init_size || !info.init_addr ||
		!range_is_readable(core, info.init_addr, info.init_size, 1)) {
		return 0;
	}
	ut64 mem_end = DLANG_TRACK_MEM_ADDR + DLANG_TRACK_MEM_SIZE;
	if (object_addr >= mem_end || info.init_size > mem_end - object_addr) {
		return 0;
	}
	ut8 *bytes = malloc(info.init_size);
	if (!bytes) {
		return 0;
	}
	bool ok = rz_io_read_at_mapped(core->io, info.init_addr, bytes, info.init_size) &&
		rz_io_write_at(core->io, object_addr, bytes, info.init_size);
	RZ_FREE(bytes);
	if (!ok) {
		return 0;
	}
	return info.init_size;
}

static void clear_dst_reg_for_skipped_op(RzCore *core, RzAnalysisOp *op) {
	const char *dst = op_dst_reg_name(op);
	if (is_valid_reg(core, dst)) {
		rz_analysis_il_vm_set_unsigned(core->analysis, dst, 0);
	}
}

static void track_step_or_skip(RzCore *core, RzAnalysisOp *op, ut64 next_addr) {
	if (!op->il_op || !op_memory_access_is_safe(core, op)) {
		clear_dst_reg_for_skipped_op(core, op);
		advance_il_pc(core, next_addr);
		return;
	}
	advance_il_pc(core, op->addr);
	if (!rz_core_il_step(core, 1)) {
		advance_il_pc(core, next_addr);
	}
}

static void add_virtual_xref(RzAnalysis *analysis, const char *method_name, ut64 addr) {
	HtSP *virtual_xrefs = rz_analysis_get_virtual_xrefs(analysis);
	if (!virtual_xrefs || RZ_STR_ISEMPTY(method_name)) {
		return;
	}
	bool found = false;
	RzSetU *set = ht_sp_find(virtual_xrefs, method_name, &found);
	if (!found) {
		set = rz_set_u_new();
		if (!set || !ht_sp_insert(virtual_xrefs, method_name, set)) {
			rz_set_u_free(set);
			return;
		}
	}
	rz_set_u_add(set, addr);
}

static void add_virtual_xrefs_for_method(RzCore *core, const char *method_name, ut64 method_addr, ut64 xref_addr) {
	add_virtual_xref(core->analysis, method_name, xref_addr);
	const RzList *flags = rz_flag_get_list(core->flags, method_addr);
	RzListIter *iter;
	RzFlagItem *flag;
	rz_list_foreach (flags, iter, flag) {
		if (RZ_STR_ISNOTEMPTY(flag->name) && strcmp(flag->name, method_name)) {
			add_virtual_xref(core->analysis, flag->name, xref_addr);
		}
	}
}

static void virtual_calls_add(RzCore *core, HtUP *calls, ut64 call_addr, DlangKnownMethod *method) {
	if (!calls || !method || RZ_STR_ISEMPTY(method->name)) {
		return;
	}
	bool found = false;
	RzSetS *set = ht_up_find(calls, call_addr, &found);
	if (!found) {
		set = rz_set_s_new(HT_STR_DUP);
		if (!set || !ht_up_insert(calls, call_addr, set)) {
			rz_set_s_free(set);
			return;
		}
	}
	rz_set_s_add(set, method->name);
	add_virtual_xrefs_for_method(core, method->name, method->addr, call_addr);
}

typedef struct dlang_comment_context_t {
	RzStrBuf *text;
	bool first;
} DlangCommentContext;

static bool virtual_comment_add_name(void *user, const char *name, RZ_UNUSED const void *value) {
	DlangCommentContext *context = user;
	if (context->first) {
		rz_strbuf_setf(context->text, "Virtual call: %s", name);
		context->first = false;
	} else {
		rz_strbuf_appendf(context->text, " / %s", name);
	}
	return true;
}

static bool virtual_comment_emit(void *user, ut64 addr, const void *value) {
	RzCore *core = user;
	RzStrBuf text;
	rz_strbuf_init(&text);
	DlangCommentContext context = { &text, true };
	ht_sp_foreach((HtSP *)value, virtual_comment_add_name, &context);
	const char *comment = rz_strbuf_get(&text);
	if (RZ_STR_ISNOTEMPTY(comment)) {
		rz_core_meta_comment_add(core, comment, addr);
	}
	rz_strbuf_fini(&text);
	return true;
}

static void devirtualize_step(RzCore *core, RzAnalysisOp *op, DlangVTableIndex *index,
	HtUP *calls, RZ_NULLABLE const DlangCallSeed *seed) {
	if (op_is_vtable_slot_dispatch(core, op)) {
		ut64 vtable_addr = get_reg_value(core->analysis, op->reg);
		DlangKnownVTable *vtable = vtable_by_addr(index, vtable_addr);
		if (!vtable) {
			return;
		}
		ut64 offset = op->disp;
		if (is_valid_reg(core, op->ireg)) {
			ut64 array_index = get_reg_value(core->analysis, op->ireg);
			ut64 scale = op->scale;
			if (!scale) {
				scale = 1;
			}
			if (array_index == UT64_MAX) {
				return;
			}
			offset += array_index * scale;
		}
		DlangKnownMethod *method = method_at_offset(vtable, offset);
		if (method) {
			virtual_calls_add(core, calls, op->addr, method);
		}
		return;
	}
	if (!op_is_register_target_dispatch(core, op)) {
		return;
	}
	ut64 target = get_reg_value(core->analysis, op->reg);
	if (!target || !addr_is_executable(core, target)) {
		return;
	}
	DlangKnownVTable *vtable;
	rz_vector_foreach (index->vtables, vtable) {
		if (seed) {
			bool seeded = false;
			for (ut64 i = 0; i < seed->count; i++) {
				if (seed->has_vtable[i] && seed->vtables[i] == vtable->addr) {
					seeded = true;
					break;
				}
			}
			if (!seeded) {
				continue;
			}
		}
		DlangKnownMethod *method;
		rz_vector_foreach (vtable->methods, method) {
			if (method->addr == target) {
				virtual_calls_add(core, calls, op->addr, method);
			}
		}
	}
}

static ut64 allocator_class_info(RzCore *core, RzAnalysisFunction *function) {
	ut64 result = 0;
	RzList *xrefs = rz_analysis_function_get_xrefs_from(function);
	RzListIter *iter;
	RzAnalysisXRef *xref;
	rz_list_foreach (xrefs, iter, xref) {
		DlangClassInfo info = { 0 };
		if (!class_info(core, xref->to, &info)) {
			continue;
		}
		if (result && result != xref->to) {
			result = 0;
			break;
		}
		result = xref->to;
	}
	rz_list_free(xrefs);
	return result;
}

static bool function_is_thunk_to(RzCore *core, RzAnalysisFunction *function, ut64 target) {
	if (!function || function->addr == target) {
		return false;
	}
	RzAnalysisOp *op = rz_core_analysis_op(core, function->addr, RZ_ANALYSIS_OP_MASK_BASIC);
	bool result = op && (op->type & RZ_ANALYSIS_OP_TYPE_MASK) == RZ_ANALYSIS_OP_TYPE_JMP &&
		op->jump == target && rz_analysis_function_max_addr(function) == function->addr + op->size;
	rz_analysis_op_free(op);
	return result;
}

static RZ_OWN RzVector /*<ut64>*/ *call_sites_to(RzCore *core, ut64 target) {
	RzVector *result = rz_vector_new(sizeof(ut64), NULL, NULL);
	if (!result) {
		return NULL;
	}
	RzList *xrefs = rz_analysis_xrefs_get_to(core->analysis, target);
	RzListIter *iter;
	RzAnalysisXRef *xref;
	rz_list_foreach (xrefs, iter, xref) {
		if (xref->type != RZ_ANALYSIS_XREF_TYPE_CALL && xref->type != RZ_ANALYSIS_XREF_TYPE_CODE) {
			continue;
		}
		RzAnalysisFunction *function = rz_analysis_get_fcn_in(core->analysis, xref->from, RZ_ANALYSIS_FCN_TYPE_NULL);
		if (!function_is_thunk_to(core, function, target)) {
			rz_vector_push(result, &xref->from);
			continue;
		}
		RzList *thunk_xrefs = rz_analysis_xrefs_get_to(core->analysis, function->addr);
		RzListIter *thunk_iter;
		RzAnalysisXRef *thunk_xref;
		rz_list_foreach (thunk_xrefs, thunk_iter, thunk_xref) {
			if (thunk_xref->type == RZ_ANALYSIS_XREF_TYPE_CALL || thunk_xref->type == RZ_ANALYSIS_XREF_TYPE_CODE) {
				rz_vector_push(result, &thunk_xref->from);
			}
		}
		rz_list_free(thunk_xrefs);
	}
	rz_list_free(xrefs);
	return result;
}

static RZ_OWN RzSetU *allocator_xrefs(RzCore *core, HtUP *known_classes) {
	RzSetU *result = rz_set_u_new();
	if (!result) {
		return NULL;
	}
	RzList *functions = rz_analysis_function_list(core->analysis);
	RzListIter *iter;
	RzAnalysisFunction *function;
	rz_list_foreach (functions, iter, function) {
		if (RZ_STR_ISEMPTY(function->name) || !strstr(function->name, "_d_newclass")) {
			continue;
		}
		ut64 known_class = allocator_class_info(core, function);
		RzVector *call_sites = call_sites_to(core, function->addr);
		ut64 *call_site;
		rz_vector_foreach (call_sites, call_site) {
			rz_set_u_add(result, *call_site);
			if (known_class) {
				ut64 *value = RZ_NEW(ut64);
				if (value) {
					*value = known_class;
					if (!ht_up_insert(known_classes, *call_site, value)) {
						free(value);
					}
				}
			}
		}
		rz_vector_free(call_sites);
	}
	return result;
}

static ut64 replay_allocator(RzCore *core, RzAnalysisOp *op, HtUP *known_classes, const char *arg0, const char *ret_reg, ut64 object_addr) {
	bool found = false;
	ut64 *known_class = ht_up_find(known_classes, op->addr, &found);
	ut64 class_info_addr = get_reg_value(core->analysis, arg0);
	if (found) {
		class_info_addr = *known_class;
	}
	ut64 object_size = allocate_object(core, class_info_addr, object_addr);
	if (is_valid_reg(core, ret_reg)) {
		ut64 result = 0;
		if (object_size) {
			result = object_addr;
		}
		rz_analysis_il_vm_set_unsigned(core->analysis, ret_reg, result);
	}
	advance_il_pc(core, op->addr + op->size);
	return object_size;
}

typedef struct dlang_function_replay_context_t {
	RzCore *core;
	RzAnalysisFunction *function;
	ut64 end;
	DlangVTableIndex *vtable_index;
	RzSetU *allocator_calls;
	HtUP *known_classes;
	const DlangCallSeed *seed;
	HtUP *calls;
} DlangFunctionReplayContext;

static bool replay_function(const DlangFunctionReplayContext *context) {
	RzCore *core = context->core;
	ut64 start = context->function->addr;
	ut64 end = context->end;
	if (!end) {
		end = rz_analysis_function_max_addr(context->function);
	}
	if (!addr_is_executable(core, start)) {
		return false;
	}
	ut8 *bytes = read_mapped_range(core, start, end);
	RzAnalysisOp *op = rz_analysis_op_new();
	if (!bytes || !op) {
		RZ_FREE(bytes);
		rz_analysis_op_free(op);
		return false;
	}
	const char *cc = rz_analysis_cc_default(core->analysis);
	const char *arg0 = rz_analysis_cc_arg(core->analysis, cc, 0);
	const char *ret_reg = rz_analysis_cc_ret(core->analysis, cc);
	ut64 old_offset = core->offset;
	ut64 offset = 0;
	core->offset = start;
	ut64 next_object = DLANG_OBJECT_ADDR + DLANG_MAX_CALL_ARGS * 2 * ptr_size(core);
	track_init(core, context->seed);
	while (start < end) {
		if (rz_analysis_op(core->analysis, op, start, bytes + offset, end - start, RZ_ANALYSIS_OP_MASK_ALL) <= 0 ||
			op->size < 1) {
			break;
		}
		devirtualize_step(core, op, context->vtable_index, context->calls, context->seed);
		ut64 next = start + op->size;
		if (rz_set_u_contains(context->allocator_calls, op->addr)) {
			ut64 size = replay_allocator(core, op, context->known_classes, arg0, ret_reg, next_object);
			next_object += RZ_ROUND(size, ptr_size(core));
		} else if ((op->type & RZ_ANALYSIS_OP_TYPE_MASK) == RZ_ANALYSIS_OP_TYPE_JMP &&
			op->jump > next && op->jump <= end) {
			next = op->jump;
			advance_il_pc(core, next);
		} else if (rz_analysis_op_is_call(op) || rz_analysis_op_is_eob(op)) {
			advance_il_pc(core, next);
		} else {
			track_step_or_skip(core, op, next);
		}
		start = next;
		offset = start - context->function->addr;
		core->offset = start;
		rz_analysis_op_fini(op);
	}
	core->offset = old_offset;
	rz_analysis_op_free(op);
	free(bytes);
	return true;
}

static void get_arg_regs(RzCore *core, RZ_OUT DlangCallSeed *args) {
	const char *cc = rz_analysis_cc_default(core->analysis);
	for (ut64 i = 0; i < DLANG_MAX_CALL_ARGS; i++) {
		const char *reg = rz_analysis_cc_arg(core->analysis, cc, i);
		if (!is_valid_reg(core, reg)) {
			break;
		}
		args->regs[args->count++] = reg;
	}
}

static bool seed_equal(const DlangCallSeed *a, const DlangCallSeed *b) {
	if (a->count != b->count) {
		return false;
	}
	for (ut64 i = 0; i < a->count; i++) {
		if (a->has_vtable[i] != b->has_vtable[i] ||
			(a->has_vtable[i] && a->vtables[i] != b->vtables[i])) {
			return false;
		}
	}
	return true;
}

static void push_unique_seed(RzVector /*<DlangCallSeed>*/ *seeds, const DlangCallSeed *seed) {
	bool has_vtable = false;
	for (ut64 i = 0; i < seed->count; i++) {
		if (seed->has_vtable[i]) {
			has_vtable = true;
			break;
		}
	}
	if (!has_vtable) {
		return;
	}
	DlangCallSeed *existing;
	rz_vector_foreach (seeds, existing) {
		if (seed_equal(existing, seed)) {
			return;
		}
	}
	rz_vector_push(seeds, (DlangCallSeed *)seed);
}

static void collect_caller_args_from_site(RzCore *core, RzAnalysisFunction *caller, ut64 call_addr,
	const DlangCallerReplayContext *context, RzVector /*<DlangCallSeed>*/ *seeds) {
	if (call_addr <= caller->addr) {
		return;
	}
	DlangFunctionReplayContext replay = {
		.core = core,
		.function = caller,
		.end = RZ_MIN(call_addr, rz_analysis_function_max_addr(caller)),
		.vtable_index = context->vtable_index,
		.allocator_calls = context->allocator_calls,
		.known_classes = context->known_classes,
	};
	if (!replay_function(&replay)) {
		return;
	}

	DlangCallSeed seed = *context->argument_regs;
	ut64 psize = ptr_size(core);
	bool big_endian = rz_asm_is_big_endian_set(core->rasm);
	for (ut64 i = 0; i < context->argument_regs->count; i++) {
		ut64 object_addr = get_reg_value(core->analysis, context->argument_regs->regs[i]);
		ut64 vtable_addr = 0;
		if (object_addr && rz_io_read_i(core->io, object_addr, &vtable_addr, psize, big_endian) &&
			vtable_by_addr(context->vtable_index, vtable_addr)) {
			seed.vtables[i] = vtable_addr;
			seed.has_vtable[i] = true;
		}
	}
	push_unique_seed(seeds, &seed);
	track_fini(core);
}

static RZ_OWN RzVector /*<DlangCallSeed>*/ *collect_caller_args(RzCore *core,
	RzAnalysisFunction *function, const DlangCallerReplayContext *context) {
	RzVector *seeds = rz_vector_new(sizeof(DlangCallSeed), NULL, NULL);
	if (!seeds) {
		return NULL;
	}
	RzVector *call_sites = call_sites_to(core, function->addr);
	ut64 *call_site;
	rz_vector_foreach (call_sites, call_site) {
		RzAnalysisFunction *caller = rz_analysis_get_fcn_in(core->analysis, *call_site, RZ_ANALYSIS_FCN_TYPE_NULL);
		if (caller) {
			collect_caller_args_from_site(core, caller, *call_site, context, seeds);
		}
	}
	rz_vector_free(call_sites);
	return seeds;
}

/**
 * \brief Resolve D virtual call targets in the current function.
 *
 * Replays the function with RzIL, propagating ClassInfo allocations and
 * receiver types from callers, then adds comments and virtual xrefs for resolved
 * class and interface methods
 */
RZ_IPI void rz_core_analysis_devirtualize_dlang_methods(RZ_NULLABLE RzCore *core) {
	if (!core) {
		return;
	}
	RzAnalysisFunction *function = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_NULL);
	if (!function) {
		RZ_LOG_ERROR("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
		return;
	}
	DlangVTableIndex *index = vtable_index_new(core);
	if (!index) {
		return;
	}
	HtUP *known_classes = ht_up_new(NULL, free);
	RzSetU *allocator_calls = NULL;
	if (known_classes) {
		allocator_calls = allocator_xrefs(core, known_classes);
	}
	if (!known_classes || !allocator_calls) {
		ht_up_free(known_classes);
		rz_set_u_free(allocator_calls);
		vtable_index_free(index);
		return;
	}
	DlangCallSeed args = { 0 };
	get_arg_regs(core, &args);
	RzVector *seeds = NULL;
	if (args.count) {
		DlangCallerReplayContext context = {
			.vtable_index = index,
			.allocator_calls = allocator_calls,
			.known_classes = known_classes,
			.argument_regs = &args,
		};
		seeds = collect_caller_args(core, function, &context);
	}

	HtUP *calls = ht_up_new(NULL, (HtUPFreeValue)rz_set_s_free);
	if (!calls) {
		rz_vector_free(seeds);
		rz_set_u_free(allocator_calls);
		ht_up_free(known_classes);
		vtable_index_free(index);
		return;
	}
	DlangFunctionReplayContext replay = {
		.core = core,
		.function = function,
		.vtable_index = index,
		.allocator_calls = allocator_calls,
		.known_classes = known_classes,
		.calls = calls,
	};

	if (replay_function(&replay)) {
		track_fini(core);
	}
	DlangCallSeed *seed;
	rz_vector_foreach (seeds, seed) {
		replay.seed = seed;
		if (replay_function(&replay)) {
			track_fini(core);
		}
	}
	ht_up_foreach(calls, virtual_comment_emit, core);
	ht_up_free(calls);
	rz_vector_free(seeds);
	rz_set_u_free(allocator_calls);
	ht_up_free(known_classes);
	vtable_index_free(index);
}
