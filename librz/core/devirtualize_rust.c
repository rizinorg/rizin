// SPDX-FileCopyrightText: 2026 historicattle <sirigere.naren@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_analysis.h>
#include <rz_core.h>
#include "core_private.h"

#define RUST_TYPE_ID_BYTES  16
#define RUST_MAX_CALL_ARGS  8
#define RUST_TRACK_MEM_ADDR 0x10000000
#define RUST_TRACK_MEM_SIZE 0x50000
#define RUST_STACK_PTR      (RUST_TRACK_MEM_ADDR + (RUST_TRACK_MEM_SIZE / 2))

typedef struct rust_any_vtable_t {
	ut64 vtable_addr;
	ut64 type_id_low;
	ut64 type_id_high;
	bool has_type_id;
	bool has_type_id_high;
	char *concrete_type;
} RustAnyVTable;

typedef struct rust_call_seed_t {
	const char *regs[RUST_MAX_CALL_ARGS]; ///< argument register names.
	ut64 values[RUST_MAX_CALL_ARGS]; ///< Values recovered for the argument registers.
	bool has_value[RUST_MAX_CALL_ARGS];
	ut64 count; ///< Number of argument registers in use.
} RustCallSeed;

typedef struct rust_known_vtable_t {
	ut64 addr; ///< Vtable base address.
	RzVector /*<RustKnownMethod>*/ *methods; ///< Owned recovered methods.
} RustKnownVTable;

typedef struct rust_known_method_t {
	ut64 addr; ///< Method target address.
	ut64 offset;
	char *name; ///<  analysis method name.
	char *real_name;
	bool is_type_id;
	RustKnownVTable *vtable; ///< Borrowed parent vtable.
} RustKnownMethod;

typedef struct rust_vtable_index_t {
	RzVector /*<RustKnownVTable>*/ *vtables;
	HtUP *by_addr;
} RustVTableIndex;

static void rust_any_vtable_fini(void *e, void *user) {
	RustAnyVTable *vtable = e;
	RZ_FREE(vtable->concrete_type);
}

static bool addr_is_executable(RzCore *core, ut64 addr) {
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	if (!obj) {
		return false;
	}
	RzBinSection *section = rz_bin_get_section_at(obj, addr, true);
	return section && (section->perm & RZ_PERM_X);
}

static RZ_OWN ut8 *read_mapped_range(RzCore *core, ut64 start, ut64 end) {
	if (end <= start) {
		return NULL;
	}
	ut8 *bytes = malloc(end - start);
	if (!bytes) {
		return NULL;
	}
	if (!rz_io_read_at_mapped(core->io, start, bytes, end - start)) {
		RZ_FREE(bytes);
		return NULL;
	}
	return bytes;
}

static bool is_any_trait_name(const char *trait_name) {
	if (RZ_STR_ISEMPTY(trait_name)) {
		return false;
	}

	return (rz_str_startswith(trait_name, "core") || rz_str_startswith(trait_name, "std")) &&
		(rz_str_endswith(trait_name, "any::Any") || rz_str_endswith(trait_name, "any::Any_"));
}

static const char *rust_trait_name_from_class_name(const char *class_name) {
	if (RZ_STR_ISEMPTY(class_name)) {
		return NULL;
	}
	if (rz_str_startswith(class_name, "impl ")) {
		const char *as = rz_str_rstr(class_name, " as ");
		if (!as) {
			return NULL;
		}
		const char *trait_name = as + strlen(" as ");
		if (RZ_STR_ISNOTEMPTY(trait_name)) {
			return trait_name;
		}
		return NULL;
	}

	const char *as = rz_str_rstr(class_name, "_as_");
	if (!as || as == class_name) {
		return NULL;
	}
	const char *trait_name = as + strlen("_as_");
	if (RZ_STR_ISNOTEMPTY(trait_name)) {
		return trait_name;
	}
	return NULL;
}

static RZ_OWN char *concrete_type(const char *class_name) {
	if (rz_str_startswith(class_name, "impl ")) {
		const char *impl_type = class_name + strlen("impl ");
		const char *as = rz_str_rstr(class_name, " as ");
		if (as > impl_type) {
			return rz_str_ndup(impl_type, (as - impl_type));
		}
		return NULL;
	}

	const char *as = rz_str_rstr(class_name, "_as_");
	if (as > class_name) {
		return rz_str_ndup(class_name, (as - class_name));
	}
	return NULL;
}

static bool method_name_is_type_id(const char *name, const char *real_name) {
	if (rz_str_startswith(name, "type_id") || rz_str_startswith(name, "get_type_id")) {
		return true;
	}
	return real_name && (strstr(real_name, "::type_id") || strstr(real_name, "::get_type_id"));
}

static void rust_known_method_fini(void *e, void *user) {
	RustKnownMethod *method = e;
	RZ_FREE(method->name);
	RZ_FREE(method->real_name);
}

static void rust_known_vtable_fini(void *e, void *user) {
	RustKnownVTable *vtable = e;
	rz_vector_free(vtable->methods);
}

static RzAnalysisMethod *rust_any_type_id_method(RzVector /*<RzAnalysisMethod>*/ *methods);
static void push_any_vtable_from_class(RzCore *core, RzVector /*<RustAnyVTable>*/ *any_vtables, const char *class_name, RzAnalysisVTable *vtable, RzAnalysisMethod *type_id_method);

static RZ_OWN RustVTableIndex *rust_vtable_index_new(RzCore *core, RzVector /*<RustAnyVTable>*/ *any_vtables) {
	RzPVector *classes = rz_analysis_class_get_all(core->analysis, false);
	if (!classes) {
		return NULL;
	}

	RustVTableIndex *index = RZ_NEW(RustVTableIndex);
	if (!index) {
		rz_pvector_free(classes);
		return NULL;
	}
	index->vtables = rz_vector_new(sizeof(RustKnownVTable), rust_known_vtable_fini, NULL);
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
		const char *trait_name = rust_trait_name_from_class_name(class_name);
		if (!trait_name) {
			continue;
		}

		RzVector *class_methods = rz_analysis_class_method_get_all(core->analysis, class_name);
		RzAnalysisMethod *type_id_method = is_any_trait_name(trait_name) ? rust_any_type_id_method(class_methods) : NULL;
		RzVector *class_vtables = rz_analysis_class_vtable_get_all(core->analysis, class_name);
		if (!class_vtables) {
			push_any_vtable_from_class(core, any_vtables, class_name, NULL, type_id_method);
			rz_vector_free(class_methods);
			continue;
		}
		if (rz_vector_empty(class_vtables)) {
			push_any_vtable_from_class(core, any_vtables, class_name, NULL, type_id_method);
		}

		RzAnalysisVTable *analysis_vtable;
		rz_vector_foreach (class_vtables, analysis_vtable) {
			push_any_vtable_from_class(core, any_vtables, class_name, analysis_vtable, type_id_method);
			RustKnownVTable vtable = {
				.addr = analysis_vtable->addr,
				.methods = rz_vector_new(sizeof(RustKnownMethod), rust_known_method_fini, NULL),
			};
			if (!vtable.methods) {
				rust_known_vtable_fini(&vtable, NULL);
				continue;
			}

			RzAnalysisMethod *analysis_method;
			rz_vector_foreach (class_methods, analysis_method) {
				RustKnownMethod method = {
					.addr = analysis_method->addr,
					.offset = analysis_method->vtable_offset,
					.name = rz_str_dup(analysis_method->name),
					.real_name = rz_str_dup(analysis_method->real_name),
					.is_type_id = method_name_is_type_id(analysis_method->name, analysis_method->real_name),
				};
				if (!rz_vector_push(vtable.methods, &method)) {
					rust_known_method_fini(&method, NULL);
				}
			}
			if (!rz_vector_push(index->vtables, &vtable)) {
				rust_known_vtable_fini(&vtable, NULL);
			}
		}
		rz_vector_free(class_vtables);
		rz_vector_free(class_methods);
	}
	rz_pvector_free(classes);

	RustKnownVTable *vtable;
	rz_vector_foreach (index->vtables, vtable) {
		ht_up_insert(index->by_addr, vtable->addr, vtable);
		RustKnownMethod *method;
		rz_vector_foreach (vtable->methods, method) {
			method->vtable = vtable;
		}
	}
	return index;
}

static void rust_vtable_index_free(RustVTableIndex *index) {
	if (!index) {
		return;
	}
	ht_up_free(index->by_addr);
	rz_vector_free(index->vtables);
	free(index);
}

static RustKnownVTable *rust_vtable_by_addr(RustVTableIndex *index, ut64 addr) {
	bool found = false;
	if (index) {
		return ht_up_find(index->by_addr, addr, &found);
	}
	return NULL;
}

static RustKnownMethod *rust_method_at_slot(RustKnownVTable *vtable, ut64 slot_addr) {
	if (!vtable || slot_addr < vtable->addr) {
		return NULL;
	}
	ut64 offset = slot_addr - vtable->addr;
	RustKnownMethod *method;
	rz_vector_foreach (vtable->methods, method) {
		if (method->offset == offset) {
			return method;
		}
	}
	return NULL;
}

static void rust_type_id_push_imm(ut64 values[2], ut64 *count, ut64 value) {
	if (value == UT64_MAX || *count >= 2) {
		return;
	}
	for (ut64 i = 0; i < *count; i++) {
		if (values[i] == value) {
			return;
		}
	}
	values[(*count)++] = value;
}

static bool rust_type_id_push_data(RzCore *core, ut64 values[2], ut64 *count, ut64 addr) {
	ut8 buf[RUST_TYPE_ID_BYTES] = { 0 };
	if (!addr || addr == UT64_MAX || !rz_io_read_at_mapped(core->io, addr, buf, sizeof(buf))) {
		return false;
	}

	bool big_endian = rz_asm_is_big_endian_set(core->rasm);
	values[0] = rz_read_ble64(buf, big_endian);
	values[1] = rz_read_ble64(buf + 8, big_endian);
	*count = 2;
	return true;
}

static bool rust_type_id_from_method(RzCore *core, ut64 method_addr, RZ_OUT ut64 *low, RZ_OUT ut64 *high, RZ_OUT bool *has_high) {
	RzAnalysisFunction *function = rz_analysis_get_fcn_in(core->analysis, method_addr, RZ_ANALYSIS_FCN_TYPE_NULL);
	if (!function) {
		return false;
	}

	ut64 start = function->addr;
	ut64 end = rz_analysis_function_max_addr(function);
	if (end <= start) {
		return false;
	}

	ut8 *bytes = read_mapped_range(core, start, end);
	if (!bytes) {
		return false;
	}

	ut64 values[2] = { 0 };
	ut64 count = 0;
	ut64 offset = 0;
	RzAnalysisOp *op = rz_analysis_op_new();
	if (!op) {
		RZ_FREE(bytes);
		return false;
	}

	while (start < end && count < 2) {
		if (rz_analysis_op(core->analysis, op, start, bytes + offset, end - start, RZ_ANALYSIS_OP_MASK_ALL) <= 0 || op->size < 1) {
			break;
		}
		ut32 type = op->type & RZ_ANALYSIS_OP_TYPE_MASK;
		if (op->ptr && op->ptr != UT64_MAX && op->refptr >= RUST_TYPE_ID_BYTES &&
			rust_type_id_push_data(core, values, &count, op->ptr)) {
			rz_analysis_op_fini(op);
			break;
		}
		if (type == RZ_ANALYSIS_OP_TYPE_MOV || type == RZ_ANALYSIS_OP_TYPE_CMOV) {
			if (op->val != UT64_MAX) {
				rust_type_id_push_imm(values, &count, op->val);
			}
			for (ut64 i = 0; i < RZ_ARRAY_SIZE(op->analysis_vals); i++) {
				if (op->analysis_vals[i].imm != ST64_MAX && op->analysis_vals[i].imm) {
					rust_type_id_push_imm(values, &count, op->analysis_vals[i].imm);
				}
			}
		}
		if (type == RZ_ANALYSIS_OP_TYPE_RET) {
			rz_analysis_op_fini(op);
			break;
		}
		start += op->size;
		offset += op->size;
		rz_analysis_op_fini(op);
	}

	rz_analysis_op_free(op);
	RZ_FREE(bytes);
	if (!count) {
		return false;
	}

	*low = values[0];
	*high = 0;
	if (count > 1) {
		*high = values[1];
	}
	*has_high = count > 1;
	return true;
}

static RzAnalysisMethod *rust_any_type_id_method(RzVector /*<RzAnalysisMethod>*/ *methods) {
	if (!methods) {
		return NULL;
	}

	RzAnalysisMethod *method;
	rz_vector_foreach (methods, method) {
		if (method_name_is_type_id(method->name, method->real_name)) {
			return method;
		}
	}
	return NULL;
}

static void push_any_vtable_from_class(RzCore *core, RzVector /*<RustAnyVTable>*/ *any_vtables, const char *class_name, RzAnalysisVTable *vtable, RzAnalysisMethod *type_id_method) {
	if (!any_vtables || !type_id_method || !type_id_method->addr || type_id_method->addr == UT64_MAX ||
		(vtable && (!vtable->addr || vtable->addr == UT64_MAX))) {
		return;
	}

	RustAnyVTable any = {
		.vtable_addr = vtable ? vtable->addr : UT64_MAX,
		.concrete_type = concrete_type(class_name),
	};
	if (!any.concrete_type) {
		return;
	}

	any.has_type_id = rust_type_id_from_method(core, type_id_method->addr, &any.type_id_low, &any.type_id_high, &any.has_type_id_high);
	if (!rz_vector_push(any_vtables, &any)) {
		rust_any_vtable_fini(&any, NULL);
	}
}

static RustAnyVTable *any_vtable_by_addr(RzVector /*<RustAnyVTable>*/ *vtables, ut64 vtable_addr) {
	if (!vtables || !vtable_addr || vtable_addr == UT64_MAX) {
		return NULL;
	}

	RustAnyVTable *any;
	rz_vector_foreach (vtables, any) {
		if (any->vtable_addr == vtable_addr) {
			return any;
		}
	}
	return NULL;
}

static ut64 il_value_to_ut64(RZ_NULLABLE RzILVal *val) {
	if (!val) {
		return UT64_MAX;
	}

	RzBitVector *bv = rz_il_value_to_bv(val);
	if (!bv) {
		return UT64_MAX;
	}

	ut64 ret = rz_bv_to_ut64(bv);
	rz_bv_free(bv);
	return ret;
}

static ut64 get_reg_value(RzAnalysis *analysis, const char *reg_name) {
	if (!reg_name) {
		return UT64_MAX;
	}

	RzAnalysisILVM *vm = rz_analysis_get_il_vm(analysis);
	if (!vm) {
		return UT64_MAX;
	}

	RzILVal *il_reg = rz_il_vm_get_var_value(vm->vm, RZ_IL_VAR_KIND_GLOBAL, reg_name);
	return il_value_to_ut64(il_reg);
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

static bool analysis_value_is_mem(RzAnalysisValue *value) {
	return value && value->memref > 0;
}

static bool analysis_value_addr(RzCore *core, RZ_NULLABLE const RzAnalysisOp *op, RzAnalysisValue *value, RZ_OUT ut64 *addr) {
	if (!analysis_value_is_mem(value)) {
		return false;
	}

	ut64 result = value->base;
	const char *base_reg = NULL;
	if (value->reg) {
		base_reg = value->reg->name;
	}
	if (base_reg) {
		ut64 base = UT64_MAX;
		const char *pc = NULL;
		RzReg *reg = rz_analysis_get_reg(core->analysis);
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
		if (index == UT64_MAX) {
			return false;
		}
		ut64 scale = value->mul;
		if (!scale) {
			scale = 1;
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
	if (!analysis_value_is_mem(value)) {
		return true;
	}

	ut64 addr = UT64_MAX;
	if (!analysis_value_addr(core, op, value, &addr)) {
		return false;
	}

	ut64 access_size = value->memref;
	if (access_size && addr >= RUST_TRACK_MEM_ADDR) {
		ut64 offset = addr - RUST_TRACK_MEM_ADDR;
		if (offset < RUST_TRACK_MEM_SIZE && access_size <= RUST_TRACK_MEM_SIZE - offset) {
			return true;
		}
	}

	if (write || !rz_io_is_valid_offset(core->io, addr, RZ_PERM_R)) {
		return false;
	}

	RzBinObject *obj = rz_bin_cur_object(core->bin);
	RzBinSection *section = NULL;
	if (obj) {
		section = rz_bin_get_section_at(obj, addr, true);
	}
	return section && !(section->perm & RZ_PERM_X);
}

static bool op_memory_access_is_safe(RzCore *core, RzAnalysisOp *op) {
	if ((op->type & RZ_ANALYSIS_OP_TYPE_MASK) == RZ_ANALYSIS_OP_TYPE_LEA) {
		return true;
	}
	if (op->dst && analysis_value_is_mem(op->dst) && !value_mem_access_is_safe(core, op, op->dst, true)) {
		return false;
	}

	for (ut64 i = 0; i < RZ_ARRAY_SIZE(op->src); i++) {
		if (op->src[i] && analysis_value_is_mem(op->src[i]) &&
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

static void get_arg_regs(RzCore *core, RZ_OUT RustCallSeed *args) {
	const char *cc = rz_analysis_cc_default(core->analysis);
	for (ut64 i = 0; i < RUST_MAX_CALL_ARGS; i++) {
		const char *reg = rz_analysis_cc_arg(core->analysis, cc, i);
		if (!is_valid_reg(core, reg)) {
			break;
		}
		args->regs[args->count++] = reg;
	}
}

static bool seed_contains_rust_vtable(RustVTableIndex *vtable_index, RustCallSeed *seed) {
	for (ut64 i = 0; i < seed->count; i++) {
		if (seed->has_value[i] && rust_vtable_by_addr(vtable_index, seed->values[i])) {
			return true;
		}
	}
	return false;
}

static bool seed_equal(RustCallSeed *a, RustCallSeed *b) {
	if (a->count != b->count) {
		return false;
	}

	for (ut64 i = 0; i < a->count; i++) {
		if (a->has_value[i] != b->has_value[i] ||
			(a->has_value[i] && a->values[i] != b->values[i])) {
			return false;
		}
	}
	return true;
}

static void push_unique_seed(RustVTableIndex *vtable_index, RzVector /*<RustCallSeed>*/ *seeds, RustCallSeed *seed) {
	if (!seed_contains_rust_vtable(vtable_index, seed)) {
		return;
	}

	RustCallSeed *it;
	rz_vector_foreach (seeds, it) {
		if (seed_equal(it, seed)) {
			return;
		}
	}
	rz_vector_push(seeds, seed);
}

static bool op_is_vtable_slot_dispatch(RzCore *core, RzAnalysisOp *op) {
	return is_valid_reg(core, op->reg) &&
		(op->type & (RZ_ANALYSIS_OP_TYPE_IND | RZ_ANALYSIS_OP_TYPE_MEM)) &&
		(rz_analysis_op_is_call(op) || rz_analysis_op_is_eob(op));
}

static bool op_is_register_target_dispatch(RzCore *core, RzAnalysisOp *op) {
	return is_valid_reg(core, op->reg) && (op->type & RZ_ANALYSIS_OP_TYPE_REG) &&
		!(op->type & (RZ_ANALYSIS_OP_TYPE_IND | RZ_ANALYSIS_OP_TYPE_MEM)) &&
		(rz_analysis_op_is_call(op) || rz_analysis_op_is_eob(op));
}

static void track_init(RzCore *core, RZ_NULLABLE const RustCallSeed *seed) {
	rz_core_analysis_esil_init_mem(core, NULL, RUST_TRACK_MEM_ADDR, RUST_TRACK_MEM_SIZE);
	rz_core_analysis_il_reinit(core);

	if (rz_asm_is_arch(core->rasm, "x86")) {
		rz_analysis_il_vm_set_unsigned(core->analysis, "rbp", RUST_STACK_PTR);
		rz_analysis_il_vm_set_unsigned(core->analysis, "rsp", RUST_STACK_PTR);
	} else if (rz_asm_is_arch(core->rasm, "arm")) {
		rz_analysis_il_vm_set_unsigned(core->analysis, "x29", RUST_STACK_PTR);
		rz_analysis_il_vm_set_unsigned(core->analysis, "sp", RUST_STACK_PTR);
	} else {
		const char *arch = rz_core_get_arch(core);
		RZ_LOG_WARN("arch %s is not supported\n", arch);
	}

	if (!seed) {
		return;
	}

	for (ut64 i = 0; i < seed->count; i++) {
		if (seed->has_value[i]) {
			rz_analysis_il_vm_set_unsigned(core->analysis, seed->regs[i], seed->values[i]);
		}
	}
}

static void track_fini(RzCore *core) {
	rz_core_analysis_il_reinit(core);
	rz_core_analysis_esil_init_mem_del(core, NULL, RUST_TRACK_MEM_ADDR, RUST_TRACK_MEM_SIZE);
}

static void add_virtual_xrefs(RzAnalysis *analysis, const char *method_name, ut64 addr) {
	bool found = false;
	HtSP *ht_virtual_xrefs = rz_analysis_get_virtual_xrefs(analysis);
	if (!ht_virtual_xrefs) {
		return;
	}

	RzSetU *set = ht_sp_find(ht_virtual_xrefs, method_name, &found);
	if (!found) {
		set = rz_set_u_new();
		if (!set) {
			return;
		}
		if (!ht_sp_insert(ht_virtual_xrefs, method_name, set)) {
			rz_set_u_free(set);
			return;
		}
	}
	if (!set) {
		return;
	}
	rz_set_u_add(set, addr);
}

static void add_virtual_xrefs_for_method(RzCore *core, const char *method_name, ut64 method_addr, ut64 xref_addr) {
	add_virtual_xrefs(core->analysis, method_name, xref_addr);
	const RzList *flags = rz_flag_get_list(core->flags, method_addr);
	RzListIter *it;
	RzFlagItem *flag;
	rz_list_foreach (flags, it, flag) {
		if (RZ_STR_ISNOTEMPTY(flag->name) && strcmp(flag->name, method_name)) {
			add_virtual_xrefs(core->analysis, flag->name, xref_addr);
		}
	}
}

static void rust_virtual_calls_add(RzCore *core, HtUP *calls, ut64 call_addr, RustKnownMethod *method) {
	if (!calls || !method) {
		return;
	}
	const char *method_name = RZ_STR_ISNOTEMPTY(method->real_name) ? method->real_name : method->name;
	if (RZ_STR_ISEMPTY(method_name)) {
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
	rz_set_s_add(set, method_name);
	add_virtual_xrefs_for_method(core, method_name, method->addr, call_addr);
}

typedef struct rust_comment_context_t {
	RzStrBuf *text;
	bool first;
} RustCommentContext;

static bool rust_virtual_comment_add_name(void *user, const char *name, RZ_UNUSED const void *value) {
	RustCommentContext *ctx = user;
	if (ctx->first) {
		rz_strbuf_setf(ctx->text, "Rust Virtual Call: %s", name);
		ctx->first = false;
	} else {
		rz_strbuf_appendf(ctx->text, " / %s", name);
	}
	return true;
}

static bool rust_virtual_comment_emit(void *user, const ut64 addr, const void *value) {
	RzCore *core = user;
	RzSetS *set = (RzSetS *)value;
	RzStrBuf *text = rz_strbuf_new(NULL);
	if (!text) {
		return true;
	}
	RustCommentContext ctx = { text, true };
	ht_sp_foreach((HtSP *)set, rust_virtual_comment_add_name, &ctx);
	char *comment = rz_strbuf_drain(text);
	if (RZ_STR_ISNOTEMPTY(comment)) {
		rz_core_meta_comment_add(core, comment, addr);
	}
	free(comment);
	return true;
}

static bool rust_virtual_call_set_free(void *user, const ut64 addr, const void *value) {
	rz_set_s_free((RzSetS *)value);
	return true;
}

static void rust_virtual_calls_fini(RzCore *core, HtUP *calls) {
	if (!calls) {
		return;
	}
	ht_up_foreach(calls, rust_virtual_comment_emit, core);
	ht_up_foreach(calls, rust_virtual_call_set_free, NULL);
	ht_up_free(calls);
}

static bool type_id_equal(RzCore *core, ut64 addr, ut64 low, ut64 high, bool has_high) {
	ut8 buf[RUST_TYPE_ID_BYTES] = { 0 };
	if (!addr || addr == UT64_MAX || !rz_io_read_at_mapped(core->io, addr, buf, sizeof(buf))) {
		return false;
	}

	bool big_endian = rz_asm_is_big_endian_set(core->rasm);
	ut64 data_low = rz_read_ble64(buf, big_endian);
	ut64 data_high = rz_read_ble64(buf + 8, big_endian);
	if (has_high) {
		return data_low == low && data_high == high;
	}
	return data_low == low || data_high == low;
}

static bool op_mem_value_has_type_id(RzCore *core, RzAnalysisOp *op, RzAnalysisValue *value, ut64 low, ut64 high, bool has_high) {
	if (!analysis_value_is_mem(value) || value->memref < RUST_TYPE_ID_BYTES) {
		return false;
	}

	ut64 addr = UT64_MAX;
	return analysis_value_addr(core, op, value, &addr) && type_id_equal(core, addr, low, high, has_high);
}

static bool op_has_scalar_imm(RzAnalysisOp *op, ut64 value) {
	if (op->val != UT64_MAX && op->val == value) {
		return true;
	}

	for (ut64 i = 0; i < RZ_ARRAY_SIZE(op->analysis_vals); i++) {
		if (op->analysis_vals[i].imm != ST64_MAX && op->analysis_vals[i].imm == value) {
			return true;
		}
	}
	return false;
}

static bool op_has_type_id(RzCore *core, RzAnalysisOp *op, ut64 low, ut64 high, bool has_high) {
	if (op->ptr && op->ptr != UT64_MAX && op->refptr >= RUST_TYPE_ID_BYTES &&
		type_id_equal(core, op->ptr, low, high, has_high)) {
		return true;
	}

	for (ut64 i = 0; i < RZ_ARRAY_SIZE(op->src); i++) {
		if (op_mem_value_has_type_id(core, op, op->src[i], low, high, has_high)) {
			return true;
		}
	}
	if (op_mem_value_has_type_id(core, op, op->dst, low, high, has_high)) {
		return true;
	}

	return op_has_scalar_imm(op, low) || (has_high && op_has_scalar_imm(op, high));
}

static bool annotate_any_type_id_compare(RzCore *core, RzAnalysisOp *op, RzVector /*<RustAnyVTable>*/ *any_vtables, RZ_NULLABLE RustAnyVTable *pending_any) {
	ut32 type = op->type & RZ_ANALYSIS_OP_TYPE_MASK;
	if (type != RZ_ANALYSIS_OP_TYPE_CMP && type != RZ_ANALYSIS_OP_TYPE_ACMP) {
		return false;
	}

	RustAnyVTable *matched = NULL;
	if (pending_any && pending_any->has_type_id &&
		op_has_type_id(core, op, pending_any->type_id_low, pending_any->type_id_high, pending_any->has_type_id_high)) {
		matched = pending_any;
	}
	if (!matched && any_vtables) {
		RustAnyVTable *any;
		rz_vector_foreach (any_vtables, any) {
			if (any->has_type_id && op_has_type_id(core, op, any->type_id_low, any->type_id_high, any->has_type_id_high)) {
				matched = any;
				break;
			}
		}
	}
	if (matched) {
		char *comment = rz_str_newf("Any downcast: %s", matched->concrete_type);
		if (comment) {
			rz_core_meta_comment_add(core, comment, op->addr);
			free(comment);
		}
	}
	return true;
}

static RZ_NULLABLE RustAnyVTable *devirtualize_step(RzCore *core, RzAnalysisOp *op, RustVTableIndex *vtable_index, HtUP *virtual_calls, RzVector /*<RustAnyVTable>*/ *any_vtables, RZ_NULLABLE const RustCallSeed *seed) {
	RustKnownMethod *method = NULL;
	ut64 vtable_addr = UT64_MAX;

	if (op_is_vtable_slot_dispatch(core, op)) {
		vtable_addr = get_reg_value(core->analysis, op->reg);
		RustKnownVTable *vtable = rust_vtable_by_addr(vtable_index, vtable_addr);
		if (!vtable) {
			return NULL;
		}

		ut64 slot_addr = vtable_addr + op->disp;
		if (slot_addr < vtable_addr) {
			return NULL;
		}
		if (is_valid_reg(core, op->ireg)) {
			ut64 index = get_reg_value(core->analysis, op->ireg);
			if (index == UT64_MAX) {
				return NULL;
			}

			ut64 scale;
			if (op->scale) {
				scale = op->scale;
			} else {
				scale = 1;
			}

			ut64 indexed = index * scale;
			if (slot_addr + indexed < slot_addr) {
				return NULL;
			}
			slot_addr += indexed;
		}
		method = rust_method_at_slot(vtable, slot_addr);
	} else if (op_is_register_target_dispatch(core, op)) {
		ut64 target = get_reg_value(core->analysis, op->reg);
		if (seed && target && target != UT64_MAX) {
			for (ut64 i = 0; i < seed->count && !method; i++) {
				if (!seed->has_value[i]) {
					continue;
				}
				RustKnownVTable *seed_vtable = rust_vtable_by_addr(vtable_index, seed->values[i]);
				if (!seed_vtable) {
					continue;
				}
				RustKnownMethod *candidate;
				rz_vector_foreach (seed_vtable->methods, candidate) {
					if (candidate->addr == target) {
						method = candidate;
						break;
					}
				}
			}
		}
		if (method) {
			vtable_addr = method->vtable->addr;
		}
	}

	if (!method || !method->addr || method->addr == UT64_MAX || !addr_is_executable(core, method->addr)) {
		return NULL;
	}

	RustAnyVTable *any = any_vtable_by_addr(any_vtables, vtable_addr);
	if (any && method->is_type_id) {
		char *comment = rz_str_newf("Any::type_id: %s", any->concrete_type);
		if (comment) {
			rz_core_meta_comment_add(core, comment, op->addr);
			free(comment);
		}
		add_virtual_xrefs_for_method(core,
			RZ_STR_ISNOTEMPTY(method->real_name) ? method->real_name : method->name,
			method->addr, op->addr);
		return any;
	}

	rust_virtual_calls_add(core, virtual_calls, op->addr, method);
	return NULL;
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

static void devirtualize_rust_function(RzCore *core, RzAnalysisFunction *function, RustVTableIndex *vtable_index, RzVector /*<RustAnyVTable>*/ *any_vtables, RZ_NULLABLE const RustCallSeed *seed, HtUP *virtual_calls) {
	ut64 start = function->addr;
	ut64 end = rz_analysis_function_max_addr(function);
	if (!addr_is_executable(core, start)) {
		return;
	}

	RzAnalysisOp *op = rz_analysis_op_new();
	if (!op) {
		return;
	}

	ut8 *bytes = read_mapped_range(core, start, end);
	if (!bytes) {
		RZ_LOG_ERROR("Cannot read at offset 0x%08" PFMT64x "\n", start);
		rz_analysis_op_free(op);
		return;
	}

	ut64 old_offset = core->offset;
	ut64 offset = 0;
	core->offset = start;
	track_init(core, seed);
	RustAnyVTable *pending_any = NULL;
	while (start < end) {
		if (rz_analysis_op(core->analysis, op, start, bytes + offset, end - start, RZ_ANALYSIS_OP_MASK_ALL) <= 0 || op->size < 1) {
			break;
		}

		RustAnyVTable *called_any = devirtualize_step(core, op, vtable_index, virtual_calls, any_vtables, seed);
		if (called_any) {
			pending_any = called_any;
		}
		if (annotate_any_type_id_compare(core, op, any_vtables, pending_any)) {
			pending_any = NULL;
		}
		ut64 next = start + op->size;
		if (rz_analysis_op_is_eob(op) || rz_analysis_op_is_call(op)) {
			advance_il_pc(core, next);
		} else {
			track_step_or_skip(core, op, next);
		}

		start = next;
		offset += op->size;
		core->offset = start;
		rz_analysis_op_fini(op);
	}

	core->offset = old_offset;
	track_fini(core);
	rz_analysis_op_free(op);
	RZ_FREE(bytes);
}

static void caller_replay_step(RzCore *core, RzAnalysisOp *op, ut64 next_addr, const char *ret_reg) {
	if (rz_analysis_op_is_call(op)) {
		if (is_valid_reg(core, ret_reg)) {
			rz_analysis_il_vm_set_unsigned(core->analysis, ret_reg, 0);
		}
		advance_il_pc(core, next_addr);
		return;
	}

	if (rz_analysis_op_is_eob(op)) {
		advance_il_pc(core, next_addr);
		return;
	}

	track_step_or_skip(core, op, next_addr);
}

static void collect_caller_args_from_site(RzCore *core, RzAnalysisFunction *caller, ut64 call_addr, RustVTableIndex *vtable_index, const RustCallSeed *args, RzVector /*<RustCallSeed>*/ *seeds) {
	ut64 start = caller->addr;
	ut64 end = RZ_MIN(call_addr, rz_analysis_function_max_addr(caller));
	if (!addr_is_executable(core, start)) {
		return;
	}

	ut8 *bytes = read_mapped_range(core, start, end);
	if (!bytes) {
		return;
	}

	RzAnalysisOp *op = rz_analysis_op_new();
	if (!op) {
		RZ_FREE(bytes);
		return;
	}

	RustCallSeed seed = *args;

	const char *cc = rz_analysis_cc_default(core->analysis);
	const char *ret_reg = rz_analysis_cc_ret(core->analysis, cc);
	ut64 old_offset = core->offset;
	ut64 offset = 0;
	core->offset = start;
	track_init(core, NULL);
	while (start < end) {
		if (rz_analysis_op(core->analysis, op, start, bytes + offset, end - start, RZ_ANALYSIS_OP_MASK_ALL) <= 0 || op->size < 1) {
			break;
		}

		ut64 next = start + op->size;
		caller_replay_step(core, op, next, ret_reg);
		start = next;
		offset += op->size;
		core->offset = start;
		rz_analysis_op_fini(op);
	}

	for (ut64 i = 0; i < args->count; i++) {
		ut64 value = get_reg_value(core->analysis, args->regs[i]);
		if (value && value != UT64_MAX) {
			seed.values[i] = value;
			seed.has_value[i] = true;
		}
	}

	push_unique_seed(vtable_index, seeds, &seed);
	core->offset = old_offset;
	track_fini(core);
	rz_analysis_op_free(op);
	RZ_FREE(bytes);
}

static RZ_OWN RzVector /*<RustCallSeed>*/ *collect_caller_args(RzCore *core, RzAnalysisFunction *function, RustVTableIndex *vtable_index, const RustCallSeed *args) {
	RzVector *seeds = rz_vector_new(sizeof(RustCallSeed), NULL, NULL);
	if (!seeds) {
		return NULL;
	}

	RzList *xrefs = rz_analysis_xrefs_get_to(core->analysis, function->addr);
	if (!xrefs) {
		rz_vector_free(seeds);
		return NULL;
	}

	RzListIter *it;
	RzAnalysisXRef *xref;
	rz_list_foreach (xrefs, it, xref) {
		if (xref->type != RZ_ANALYSIS_XREF_TYPE_CALL && xref->type != RZ_ANALYSIS_XREF_TYPE_CODE) {
			continue;
		}
		RzAnalysisFunction *caller = rz_analysis_get_fcn_in(core->analysis, xref->from, RZ_ANALYSIS_FCN_TYPE_NULL);
		if (!caller) {
			continue;
		}
		collect_caller_args_from_site(core, caller, xref->from, vtable_index, args, seeds);
	}

	rz_list_free(xrefs);
	if (rz_vector_empty(seeds)) {
		rz_vector_free(seeds);
		return NULL;
	}
	return seeds;
}

static void devirtualize_rust_trait_object(RzCore *core) {
	RzAnalysisFunction *function = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_NULL);
	if (!function) {
		RZ_LOG_ERROR("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
		return;
	}

	RzVector *any_vtables = rz_vector_new(sizeof(RustAnyVTable), rust_any_vtable_fini, NULL);
	RustVTableIndex *vtable_index = rust_vtable_index_new(core, any_vtables);
	if (!vtable_index) {
		rz_vector_free(any_vtables);
		return;
	}
	RustCallSeed args = { 0 };
	get_arg_regs(core, &args);
	RzVector *seeds = NULL;
	if (args.count) {
		seeds = collect_caller_args(core, function, vtable_index, &args);
	}

	HtUP *virtual_calls = ht_up_new(NULL, NULL);
	devirtualize_rust_function(core, function, vtable_index, any_vtables, NULL, virtual_calls);

	RustCallSeed *seed;
	if (seeds) {
		rz_vector_foreach (seeds, seed) {
			devirtualize_rust_function(core, function, vtable_index, any_vtables, seed, virtual_calls);
		}
	}

	rust_virtual_calls_fini(core, virtual_calls);
	rz_vector_free(seeds);
	rz_vector_free(any_vtables);
	rust_vtable_index_free(vtable_index);
}

/**
 * \brief devirtualize Rust trait object calls in the current function
 */
RZ_IPI void rz_core_analysis_devirtualize_rust_methods(RZ_NULLABLE RzCore *core) {
	if (!core) {
		return;
	}
	devirtualize_rust_trait_object(core);
}
