// SPDX-FileCopyrightText: 2026 historicattle <sirigere.naren@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_core.h>
#include "core_private.h"

#define SWIFT_MAX_CALL_ARGS   9
#define SWIFT_MAX_ARG_SLOTS   8
#define SWIFT_TABLE_SCAN_SIZE 0x400
#define SWIFT_TRACK_MEM_ADDR  0x10000000
#define SWIFT_TRACK_MEM_SIZE  0x50000
#define SWIFT_STACK_PTR       (SWIFT_TRACK_MEM_ADDR + (SWIFT_TRACK_MEM_SIZE / 2))
#define SWIFT_OBJECT_ADDR     (SWIFT_TRACK_MEM_ADDR + 0x30000)
#define SWIFT_OBJECT_SIZE     0x100

/**
 * \brief Method target and offset in a Swift dispatch table.
 */
typedef struct swift_known_method_t {
	ut64 addr;
	ut64 offset;
	char *name;
} SwiftKnownMethod;

/**
 * \brief Swift class metadata or protocol witness table.
 */
typedef struct swift_known_table_t {
	ut64 addr;
	ut64 size;
	bool witness;
	char *symbol_name;
	char *raw_name;
	RzVector *methods;
} SwiftKnownTable;

/**
 * \brief Swift dispatch tables and function indexes.
 */
typedef struct swift_table_index_t {
	RzVector *tables;
	HtUP *by_addr;
	HtUU *metadata_accessors;
	HtUU *constructors;
} SwiftTableIndex;

/**
 * \brief Dispatch table pointer in a caller argument.
 */
typedef struct swift_seed_slot_t {
	ut64 offset;
	ut64 table;
} SwiftSeedSlot;

/**
 * \brief Caller argument used for dispatch replay.
 */
typedef struct swift_seed_arg_t {
	bool direct;
	ut64 slot_count;
	SwiftSeedSlot slots[SWIFT_MAX_ARG_SLOTS];
} SwiftSeedArg;

/**
 * \brief Caller register state used for dispatch replay.
 */
typedef struct swift_call_seed_t {
	const char *regs[SWIFT_MAX_CALL_ARGS];
	SwiftSeedArg args[SWIFT_MAX_CALL_ARGS];
	ut64 count;
} SwiftCallSeed;

/**
 * \brief Resolved methods for a call site.
 */
typedef struct swift_call_site_t {
	RzSetS *methods;
	bool witness;
} SwiftCallSite;

static ut64 ptr_size(RzCore *core) {
	if (rz_asm_get_bits(core->rasm) == 64) {
		return 8;
	}
	return 4;
}

static bool read_ptr(RzCore *core, ut64 addr, RZ_OUT ut64 *value) {
	return rz_io_read_i(core->io, addr, value, ptr_size(core), rz_asm_is_big_endian_set(core->rasm));
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
	if (end <= start || end - start > SIZE_MAX) {
		return NULL;
	}
	ut8 *bytes = malloc(end - start);
	if (!bytes) {
		return NULL;
	}
	if (!rz_io_read_at_mapped(core->io, start, bytes, end - start)) {
		RZ_FREE(bytes);
	}
	return bytes;
}

static void known_method_fini(void *element, RZ_UNUSED void *user) {
	SwiftKnownMethod *method = element;
	RZ_FREE(method->name);
}

static void known_table_fini(void *element, RZ_UNUSED void *user) {
	SwiftKnownTable *table = element;
	RZ_FREE(table->symbol_name);
	RZ_FREE(table->raw_name);
	rz_vector_free(table->methods);
}

static bool has_objc_thunk(RzCore *core) {
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	const RzPVector *symbols = NULL;
	if (obj) {
		symbols = rz_bin_object_get_symbols(obj);
	}
	if (!symbols) {
		return false;
	}
	void **iter;
	rz_pvector_foreach (symbols, iter) {
		RzBinSymbol *symbol = *iter;
		if (!symbol) {
			continue;
		}
		if (RZ_STR_ISNOTEMPTY(symbol->dname) && strstr(symbol->dname, "@objc")) {
			return true;
		}
	}
	return false;
}

static void add_method(RzCore *core, SwiftKnownTable *table, ut64 addr, ut64 offset, const char *name) {
	if (RZ_STR_ISEMPTY(name)) {
		RzBinObject *obj = rz_bin_cur_object(core->bin);
		RzBinSymbol *symbol = NULL;
		if (obj) {
			symbol = rz_bin_object_get_symbol_at(obj, addr, true);
		}
		if (symbol) {
			name = symbol->dname;
		}
	}
	char *method_name;
	if (RZ_STR_ISNOTEMPTY(name)) {
		method_name = rz_str_dup(name);
	} else {
		method_name = rz_str_newf("0x%" PFMT64x, addr);
	}
	SwiftKnownMethod method = {
		.addr = addr,
		.offset = offset,
		.name = method_name,
	};
	if (!method.name || !rz_vector_push(table->methods, &method)) {
		known_method_fini(&method, NULL);
	}
}

static void scan_table(RzCore *core, SwiftKnownTable *table, RzVector *tables) {
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	RzBinSection *section = NULL;
	if (obj) {
		section = rz_bin_get_section_at(obj, table->addr, true);
	}
	if (!section || !(section->perm & RZ_PERM_R) || section->vaddr > table->addr ||
		table->addr - section->vaddr >= section->vsize) {
		return;
	}
	ut64 size = section->vsize - (table->addr - section->vaddr);
	ut64 table_size = SWIFT_TABLE_SCAN_SIZE;
	if (table->size) {
		table_size = table->size;
	}
	size = RZ_MIN(size, table_size);
	SwiftKnownTable *next;
	rz_vector_foreach (tables, next) {
		if (next->addr > table->addr) {
			size = RZ_MIN(size, next->addr - table->addr);
		}
	}
	ut64 psize = ptr_size(core);
	ut64 first = 0;
	if (table->witness && table->raw_name && !rz_str_startswith(table->raw_name, "__TWP")) {
		first = psize;
	}
	const RzPVector *symbols = NULL;
	if (obj) {
		symbols = rz_bin_object_get_symbols(obj);
	}
	void **iter;
	rz_pvector_foreach (symbols, iter) {
		RzBinSymbol *symbol = *iter;
		if (symbol && symbol->vaddr > table->addr) {
			size = RZ_MIN(size, symbol->vaddr - table->addr);
		}
	}
	for (ut64 offset = first; offset + psize <= size; offset += psize) {
		ut64 target;
		if (offset > UT64_MAX - table->addr || !read_ptr(core, table->addr + offset, &target) ||
			!target || !addr_is_executable(core, target)) {
			continue;
		}
		add_method(core, table, target, offset, NULL);
	}
}

static SwiftKnownTable *add_table(RzVector *tables, ut64 addr, bool witness, const char *name, const char *raw_name) {
	if (!addr || addr == UT64_MAX) {
		return NULL;
	}
	SwiftKnownTable *existing;
	rz_vector_foreach (tables, existing) {
		if (existing->addr == addr) {
			if (!existing->raw_name) {
				existing->raw_name = rz_str_dup(raw_name);
			}
			if (RZ_STR_ISNOTEMPTY(name)) {
				char *copy = rz_str_dup(name);
				if (copy) {
					free(existing->symbol_name);
					existing->symbol_name = copy;
				}
			}
			existing->witness |= witness;
			return existing;
		}
	}
	SwiftKnownTable table = {
		.addr = addr,
		.witness = witness,
		.symbol_name = rz_str_dup(name),
		.raw_name = rz_str_dup(raw_name),
		.methods = rz_vector_new(sizeof(SwiftKnownMethod), known_method_fini, NULL),
	};
	SwiftKnownTable *result = NULL;
	if (table.methods) {
		result = rz_vector_push(tables, &table);
	}
	if (!result) {
		known_table_fini(&table, NULL);
	}
	return result;
}

static void add_analysis_vtables(RzCore *core, RzVector *tables) {
	RzPVector *classes = rz_analysis_class_get_all(core->analysis, false);
	void **iter;
	rz_pvector_foreach (classes, iter) {
		SdbKv *kv = *iter;
		RzVector *vtables = rz_analysis_class_vtable_get_all(core->analysis, sdbkv_key(kv));
		RzVector *methods = rz_analysis_class_method_get_all(core->analysis, sdbkv_key(kv));
		RzAnalysisVTable *vtable;
		rz_vector_foreach (vtables, vtable) {
			SwiftKnownTable *table = add_table(tables, vtable->addr, false, sdbkv_key(kv), NULL);
			if (!table || !rz_vector_empty(table->methods)) {
				continue;
			}
			table->size = vtable->size;
			RzAnalysisMethod *method;
			rz_vector_foreach (methods, method) {
				ut64 offset = method->vtable_offset;
				ut64 target;
				ut64 psize = ptr_size(core);
				if (method->vtable_offset < 0 || offset % psize || offset > UT64_MAX - table->addr ||
					(table->size && (offset >= table->size || psize > table->size - offset)) ||
					!read_ptr(core, table->addr + offset, &target) || target != method->addr || !addr_is_executable(core, target)) {
					continue;
				}
				const char *name = method->name;
				if (RZ_STR_ISNOTEMPTY(method->real_name)) {
					name = method->real_name;
				}
				add_method(core, table, target, offset, name);
			}
		}
		rz_vector_free(methods);
		rz_vector_free(vtables);
	}
	rz_pvector_free(classes);
}

static SwiftKnownTable *table_for_class_name(SwiftTableIndex *index, const char *name) {
	SwiftKnownTable *result = NULL;
	SwiftKnownTable *table;
	rz_vector_foreach (index->tables, table) {
		const char *class_name = table->symbol_name;
		if (table->witness || RZ_STR_ISEMPTY(class_name)) {
			continue;
		}
		if (rz_str_startswith(class_name, "type metadata for ")) {
			class_name += strlen("type metadata for ");
		}
		if (!strcmp(class_name, name)) {
			if (result) {
				return NULL;
			}
			result = table;
		}
	}
	return result;
}

static void build_function_maps(RzCore *core, SwiftTableIndex *index) {
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	const RzPVector *symbols = NULL;
	if (obj) {
		symbols = rz_bin_object_get_symbols(obj);
	}
	if (!symbols) {
		return;
	}
	void **iter;
	rz_pvector_foreach (symbols, iter) {
		RzBinSymbol *symbol = *iter;
		if (!symbol || !addr_is_executable(core, symbol->vaddr)) {
			continue;
		}
		const char *display = symbol->dname;
		SwiftKnownTable *table = NULL;
		if (RZ_STR_ISNOTEMPTY(display)) {
			if (rz_str_startswith(display, "type metadata accessor for ")) {
				table = table_for_class_name(index, display + strlen("type metadata accessor for "));
				if (table) {
					ht_uu_insert(index->metadata_accessors, symbol->vaddr, table->addr);
				}
			} else if (strstr(display, "allocating init")) {
				rz_vector_foreach (index->tables, table) {
					const char *class_name = table->symbol_name;
					if (table->witness || RZ_STR_ISEMPTY(class_name)) {
						continue;
					}
					if (rz_str_startswith(class_name, "type metadata for ")) {
						class_name += strlen("type metadata for ");
					}
					if (strstr(display, class_name)) {
						ht_uu_insert(index->constructors, symbol->vaddr, table->addr);
						break;
					}
				}
			}
		}
	}
}

static void table_index_free(SwiftTableIndex *index) {
	if (!index) {
		return;
	}
	ht_uu_free(index->constructors);
	ht_uu_free(index->metadata_accessors);
	ht_up_free(index->by_addr);
	rz_vector_free(index->tables);
	free(index);
}

static RZ_OWN SwiftTableIndex *table_index_new(RzCore *core) {
	SwiftTableIndex *index = RZ_NEW0(SwiftTableIndex);
	if (!index) {
		return NULL;
	}
	index->tables = rz_vector_new(sizeof(SwiftKnownTable), known_table_fini, NULL);
	index->by_addr = ht_up_new(NULL, NULL);
	index->metadata_accessors = ht_uu_new();
	index->constructors = ht_uu_new();
	if (!index->tables || !index->by_addr || !index->metadata_accessors || !index->constructors) {
		table_index_free(index);
		return NULL;
	}

	add_analysis_vtables(core, index->tables);
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	const RzPVector *symbols = NULL;
	if (obj) {
		symbols = rz_bin_object_get_symbols(obj);
	}
	if (symbols) {
		void **iter;
		rz_pvector_foreach (symbols, iter) {
			RzBinSymbol *symbol = *iter;
			if (!symbol || RZ_STR_ISEMPTY(symbol->dname)) {
				continue;
			}
			bool witness = strstr(symbol->dname, "protocol witness table for ");
			bool metadata = strstr(symbol->dname, "type metadata for ") &&
				!strstr(symbol->dname, "full type metadata for ") && !strstr(symbol->dname, "lazy cache");
			if (witness || metadata) {
				SwiftKnownTable *table = add_table(index->tables, symbol->vaddr, witness, symbol->dname, symbol->name);
				if (table && !table->size) {
					table->size = symbol->size;
				}
			}
		}
	}

	SwiftKnownTable *table;
	rz_vector_foreach (index->tables, table) {
		if (rz_vector_empty(table->methods)) {
			scan_table(core, table, index->tables);
		}
		if (!ht_up_insert(index->by_addr, table->addr, table)) {
			table_index_free(index);
			return NULL;
		}
	}
	build_function_maps(core, index);
	return index;
}

static SwiftKnownTable *table_by_addr(SwiftTableIndex *index, ut64 addr) {
	if (!index) {
		return NULL;
	}
	return ht_up_find(index->by_addr, addr, NULL);
}

static SwiftKnownMethod *method_at_offset(SwiftKnownTable *table, ut64 offset) {
	if (!table) {
		return NULL;
	}
	SwiftKnownMethod *method;
	rz_vector_foreach (table->methods, method) {
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
	if (!reg_name) {
		return UT64_MAX;
	}
	RzAnalysisILVM *vm = rz_analysis_get_il_vm(analysis);
	if (!vm) {
		return UT64_MAX;
	}
	RzILVal *value = rz_il_vm_get_var_value(vm->vm, RZ_IL_VAR_KIND_GLOBAL, reg_name);
	return il_value_to_ut64(value);
}

static ut64 get_mem_value(RzAnalysis *analysis, ut64 addr, ut64 bytes) {
	RzAnalysisILVM *vm = rz_analysis_get_il_vm(analysis);
	if (!vm || !vm->vm) {
		return UT64_MAX;
	}
	RzBitVector *address = rz_bv_new_from_ut64(rz_analysis_get_bits(analysis), addr);
	if (!address) {
		return UT64_MAX;
	}
	RzBitVector *value = rz_il_vm_mem_loadw(vm->vm, 0, address, bytes * 8);
	rz_bv_free(address);
	if (!value) {
		return UT64_MAX;
	}
	ut64 result = rz_bv_to_ut64(value);
	rz_bv_free(value);
	return result;
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

static bool memory_access_is_safe(RzCore *core, ut64 addr, ut64 size, bool write) {
	if (size && addr >= SWIFT_TRACK_MEM_ADDR) {
		ut64 offset = addr - SWIFT_TRACK_MEM_ADDR;
		if (offset < SWIFT_TRACK_MEM_SIZE && size <= SWIFT_TRACK_MEM_SIZE - offset) {
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

static bool value_mem_access_is_safe(RzCore *core, RzAnalysisOp *op, RzAnalysisValue *value, bool write) {
	if (!analysis_value_is_mem(value)) {
		return true;
	}
	ut64 addr = UT64_MAX;
	return analysis_value_addr(core, op, value, &addr) && memory_access_is_safe(core, addr, value->memref, write);
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

static void clear_dst_reg_for_skipped_op(RzCore *core, RzAnalysisOp *op) {
	const char *dst = op_dst_reg_name(op);
	if (is_valid_reg(core, dst)) {
		rz_analysis_il_vm_set_unsigned(core->analysis, dst, 0);
	}
}

static bool track_step_or_skip(RzCore *core, RzAnalysisOp *op, ut64 next_addr) {
	if (!op->il_op || !op_memory_access_is_safe(core, op)) {
		clear_dst_reg_for_skipped_op(core, op);
		advance_il_pc(core, next_addr);
		return true;
	}
	advance_il_pc(core, op->addr);
	return rz_core_il_step(core, 1);
}

static void track_init(RzCore *core, RZ_NULLABLE const SwiftCallSeed *seed) {
	rz_core_analysis_esil_init_mem(core, NULL, SWIFT_TRACK_MEM_ADDR, SWIFT_TRACK_MEM_SIZE);
	rz_core_analysis_il_reinit(core);

	if (rz_asm_is_arch(core->rasm, "x86")) {
		rz_analysis_il_vm_set_unsigned(core->analysis, "rbp", SWIFT_STACK_PTR);
		rz_analysis_il_vm_set_unsigned(core->analysis, "rsp", SWIFT_STACK_PTR);
	} else if (rz_asm_is_arch(core->rasm, "arm")) {
		rz_analysis_il_vm_set_unsigned(core->analysis, "x29", SWIFT_STACK_PTR);
		rz_analysis_il_vm_set_unsigned(core->analysis, "sp", SWIFT_STACK_PTR);
	} else {
		RZ_LOG_WARN("arch %s is not supported\n", rz_core_get_arch(core));
	}

	if (!seed) {
		return;
	}

	ut64 psize = ptr_size(core);
	bool big_endian = rz_asm_is_big_endian_set(core->rasm);
	for (ut64 i = 0; i < seed->count; i++) {
		const SwiftSeedArg *arg = &seed->args[i];
		if (!arg->slot_count) {
			continue;
		}
		ut64 object = SWIFT_OBJECT_ADDR + i * SWIFT_OBJECT_SIZE;
		ut64 value = object;
		if (arg->direct) {
			value = arg->slots[0].table;
		}
		rz_analysis_il_vm_set_unsigned(core->analysis, seed->regs[i], value);
		if (!arg->direct) {
			for (ut64 n = 0; n < arg->slot_count; n++) {
				ut64 table = arg->slots[n].table;
				rz_io_write_i(core->io, object + arg->slots[n].offset, &table, psize, big_endian);
			}
		}
	}
}

static void track_fini(RzCore *core) {
	rz_core_analysis_il_reinit(core);
	rz_core_analysis_esil_init_mem_del(core, NULL, SWIFT_TRACK_MEM_ADDR, SWIFT_TRACK_MEM_SIZE);
}

static void add_virtual_xref(RzAnalysis *analysis, const char *method_name, ut64 call_addr) {
	bool found = false;
	HtSP *virtual_xrefs = rz_analysis_get_virtual_xrefs(analysis);
	if (!virtual_xrefs || RZ_STR_ISEMPTY(method_name)) {
		return;
	}
	RzSetU *set = ht_sp_find(virtual_xrefs, method_name, &found);
	if (!found) {
		set = rz_set_u_new();
		if (!set) {
			return;
		}
		if (!ht_sp_insert(virtual_xrefs, method_name, set)) {
			rz_set_u_free(set);
			return;
		}
	}
	if (!set) {
		return;
	}
	rz_set_u_add(set, call_addr);
}

static void add_virtual_xrefs_for_method(RzCore *core, const char *method_name, ut64 method_addr, ut64 call_addr) {
	add_virtual_xref(core->analysis, method_name, call_addr);
	const RzList *flags = rz_flag_get_list(core->flags, method_addr);
	RzListIter *iter;
	RzFlagItem *flag;
	rz_list_foreach (flags, iter, flag) {
		if (RZ_STR_ISNOTEMPTY(flag->name) && strcmp(flag->name, method_name)) {
			add_virtual_xref(core->analysis, flag->name, call_addr);
		}
	}
}

static void call_site_free(void *value) {
	SwiftCallSite *site = value;
	if (site) {
		rz_set_s_free(site->methods);
		free(site);
	}
}

static void calls_add(RzCore *core, HtUP *calls, ut64 call_addr, bool witness, SwiftKnownMethod *method) {
	if (!calls || !method || RZ_STR_ISEMPTY(method->name)) {
		return;
	}
	SwiftCallSite *site = ht_up_find(calls, call_addr, NULL);
	if (!site) {
		site = RZ_NEW0(SwiftCallSite);
		if (!site) {
			return;
		}
		site->methods = rz_set_s_new(HT_STR_DUP);
		if (!site->methods || !ht_up_insert(calls, call_addr, site)) {
			call_site_free(site);
			return;
		}
	}
	site->witness |= witness;
	rz_set_s_add(site->methods, method->name);
	add_virtual_xrefs_for_method(core, method->name, method->addr, call_addr);
}

/**
 * \brief Formatting state for call-site comments.
 */
typedef struct swift_comment_context_t {
	RzStrBuf *text;
	bool first;
} SwiftCommentContext;

static bool comment_add_name(void *user, const char *name, RZ_UNUSED const void *value) {
	SwiftCommentContext *context = user;
	if (!context->first) {
		rz_strbuf_append(context->text, " / ");
	}
	rz_strbuf_append(context->text, name);
	context->first = false;
	return true;
}

static bool comment_emit(void *user, ut64 addr, const void *value) {
	RzCore *core = user;
	SwiftCallSite *site = (SwiftCallSite *)value;
	RzStrBuf text = { 0 };
	rz_strbuf_init(&text);
	if (site->witness) {
		rz_strbuf_set(&text, "Swift Protocol Call: ");
	} else {
		rz_strbuf_set(&text, "Swift Virtual Call: ");
	}
	SwiftCommentContext context = { &text, true };
	ht_sp_foreach((HtSP *)site->methods, comment_add_name, &context);
	rz_core_meta_comment_add(core, rz_strbuf_get(&text), addr);
	rz_strbuf_fini(&text);
	return true;
}

static bool op_is_table_dispatch(RzCore *core, RzAnalysisOp *op) {
	return is_valid_reg(core, op->reg) && (op->type & (RZ_ANALYSIS_OP_TYPE_IND | RZ_ANALYSIS_OP_TYPE_MEM)) &&
		(rz_analysis_op_is_call(op) || rz_analysis_op_is_eob(op));
}

static bool op_is_register_dispatch(RzCore *core, RzAnalysisOp *op) {
	return is_valid_reg(core, op->reg) && (op->type & RZ_ANALYSIS_OP_TYPE_REG) &&
		!(op->type & (RZ_ANALYSIS_OP_TYPE_IND | RZ_ANALYSIS_OP_TYPE_MEM)) &&
		(rz_analysis_op_is_call(op) || rz_analysis_op_is_eob(op));
}

static void devirtualize_step(RzCore *core, RzAnalysisOp *op, SwiftTableIndex *index, HtUP *calls, RZ_NULLABLE const SwiftCallSeed *seed) {
	if (op_is_table_dispatch(core, op)) {
		ut64 table_addr = get_reg_value(core->analysis, op->reg);
		SwiftKnownTable *table = table_by_addr(index, table_addr);
		if (!table) {
			return;
		}
		ut64 slot_addr = table_addr + op->disp;
		if (slot_addr < table_addr) {
			return;
		}
		if (is_valid_reg(core, op->ireg)) {
			ut64 array_index = get_reg_value(core->analysis, op->ireg);
			if (array_index == UT64_MAX) {
				return;
			}
			ut64 scale = op->scale;
			if (!scale) {
				scale = 1;
			}
			ut64 indexed = array_index * scale;
			if (slot_addr + indexed < slot_addr) {
				return;
			}
			slot_addr += indexed;
		}
		SwiftKnownMethod *method = method_at_offset(table, slot_addr - table_addr);
		if (method && addr_is_executable(core, method->addr)) {
			calls_add(core, calls, op->addr, table->witness, method);
		}
		return;
	}
	if (!op_is_register_dispatch(core, op) || !seed) {
		return;
	}
	ut64 target = get_reg_value(core->analysis, op->reg);
	if (!target || target == UT64_MAX || !addr_is_executable(core, target)) {
		return;
	}
	SwiftKnownTable *table;
	rz_vector_foreach (index->tables, table) {
		bool seeded = false;
		for (ut64 i = 0; i < seed->count && !seeded; i++) {
			for (ut64 n = 0; n < seed->args[i].slot_count; n++) {
				seeded = seed->args[i].slots[n].table == table->addr;
				if (seeded) {
					break;
				}
			}
		}
		if (!seeded) {
			continue;
		}
		SwiftKnownMethod *method;
		rz_vector_foreach (table->methods, method) {
			if (method->addr == target) {
				calls_add(core, calls, op->addr, table->witness, method);
			}
		}
	}
}

static bool replay_call(RzCore *core, RzAnalysisOp *op, SwiftTableIndex *index, const char *ret_reg, ut64 *next_object, bool clear_unknown) {
	ut64 table_addr = ht_uu_find(index->metadata_accessors, op->jump, NULL);
	ut64 result = table_addr;
	if (!table_addr) {
		table_addr = ht_uu_find(index->constructors, op->jump, NULL);
		if (table_addr) {
			if (*next_object > SWIFT_TRACK_MEM_ADDR + SWIFT_TRACK_MEM_SIZE - SWIFT_OBJECT_SIZE) {
				return false;
			}
			rz_io_write_i(core->io, *next_object, &table_addr, ptr_size(core), rz_asm_is_big_endian_set(core->rasm));
			result = *next_object;
			*next_object += SWIFT_OBJECT_SIZE;
		}
	}
	advance_il_pc(core, op->addr + op->size);
	if (table_addr) {
		return rz_analysis_il_vm_set_unsigned(core->analysis, ret_reg, result);
	}
	if (clear_unknown) {
		return rz_analysis_il_vm_set_unsigned(core->analysis, ret_reg, 0);
	}
	return true;
}

static void recover_seed_arg(RzCore *core, SwiftTableIndex *index, ut64 value, RZ_OUT SwiftSeedArg *arg) {
	if (!value || value == UT64_MAX) {
		return;
	}
	if (table_by_addr(index, value)) {
		arg->direct = true;
		arg->slot_count = 1;
		arg->slots[0].table = value;
		return;
	}
	ut64 psize = ptr_size(core);
	for (ut64 i = 0; i < SWIFT_MAX_ARG_SLOTS; i++) {
		if (i * psize > UT64_MAX - value || !memory_access_is_safe(core, value + i * psize, psize, false)) {
			break;
		}
		ut64 table_addr = get_mem_value(core->analysis, value + i * psize, psize);
		if (!table_by_addr(index, table_addr)) {
			continue;
		}
		SwiftSeedSlot *slot = &arg->slots[arg->slot_count++];
		slot->offset = i * psize;
		slot->table = table_addr;
	}
}

static bool replay_function(RzCore *core, RzAnalysisFunction *function, ut64 end, SwiftTableIndex *index,
	RZ_NULLABLE const SwiftCallSeed *seed, RZ_NULLABLE HtUP *calls, RZ_NULLABLE SwiftCallSeed *recovered) {
	ut64 start = function->addr;
	if (!end) {
		end = rz_analysis_function_max_addr(function);
	}
	if (!addr_is_executable(core, start)) {
		return false;
	}
	ut8 *bytes = read_mapped_range(core, start, end);
	RzAnalysisOp *op = rz_analysis_op_new();
	if (!bytes || !op) {
		free(bytes);
		rz_analysis_op_free(op);
		return false;
	}
	const char *cc = function->cc;
	if (!cc) {
		cc = rz_analysis_cc_default(core->analysis);
	}
	const char *ret_reg = rz_analysis_cc_ret(core->analysis, cc);
	ut64 old_offset = core->offset;
	ut64 next_object = SWIFT_OBJECT_ADDR + SWIFT_MAX_CALL_ARGS * SWIFT_OBJECT_SIZE;
	core->offset = start;
	track_init(core, seed);
	bool ok = true;
	while (ok && start < end) {
		if (rz_analysis_op(core->analysis, op, start, bytes + (start - function->addr),
			    RZ_MIN(end - start, INT_MAX), RZ_ANALYSIS_OP_MASK_ALL) <= 0 ||
			op->size < 1 || (ut64)op->size > end - start) {
			break;
		}
		if (calls) {
			devirtualize_step(core, op, index, calls, seed);
		}
		ut64 next = start + op->size;
		if (rz_analysis_op_is_call(op)) {
			ok = replay_call(core, op, index, ret_reg, &next_object, recovered != NULL);
		} else if (rz_analysis_op_is_eob(op)) {
			advance_il_pc(core, next);
		} else {
			ok = track_step_or_skip(core, op, next);
		}
		start = next;
		core->offset = start;
		rz_analysis_op_fini(op);
	}
	if (ok && recovered) {
		for (ut64 i = 0; i < recovered->count; i++) {
			recover_seed_arg(core, index, get_reg_value(core->analysis, recovered->regs[i]), &recovered->args[i]);
		}
	}
	core->offset = old_offset;
	track_fini(core);
	rz_analysis_op_free(op);
	free(bytes);
	return ok;
}

static void get_arg_regs(RzCore *core, const char *cc, RZ_OUT SwiftCallSeed *seed) {
	if (!cc) {
		cc = rz_analysis_cc_default(core->analysis);
	}
	for (ut64 i = 0; i < SWIFT_MAX_CALL_ARGS - 1; i++) {
		const char *reg = rz_analysis_cc_arg(core->analysis, cc, i);
		if (!is_valid_reg(core, reg)) {
			break;
		}
		seed->regs[seed->count++] = reg;
	}
	const char *self = "r13";
	if (rz_asm_is_arch(core->rasm, "arm")) {
		self = "x20";
	}
	for (ut64 i = 0; i < seed->count; i++) {
		if (!strcmp(seed->regs[i], self)) {
			return;
		}
	}
	if (is_valid_reg(core, self)) {
		seed->regs[seed->count++] = self;
	}
}

static bool seed_equal(const SwiftCallSeed *a, const SwiftCallSeed *b) {
	if (a->count != b->count) {
		return false;
	}
	for (ut64 i = 0; i < a->count; i++) {
		if (a->args[i].direct != b->args[i].direct || a->args[i].slot_count != b->args[i].slot_count) {
			return false;
		}
		for (ut64 n = 0; n < a->args[i].slot_count; n++) {
			if (a->args[i].slots[n].offset != b->args[i].slots[n].offset ||
				a->args[i].slots[n].table != b->args[i].slots[n].table) {
				return false;
			}
		}
	}
	return true;
}

static void push_unique_seed(RzVector *seeds, const SwiftCallSeed *seed) {
	bool useful = false;
	for (ut64 i = 0; i < seed->count; i++) {
		useful |= seed->args[i].slot_count > 0;
	}
	if (!useful) {
		return;
	}
	SwiftCallSeed *existing;
	rz_vector_foreach (seeds, existing) {
		if (seed_equal(existing, seed)) {
			return;
		}
	}
	SwiftCallSeed copy = *seed;
	rz_vector_push(seeds, &copy);
}

static void collect_seed_from_site(RzCore *core, RzAnalysisFunction *caller, ut64 call_addr, SwiftTableIndex *index,
	const SwiftCallSeed *args, RzVector *seeds) {
	SwiftCallSeed seed = *args;
	if (call_addr > caller->addr && call_addr < rz_analysis_function_max_addr(caller) &&
		replay_function(core, caller, call_addr, index, NULL, NULL, &seed)) {
		push_unique_seed(seeds, &seed);
	}
}

static RZ_OWN RzVector *collect_caller_seeds(RzCore *core, RzAnalysisFunction *function, SwiftTableIndex *index, const SwiftCallSeed *args) {
	RzVector *seeds = rz_vector_new(sizeof(SwiftCallSeed), NULL, NULL);
	RzList *xrefs = rz_analysis_xrefs_get_to(core->analysis, function->addr);
	if (!seeds || !xrefs) {
		rz_vector_free(seeds);
		rz_list_free(xrefs);
		return NULL;
	}
	RzListIter *iter;
	RzAnalysisXRef *xref;
	rz_list_foreach (xrefs, iter, xref) {
		if (xref->type != RZ_ANALYSIS_XREF_TYPE_CALL && xref->type != RZ_ANALYSIS_XREF_TYPE_CODE) {
			continue;
		}
		RzAnalysisFunction *caller = rz_analysis_get_fcn_in(core->analysis, xref->from, RZ_ANALYSIS_FCN_TYPE_NULL);
		if (caller) {
			collect_seed_from_site(core, caller, xref->from, index, args, seeds);
		}
	}
	rz_list_free(xrefs);
	if (rz_vector_empty(seeds)) {
		rz_vector_free(seeds);
		return NULL;
	}
	return seeds;
}

/**
 * \brief Resolve Swift class vtable and protocol witness calls in the current function.
 */
RZ_IPI void rz_core_analysis_devirtualize_swift_methods(RZ_NULLABLE RzCore *core) {
	if (!core) {
		return;
	}
	RzAnalysisFunction *function = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_NULL);
	if (!function) {
		RZ_LOG_ERROR("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
		return;
	}
	SwiftTableIndex *index = table_index_new(core);
	if (!index) {
		return;
	}
	SwiftCallSeed args = { 0 };
	get_arg_regs(core, function->cc, &args);
	RzVector *seeds = NULL;
	if (args.count) {
		seeds = collect_caller_seeds(core, function, index, &args);
	}
	HtUP *calls = ht_up_new(NULL, call_site_free);
	if (!calls) {
		rz_vector_free(seeds);
		table_index_free(index);
		return;
	}
	replay_function(core, function, 0, index, NULL, calls, NULL);
	SwiftCallSeed *seed;
	rz_vector_foreach (seeds, seed) {
		replay_function(core, function, 0, index, seed, calls, NULL);
	}
	ht_up_foreach(calls, comment_emit, core);
	ht_up_free(calls);
	rz_vector_free(seeds);
	table_index_free(index);

	if (has_objc_thunk(core)) {
		rz_core_analysis_devirtualize_objc_methods(core);
	}
}
