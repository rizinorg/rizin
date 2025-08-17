// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_util.h>
#include <rz_type.h>
#include <rz_analysis.h>
#include <analysis_private.h>
#include <string.h>
#include "omf/omf.h"

static OMF_components *get_component_by_ti(const rz_bin_omf166_obj *omf_obj, ut16 ti) {
	bool found = false;
	OMF_type *type = ht_up_find(omf_obj->ht_types, ti, &found);
	// rz_return_val_if_fail(found, NULL);
	if (type->descr_type == COMPONENT_LIST_DESCRIPTOR) {
		return (OMF_components *)&type->descriptor.components;
	}
	return NULL;
}

static inline OMF_type *OMF_TYPE_TI(const rz_bin_omf166_obj *omf_obj, ut16 ti) {
	bool found = false;
	// const RzTypeDB *typedb = omf_obj->typedb;

	OMF_type *type = ht_up_find(omf_obj->ht_types, ti, &found);
	RZ_LOG_DEBUG("OMF_TYPE_TI[0x%02x] found: %5s, label: `%s`\n", ti, found ? "true" : "false", type->label);
	rz_return_val_if_fail(found, NULL);
	return type;
}

static bool is_final_type(const rz_bin_omf166_obj *obj, ut16 ti_index) {
	bool found = false;
	OMF_type *type = ht_up_find(obj->ht_types, ti_index, &found);
	rz_return_val_if_fail(found, false);
	return (type->descr_type == FINAL_TYPE) ? true : false;
}

static inline RzType *TYPE_TI(rz_bin_omf166_obj *omf_obj, ut16 ti) {
	bool found = false;
	const RzTypeDB *typedb = omf_obj->typedb;

	const OMF_type *type = ht_up_find(omf_obj->ht_types, ti, &found);
	rz_return_val_if_fail(found, rz_type_identifier_of_base_type_str(typedb, "unknown_t"));
	if (found && type->descr_type == ARRAY_DESCRIPTOR) {
		RzType *subtype = TYPE_TI(omf_obj, type->descriptor.array.ti);
		ut64 count = (type->descriptor.array.dimsz == 0xFFFFFFFF) ? 0 : type->descriptor.array.dimsz;
		RzType *newtype = NULL;
		if (is_final_type(omf_obj, type->descriptor.array.ti)) {
			newtype = rz_type_array_of_base_type_str(omf_obj->typedb, subtype->identifier.name, count);
			rz_type_free(subtype);
		} else {
			newtype = rz_type_array_of_type(omf_obj->typedb, subtype, count);
			if (!newtype)
				rz_type_free(subtype);
		}
		return newtype;
	}
	if (found && type->descr_type == POINTER_DESCRIPTOR) {
		RzType *subtype = TYPE_TI(omf_obj, type->descriptor.pointer.ti);
		RzType *newtype = NULL;
		bool is_const = true;
		if (is_final_type(omf_obj, type->descriptor.pointer.ti)) {
			newtype = rz_type_pointer_of_base_type_str(omf_obj->typedb, subtype->identifier.name, is_const);
		} else {
			newtype = rz_type_pointer_of_type(omf_obj->typedb, subtype, is_const);
		}
		rz_type_free(subtype);
		return newtype;
	}

	RzType *ret = rz_type_identifier_of_base_type_str(typedb, type->label);
	if (!ret)
		return rz_type_identifier_of_base_type_str(typedb, "unknown_t");
	return ret;
}

static RzBaseType *create_new_primitive_type(const RzTypeDB *typedb, const char *name, ut16 size) {
	RzBaseType *bt = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ATOMIC);
	bt->name = rz_str_dup(name);
	bt->size = size;
	bool result = rz_type_db_save_base_type(typedb, bt);
	rz_return_val_if_fail(result, NULL);
	return bt;
}

static RzCallable *create_noretarg_func(RzTypeDB *typedb, const char *name) {
	RzCallable *callable = rz_type_func_new(typedb, name, NULL);
	if (!rz_type_func_noreturn_add(typedb, name)) {
		rz_type_callable_free(callable);
		return NULL;
	}
	return callable;
}

static bool create_new_func(rz_bin_omf166_obj *omf_obj, OMF_symbol *symbol) {
	RzTypeDB *typedb = omf_obj->typedb;
	bool found = false;
	const OMF_type *omf_type = ht_up_find(omf_obj->ht_types, symbol->ti, &found);
	if (omf_type->descriptor.function.rtype_ti == 0x00 && omf_type->descriptor.function.parmlist_ti == 0x00) {
		RzCallable *callable = create_noretarg_func(typedb, symbol->name2);
		if (!rz_type_func_save(typedb, callable)) {
			rz_type_callable_free(callable);
			return false;
		}
		return true;
	}

	const char *ret_type_name = name_of_ti(omf_obj, omf_type->descriptor.function.rtype_ti);
	RzType *ret_type = rz_type_identifier_of_base_type_str(typedb, ret_type_name);

	RzCallable *callable = rz_type_func_new(typedb, symbol->name2, ret_type);

	if (!strcmp(ret_type_name, "void") || (!ret_type)) {
		rz_type_func_noreturn_add(typedb, symbol->name2);
	}

	RZ_LOG_DEBUG("create_new_func: ti: 0x%02x, rtype_ti: 0x%02x [%s], parmlist_ti: 0x%02x [%s], symbol->name2: `%s` cal `%s`\n",
		symbol->ti,
		omf_type->descriptor.function.rtype_ti,
		omf_type->descriptor.function.rtype_ti == 0x00 ? "0x00" : name_of_ti(omf_obj, omf_type->descriptor.function.rtype_ti),
		omf_type->descriptor.function.parmlist_ti,
		omf_type->descriptor.function.parmlist_ti == 0x00 ? "0x00" : name_of_ti(omf_obj, omf_type->descriptor.function.parmlist_ti),
		symbol->name2,
		callable->name);

	ut8 parmlist_ti = omf_type->descriptor.function.parmlist_ti;

	OMF_type *paramt = OMF_TYPE_TI(omf_obj, parmlist_ti);
	rz_return_val_if_fail(paramt, NULL);

	///< (parmlist_ti == 0x4A || parmlist_ti == 0x4d || parmlist_ti == 0x4e)
	// parse parameter list
	if ((paramt->descr_type == FINAL_TYPE) && (parmlist_ti != 0x4A)) {
		RZ_LOG_DEBUG("paramt->descr_type == FINAL_TYPE\n");
		RzType *carg_type = rz_type_identifier_of_base_type_str(
			typedb,
			name_of_ti(omf_obj, paramt->descriptor.final_types.index));

		RzCallableArg *cargs = rz_type_callable_arg_new(
			typedb,
			rz_str_dup(paramt->descriptor.final_types.label),
			carg_type);
		rz_type_callable_arg_add(callable, cargs);
	}
	if (paramt->descr_type == COMPONENT_LIST_DESCRIPTOR) {
		RZ_LOG_DEBUG("paramt->descr_type == COMPONENT_LIST_DESCRIPTOR\n");
		OMF_components *components = get_component_by_ti(omf_obj, parmlist_ti);
		if (components) {
			for (ut16 i = 0; i < components->count; i++) {
				OMF_component *component = (OMF_component *)components->comp + i;
				if (!component)
					continue;
				RZ_LOG_DEBUG("\tindex: 0x%04x, TI16: 0x%04x (%s), OFFS32: 0x%04x, REP8: 0x%02x, POS8: 0x%02x, n: %d (%s)\n",
					components->index,
					component->ti,
					name_of_ti(omf_obj, component->ti),
					component->offset, component->REP8,
					component->POS8,
					component->n,
					component->name);

				RzType *carg_type = TYPE_TI(omf_obj, component->ti);
				RzCallableArg *cargs = rz_type_callable_arg_new(typedb, component->name, carg_type);
				rz_type_callable_arg_add(callable, cargs);
			}
		}
	}
	if (!rz_type_func_save(typedb, callable)) {
		rz_type_callable_free(callable);
		return false;
	}
	return true;
}

static bool omf_try_create_var_global(
	RZ_BORROW RZ_IN RZ_NONNULL RzAnalysis *analysis,
	RZ_BORROW RZ_IN RZ_NONNULL rz_bin_omf166_obj *omf_obj) {
	bool result = false;

	RzPVector *v = omf_obj->symbols_vec;
	void **it;
	rz_pvector_foreach (v, it) {
		OMF_symbol *p = (OMF_symbol *)*it;
		if (p->rec_type == OMF166_DEBSYM)
			continue;
		if (p->rec_type == REP_CONST)
			continue;
		if (p->REP == REP_CONST)
			continue;
		if (p->REP == REP_REGBANK)
			continue;
		if (p->REP == REP_INTNO)
			continue;
		if (!p->is_data)
			continue;

		RzAnalysisVarGlobal *exist_var = rz_analysis_var_global_get_byname(analysis, p->name2);
		if (exist_var)
			continue;
		RzType *p_ti = TYPE_TI(omf_obj, p->ti);
		result = rz_analysis_var_global_create(
			analysis,
			p->name2,
			p_ti,
			p->base + p->offset);
		if (!result) {
			continue;
		}
	}
	return result;
}

static bool types_cb(void *user, const ut64 k, const void *v) {
	OMF_type *type = (OMF_type *)v;
	rz_bin_omf166_obj *omf_obj = (rz_bin_omf166_obj *)user;

	if (type->descr_type == FINAL_TYPE) {
		RzType *ret = rz_type_identifier_of_base_type_str(omf_obj->typedb, type->label);
		if (ret) {
			rz_type_free(ret); // ?
			return true;
		}
		RzBaseType *ret_bt = create_new_primitive_type(
			omf_obj->typedb,
			type->label,
			type->descriptor.final_types.size);
		(void)ret_bt;
	}
	if (type->descr_type == STRUCT_UNION_DESCRIPTOR) {
		RzBaseType *bt = rz_type_base_type_new(
			type->descriptor.struct_union.is_struct == 1 ? RZ_BASE_TYPE_KIND_STRUCT : RZ_BASE_TYPE_KIND_UNION);
		bt->name = rz_str_dup(type->descriptor.struct_union.tagname);
		bt->size = type->descriptor.struct_union.size;

		const OMF_components *components = get_component_by_ti(omf_obj, type->descriptor.struct_union.member_ti);
		if (components) {
			for (ut16 i = 0; i < components->count; i++) {
				OMF_component *component = (OMF_component *)components->comp + i;
				if (!component)
					continue;

				RzTypeStructMember member = { 0 };
				member.name = rz_str_dup(component->name);
				member.type = TYPE_TI(omf_obj, component->ti);
				member.offset = component->offset; // in bytes
				member.size = 1; // in bits?
				rz_vector_push(&bt->struct_data.members, &member);
			}
		}
		rz_type_db_save_base_type(omf_obj->typedb, bt);

		const RzBaseType *btype = rz_type_db_get_base_type(omf_obj->typedb, type->descriptor.struct_union.tagname);
		if (btype) {
			RZ_LOG_DEBUG("Found: `%s`\n", btype->name);
		} else
			RZ_LOG_DEBUG("Not found: struct `%s`\n", type->descriptor.struct_union.tagname);
	}

	if (type->descr_type == FUNCTION_DESCRIPTOR) {
		RzBaseType *bt = rz_type_base_type_new(RZ_BASE_TYPE_KIND_TYPEDEF);
		bt->name = rz_str_dup("some");
		RzType *newtype = RZ_NEW0(RzType);
		if (!newtype) {
			return NULL;
		}
		newtype->kind = RZ_TYPE_KIND_CALLABLE;

		RzCallable *cal = RZ_NEW0(RzCallable);
		if (!cal) {
			return NULL;
		}

		cal->name = rz_str_dup("ffff");
		newtype->callable = cal;
		cal->ret = TYPE_TI(omf_obj, type->descriptor.function.rtype_ti);
		cal->args = rz_pvector_new((RzPVectorFree)rz_type_callable_arg_free);
		rz_return_val_if_fail(cal->args, false);

		OMF_components *components = get_component_by_ti(omf_obj, type->descriptor.function.parmlist_ti);
		if (components) {
			for (ut16 i = 0; i < components->count; i++) {
				OMF_component *component = (OMF_component *)components->comp + i;
				RZ_LOG_DEBUG("\tindex: 0x%04x, TI16: 0x%04x (%s), OFFS32: 0x%04x, REP8: 0x%02x, POS8: 0x%02x, n: %d (%s)\n",
					components->index,
					component->ti,
					name_of_ti(omf_obj, component->ti),
					component->offset, component->REP8,
					component->POS8,
					component->n,
					component->name);

				RzCallableArg *cargs = RZ_NEW0(RzCallableArg);
				if (!cargs) {
					return NULL;
				}

				cargs->name = rz_str_dup(component->name);
				cargs->type = TYPE_TI(omf_obj, component->ti);
				rz_pvector_push(cal->args, cargs);
			}
		}
		bt->type = newtype;
		rz_type_db_save_base_type(omf_obj->typedb, bt);
		type->rz_type = (void *)cal;
	}
	if (type->descr_type == ARRAY_DESCRIPTOR) {
	}
	return true;
}

static bool omf166_integrate_function(void *user, const ut64 k, const void *value) {
	RZ_LOG_DEBUG("---->omf166_integrate_function\n");
	return true;
}

/**
 * \brief Use parsed OMF166 function info in the function analysis
 * \param analysis The analysis
 */
RZ_API void rz_analysis_omf166_integrate_functions(RzAnalysis *analysis) {
	rz_return_if_fail(analysis);
	ht_up_foreach(analysis->debug_info->function_by_addr, omf166_integrate_function, analysis);
}

#define CPUCON1_NAME        "CPUCON1"
#define SP_RESET_VALUE      0xFC00
#define CPUCON1_RESET_VALUE 0x0000

bool set_reg_val2(RzReg *areg, const char *name, const ut16 value) {
	RzRegItem *r = rz_reg_get(areg, name, RZ_REG_TYPE_GPR);
	return rz_reg_set_value(areg, r, (ut64)value);
}

ut64 get_flg_val(RzReg *areg, const char *name) {
	const ut64 value = rz_reg_getv(areg, name);
	RZ_LOG_DEBUG("`%s_reg` value1: 0x%04" PFMT64x "\n", name, value);
	return value;
}

ut64 get_reg_val2(RzReg *areg, const char *name) {
	RzRegItem *reg = rz_reg_get(areg, name, RZ_REG_TYPE_GPR);
	const ut64 value = rz_reg_get_value(areg, reg);
	RZ_LOG_DEBUG("`%s` reg value: 0x%08" PFMT64x "\n", name, value);
	return value;
}
#define SET_CPUCON1(val) rz_return_val_if_fail(set_reg_val2(areg, CPUCON1_NAME, val), false)
#define SET_SP(val)      rz_return_val_if_fail(set_reg_val2(areg, "SP", val), false)
#define SET_CSP(val)     rz_return_val_if_fail(set_reg_val2(areg, "CSP", val), false)
#define SET_SGTDIS(val)  rz_return_val_if_fail(set_reg_val2(areg, CPUCON1_NAME, (CPUCON1_RESET_VALUE | (val << 3))), false)

#define GET_SGTDIS  get_flg_val(areg, "SGTDIS")
#define GET_CPUCON1 get_reg_val2(areg, "CPUCON1")
#define GET_SP      get_reg_val2(areg, "SP")

RZ_API bool rz_core_bin_apply_omf_debug(const RzCore *core, const RzBinFile *binfile) {
	rz_return_val_if_fail(core, false);

	const char *arch = rz_config_get(core->config, "asm.arch");
	if (!strstr(arch, "c166")) {
		return false;
	}

	const RzBinObject *binobj = rz_bin_cur_object(core->bin);
	RzBinInfo *info = binobj ? binobj->info : NULL;
	if (!info) {
		return false;
	}
	if (!info->rclass) {
		return false;
	}
	if (RZ_STR_NE(info->rclass, "OMF166")) {
		return false;
	}
	rz_return_val_if_fail(binfile, false);

	RzReg *areg = rz_analysis_get_reg(core->analysis);

	SET_SP(SP_RESET_VALUE);

	rz_bin_omf166_obj *omf_obj = (rz_bin_omf166_obj *)binfile->o->bin_obj;

#ifdef RZ_BUILD_DEBUG
	const char *mm_string = get_memory_model(omf_obj->modinfo);
	RZ_LOG_DEBUG("OMF166 Memory Model: %s\n", mm_string);
	RZ_LOG_DEBUG("Segmentation Disable/Enable Control: %s\n", (omf_obj->modinfo & 0x01) ? "Segmentation enabled" : "Segmentation disabled");
	RZ_FREE(mm_string);
#endif

	const ut8 mm = memory_model_type(omf_obj->modinfo);
	if (mm == OMF_MEMORY_MODEL_TINY && !(omf_obj->modinfo & 0x01)) {
		eprintf("Wrong memory model type, segmentation cannot be enabled, if mm is TINY\n");
		return false;
	}

	SET_SGTDIS(!(omf_obj->modinfo & 0x01));
#ifdef RZ_BUILD_DEBUG
	GET_SGTDIS;
	GET_SP;
	GET_CPUCON1;
#endif

	if (!binfile->o->lines) {
		RzPVector *ls = omf_obj->linnums_vec;
		void **lit;
		ut16 index = 0;

		binfile->o->lines = RZ_NEW0(RzBinSourceLineInfo);
		const size_t lc = rz_pvector_len(omf_obj->linnums_vec);
		binfile->o->lines->samples_count = lc;
		binfile->o->lines->samples = RZ_NEWS0(RzBinSourceLineSample, lc);

		rz_pvector_foreach (ls, lit) {
			OMF_linnums *linnum = (OMF_linnums *)*lit;
			RzBinSourceLineSample *sample = &binfile->o->lines->samples[index];
			sample->address = linnum->address;
			sample->line = linnum->LineNumber;
			sample->column = 0;
			sample->file = rz_str_dup(linnum->filename);
			index++;
		}
		rz_str_constpool_init(&binfile->o->lines->filename_pool);
	}

	omf_obj->typedb = core->analysis->typedb;

	rz_type_db_purge(core->analysis->typedb);
	char *types_dir = rz_path_system(core->sys_path, RZ_SDB_TYPES);
	if (!types_dir) {
		return false;
	}
	rz_type_db_reload(core->analysis->typedb, types_dir);
	free(types_dir);

	// rz_flag_space_push(core->flags, RZ_FLAGS_FS_SYMBOLS);

	ht_up_foreach(omf_obj->ht_types, (HtUPForeachCallback)types_cb, (void *)omf_obj);

	const RzPVector *vs = omf_obj->symbols_vec;
	void **vit;
	rz_pvector_foreach (vs, vit) {
		OMF_symbol *symbol = (OMF_symbol *)*vit;
		if (symbol->is_data) {
			continue;
		}
		if (symbol->ti == 0x99) {
			// printf("\nsymbol: [0x%02x] `%s` (0x%08x)  (%d) [%" PFMT64d "], %s\n",
			// 			symbol->ti,
			// 			symbol->name2,
			// 			symbol->base | symbol->offset,
			// 			symbol->rec_type,
			// 			symbol->size,
			// 			symbol->is_data ? "data" : "function");
			bool found = false;
			OMF_type *newtype = ht_up_find(omf_obj->ht_types, symbol->ti, &found);
			if (found) {
				// printf("[0x%02x] type label: %s {0x%02x}\n", symbol->ti, newtype->label, newtype->descr_type);
				if (newtype->descr_type == FUNCTION_DESCRIPTOR) {
					// printf("FUNCTION Descriptor `%s`, ret: %s, paramlist: (0x%04x) %s\n",
					// 	newtype->descriptor.function.attrib == 1 ? "NEAR" : "FAR",
					// 	name_of_ti(omf_obj, newtype->descriptor.function.rtype_ti),
					// 	newtype->descriptor.function.parmlist_ti,
					// 	name_of_ti(omf_obj, newtype->descriptor.function.parmlist_ti));
					// newtype->descriptor.function
					// RzCallable *c = rz_type_callable_new(symbol->name2);
					// c->noret = true;
					// c->ret = rz_type_identifier_of_base_type_str(core->analysis->typedb, "void");
					// // c->cc = rz_str_constpool_get(&core->analysis->constpool, "sectarian");
					RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, symbol->base | symbol->offset);
					if (!fcn) {
						RZ_LOG_DEBUG("Function %s not found\n", symbol->name2);
						void **it;
						rz_pvector_foreach (omf_obj->pe_vec, it) {
						}
						fcn = rz_analysis_create_function(core->analysis, symbol->name2, symbol->base | symbol->offset, RZ_ANALYSIS_FCN_TYPE_FCN);
						if (rz_str_endswith_icase(symbol->name2, "_trap")) {
							// fcn->;
							RzAnalysisBlock *bb = rz_analysis_create_block(core->analysis, symbol->base | symbol->offset, 2);
							bb->jump = UT64_MAX;
							bb->fail = UT64_MAX;
							rz_analysis_function_add_block(fcn, bb);
						}
						// 	// // fcn = rz_analysis_create_function(core->analysis, pname, meta_addr, RZ_ANALYSIS_FCN_TYPE_IMP);
						// 	// // RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, PROTO_VADDRESS(proto->index));
						// 	// RzAnalysisBlock *bb = rz_analysis_create_block(core->analysis, symbol->base | symbol->offset, symbol->size);
						// 	// bb->jump = UT64_MAX;
						// 	// bb->fail = UT64_MAX;
						// 	//
						// 	// rz_analysis_function_add_block(fcn, bb);
						// rz_analysis_function_set_type(core->analysis, fcn, c);
						// rz_type_callable_free(c);
					} else {
						RZ_LOG_DEBUG("Function %s found\n", symbol->name2);
					}
				}
			}
		}
		if (symbol->rec_type == OMF166_PUBDEF && !symbol->is_data) {

			// if (!create_new_func(omf_obj, symbol)) {
			// 	RZ_LOG_DEBUG("error create_new_func\n");
			// }
		}
	}
	/* omf_try_create_var_global(core->analysis, omf_obj);*/
	(void)create_new_func;
	(void)omf_try_create_var_global;

	if (!binfile->o->lines) {
		RzPVector *ls = omf_obj->linnums_vec;
		void **lit;
		ut16 index = 0;

		binfile->o->lines = RZ_NEW0(RzBinSourceLineInfo);
		const size_t lc = rz_pvector_len(omf_obj->linnums_vec);
		binfile->o->lines->samples_count = lc;
		binfile->o->lines->samples = RZ_NEWS0(RzBinSourceLineSample, lc);

		rz_pvector_foreach (ls, lit) {
			OMF_linnums *linnum = (OMF_linnums *)*lit;
			RzBinSourceLineSample *sample = &binfile->o->lines->samples[index];
			sample->address = linnum->address;
			sample->line = linnum->LineNumber;
			sample->column = 0;
			sample->file = rz_str_dup(linnum->filename);
			index++;
		}
		rz_str_constpool_init(&binfile->o->lines->filename_pool);
	}
	return true;
}
