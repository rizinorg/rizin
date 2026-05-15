// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_util.h>
#include <rz_type.h>
#include <rz_analysis.h>
#include <analysis_private.h>
#include <string.h>
#include "omf/omf.h"

bool set_reg_val2(RzReg *areg, const char *name, const ut16 value) {
	RzRegItem *r = rz_reg_get(areg, name, RZ_REG_TYPE_GPR);
	return rz_reg_set_value(areg, r, (ut64)value);
}

ut64 get_flg_val(RzReg *areg, const char *name) {
	const ut64 value = rz_reg_getv(areg, name);
	return value;
}

ut64 get_reg_val2(RzReg *areg, const char *name) {
	RzRegItem *reg = rz_reg_get(areg, name, RZ_REG_TYPE_GPR);
	const ut64 value = rz_reg_get_value(areg, reg);
	return value;
}

#define SET_CPUCON1(val) set_reg_val2(areg, CPUCON1_NAME, val)
#define SET_SP(val)      set_reg_val2(areg, "SP", val)
#define SET_CSP(val)     set_reg_val2(areg, "CSP", val)
#define SET_SGTDIS(val)  set_reg_val2(areg, CPUCON1_NAME, (CPUCON1_RESET_VALUE | (val << 3)))

#define GET_SGTDIS  get_flg_val(areg, "SGTDIS")
#define GET_CPUCON1 get_reg_val2(areg, "CPUCON1")
#define GET_SP      get_reg_val2(areg, "SP")

static OMF_components *get_component_by_ti(const rz_bin_omf166_obj *omf_obj, ut16 ti) {
	bool found = false;
	OMF_type *type = ht_up_find(omf_obj->ht_types, ti, &found);
	if (type->descr_type == COMPONENT_LIST_DESCRIPTOR) {
		return (OMF_components *)&type->descriptor.components;
	}
	return NULL;
}

static bool is_final_type(const rz_bin_omf166_obj *obj, ut16 ti_index) {
	bool found = false;
	const OMF_type *type = ht_up_find(obj->ht_types, ti_index, &found);
	if (!found) {
		return false;
	}
	return (type->descr_type == FINAL_TYPE) ? true : false;
}

static inline RzType *TYPE_TI(rz_bin_omf166_obj *omf_obj, ut16 ti) {
	bool found = false;
	const RzTypeDB *typedb = omf_obj->typedb;

	const OMF_type *type = ht_up_find(omf_obj->ht_types, ti, &found);
	if (!found) {
		return rz_type_identifier_of_base_type_str(typedb, "unknown_t");
	}
	if (found && type->descr_type == ARRAY_DESCRIPTOR) {
		RzType *subtype = TYPE_TI(omf_obj, type->descriptor.array.ti);
		const ut64 count = (type->descriptor.array.dimsz == 0xFFFFFFFF) ? 0 : type->descriptor.array.dimsz;
		RzType *newtype = NULL;
		if (is_final_type(omf_obj, type->descriptor.array.ti)) {
			newtype = rz_type_array_of_base_type_str(omf_obj->typedb, subtype->identifier.name, count);
			rz_type_free(subtype);
		} else {
			newtype = rz_type_array_of_type(omf_obj->typedb, subtype, count);
			if (!newtype) {
				rz_type_free(subtype);
			}
		}
		return newtype;
	}
	if (found && type->descr_type == POINTER_DESCRIPTOR) {
		RzType *subtype = TYPE_TI(omf_obj, type->descriptor.pointer.ti);
		RzType *newtype = NULL;
		const bool is_const = true;
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
	const bool result = rz_type_db_save_base_type(typedb, bt);
	if (!result) {
		rz_type_base_type_free(bt);
		RZ_LOG_WARN("Not found: `%s`\n", name);
		return NULL;
	}
	return bt;
}

static bool types_cb(void *user, const ut64 k, const void *v) {
	OMF_type *type = (OMF_type *)v;
	rz_bin_omf166_obj *omf_obj = (rz_bin_omf166_obj *)user;

	if (type->descr_type == FINAL_TYPE) {
		RzType *ret = rz_type_identifier_of_base_type_str(omf_obj->typedb, type->label);
		if (ret) {
			rz_type_free(ret);
			return true;
		}
		create_new_primitive_type(
			omf_obj->typedb,
			type->label,
			type->descriptor.final_types.size);
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
				member.offset = component->offset;
				member.size = 8;
				rz_vector_push(&bt->struct_data.members, &member);
			}
		}
		rz_type_db_save_base_type(omf_obj->typedb, bt);
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

		cal->name = rz_str_dup("function");
		newtype->callable = cal;
		cal->ret = TYPE_TI(omf_obj, type->descriptor.function.rtype_ti);
		cal->args = rz_pvector_new((RzPVectorFree)rz_type_callable_arg_free);
		if (!cal->args) {
			return false;
		}

		const OMF_components *components = get_component_by_ti(omf_obj, type->descriptor.function.parmlist_ti);
		if (components) {
			for (ut16 i = 0; i < components->count; i++) {
				const OMF_component *component = (OMF_component *)components->comp + i;
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
	return true;
}

RZ_API bool rz_core_bin_apply_omf_debug(const RzCore *core, const RzBinFile *binfile) {
	if (!core || !binfile) {
		return false;
	}

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
		RZ_LOG_WARN("Wrong memory model type, segmentation cannot be enabled, if mm is TINY\n");
		return false;
	}

	SET_SGTDIS(!(omf_obj->modinfo & 0x01));

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

	ht_up_foreach(omf_obj->ht_types, (HtUPForeachCallback)types_cb, (void *)omf_obj);

	void **bvit;
	rz_pvector_foreach (omf_obj->blocks_vec, bvit) {
		OMF_blocks *block = (OMF_blocks *)*bvit;
		if (!block->PInfoProcedure) {
			continue;
		}
		const ut32 addr = block->FrameNumber << 16 | block->BlockOffset16;

		RzAnalysisFunction *fcn_blk = rz_analysis_get_function_at(core->analysis, addr);
		if (!fcn_blk) {
			fcn_blk = rz_analysis_create_function(
				core->analysis,
				block->name,
				addr,
				RZ_ANALYSIS_FCN_TYPE_FCN);
			if (!fcn_blk) {
				RZ_LOG_WARN("Can`t create function %s on 0x%08x\n", block->name, addr);
				continue;
			}
			RzAnalysisBlock *bb = rz_analysis_create_block(core->analysis, addr, block->BlockLength16);
			// bb->jump = UT64_MAX;
			bb->fail = UT64_MAX;
			rz_analysis_function_add_block(fcn_blk, bb);
		}
	}
	return true;
}
