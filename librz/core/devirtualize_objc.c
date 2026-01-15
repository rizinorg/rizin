// SPDX-FileCopyrightText: 2025 tushar3q34 <tushar3q34@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_analysis.h>
#include <rz_core.h>
#include "core_private.h"

/**
 * \file devirtualize_objc.c
 * Devirtualization for Objective-C methods
 *
 * This file implements the devirtualization of Objective-C methods
 * by analyzing the class and method structure.
 */

static bool is_branch_type_to_method(RzAnalysisOp *op) {
	switch (op->type) {
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_RET:
	case RZ_ANALYSIS_OP_TYPE_CALL:
	case RZ_ANALYSIS_OP_TYPE_UCALL:
	case RZ_ANALYSIS_OP_TYPE_RCALL:
	case RZ_ANALYSIS_OP_TYPE_ICALL:
	case RZ_ANALYSIS_OP_TYPE_IRCALL:
	case RZ_ANALYSIS_OP_TYPE_CCALL:
	case RZ_ANALYSIS_OP_TYPE_UCCALL:
		return true;
	default:
		return false;
	}
}

/**
 * \brief initialises stack and registers for tainting
 */
static void rz_track_init(RzAnalysis *analysis, RzCore *core) {
	// Random Memory allocation representing function stack
	rz_core_analysis_esil_init_mem(core, NULL, 0x1000, 0x1050);
	rz_core_analysis_il_reinit(core); // initializing VM
	// TODO : Make general for other archs
	if (!rz_str_cmp(analysis->arch_target->arch, "x86", -1)) {
		rz_core_analysis_il_vm_set(core, "rbp", 0x1fff);
		rz_core_analysis_il_vm_set(core, "rsp", 0x1fff);
	} else if (!rz_str_cmp(analysis->arch_target->arch, "arm", -1)) {
		rz_core_analysis_il_vm_set(core, "fp", 0x1fff);
		rz_core_analysis_il_vm_set(core, "sp", 0x1fff);
	} else {
		RZ_LOG_WARN("arch %s not supported", analysis->arch_target->arch);
	}
}

static ut64 get_reg_value(RzAnalysis *analysis, const char *reg_name) {
	RzAnalysisILVM *vm = analysis->il_vm;
	RzILVal *il_c_reg = rz_il_vm_get_var_value(vm->vm, RZ_IL_VAR_KIND_GLOBAL, reg_name);
	if (!il_c_reg) {
		return UT64_MAX;
	}
	RzBitVector *bv = rz_il_value_to_bv(il_c_reg);
	if (!bv) {
		return UT64_MAX;
	}
	ut64 val = rz_bv_to_ut64(bv);
	rz_bv_free(bv);
	return val;
}

static RZ_OWN char *get_message_dispatch_method(RzCore *core, ut64 meta_class_addr, ut64 meth_str_addr) {
	RzBinFile *bf = rz_bin_cur(core->bin);
	void **it;

	const RzPVector *vec = rz_bin_object_get_strings(bf->o);
	char *methname = NULL;
	rz_pvector_foreach (vec, it) {
		RzBinString *bin_str = *it;
		if (bin_str->vaddr == meth_str_addr) {
			methname = rz_str_dup(bin_str->string);
			break;
		}
	}

	const RzPVector *symbols = rz_bin_object_get_symbols(bf->o);
	char *classname = NULL;
	rz_pvector_foreach (symbols, it) {
		RzBinSymbol *symbol = *it;
		if (symbol->vaddr == meta_class_addr) {
			classname = rz_str_dup(strstr(symbol->name, "CLASS_$_") + strlen("CLASS_$_"));
			break;
		}
	}

	if (!classname || !methname) {
		RZ_FREE(methname);
		RZ_FREE(classname);
		return NULL;
	}

	// Modifying method name to include method_class_(name)
	char *oldname = methname;
	methname = rz_str_newf("method_%s_%s", classname, methname);
	RZ_FREE(oldname);

	RzVector *methods = rz_analysis_class_method_get_all(core->analysis, classname);
	bool found = false;
	if (methods) {
		RzAnalysisMethod *method;
		rz_vector_foreach (methods, method) {
			if (!rz_str_cmp(method->name, methname, -1)) {
				found = true;
				break;
			}
		}
	}

	rz_vector_free(methods);
	RZ_FREE(classname);
	if (found) {
		return methname;
	}
	RZ_FREE(methname);
	return NULL;
}

static RzSetU *allocator_xrefs(RzAnalysis *analysis) {
	RzList *list = rz_analysis_function_list(analysis);
	if (!list) {
		return NULL;
	}
	RzListIter *it;
	RzAnalysisFunction *fcn;
	RzSetU *xref_addrs = rz_set_u_new();
	rz_list_foreach (list, it, fcn) {
		char *res = strstr(fcn->name, "sym.imp.objc_alloc_init");
		if (res != NULL) {
			RzList *xref_list = rz_analysis_xrefs_get_to(analysis, fcn->addr);
			RzListIter *itt;
			RzAnalysisXRef *xref;
			rz_list_foreach (xref_list, itt, xref) {
				rz_set_u_add(xref_addrs, xref->from);
			}
		}
	}
	return xref_addrs;
}

static void add_virtual_xrefs(RzAnalysis *analysis, const char *method_name, ut64 addr) {
	bool found = false;
	HtSP *virtual_xrefs = analysis->ht_virtual_xrefs;
	RzSetU *set = ht_sp_find(virtual_xrefs, method_name, &found);
	if (!found) {
		set = rz_set_u_new();
		ht_sp_insert(virtual_xrefs, method_name, set);
	}
	rz_set_u_add(set, addr);
}

static void devirtualize_msg_dispatch(RzCore *core, RzSetU *msg_dispatch_addr) {

	RzAnalysisFunction *function = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_ROOT);
	if (!function) {
		function = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_NULL);
	}
	if (!function) {
		RZ_LOG_ERROR("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
		return;
	}

	// The first argument is usually the register holding class meta info
	const char *cl_reg = rz_analysis_cc_arg(core->analysis, function->cc, 0);

	// The second argument is usually the register holding message selector
	const char *m_reg = rz_analysis_cc_arg(core->analysis, function->cc, 1);

	// The return argument stores the value of instance after call to allocator
	const char *ret_reg = rz_analysis_cc_ret(core->analysis, function->cc);

	RzSetU *xref_addrs = allocator_xrefs(core->analysis);

	ut64 start = function->addr; // start of the function
	ut64 end = rz_analysis_function_max_addr(function);
	RzAnalysisOp *op = rz_analysis_op_new();
	rz_track_init(core->analysis, core);

	ut8 *bytes = malloc(end - start);
	if (!rz_io_read_at_mapped(core->io, start, bytes, end - start)) {
		RZ_LOG_ERROR("Cannot read at offset 0x%08" PFMT64x "\n", start);
	}
	ut64 offset = 0;

	bool refresh_vm = false;
	while (start < end) {
		rz_analysis_op(core->analysis, op, start, bytes + offset, end - start, RZ_ANALYSIS_OP_MASK_ALL);
		if (refresh_vm) {
			rz_core_analysis_il_reinit(core);
			refresh_vm = false;
		}
		refresh_vm = is_branch_type_to_method(op);

		rz_core_il_step(core, 1);

		if (rz_set_u_contains(xref_addrs, start)) {
			// continue track past allocator call
			ut64 val = get_reg_value(core->analysis, cl_reg);
			rz_core_analysis_il_vm_set(core, ret_reg, val);
		}

		if (rz_set_u_contains(msg_dispatch_addr, op->addr)) {
			// Devirtualize the message dispatch
			ut64 vf_addr = get_reg_value(core->analysis, m_reg);
			ut64 cmeta_addr = get_reg_value(core->analysis, cl_reg);

			// Get function name called by message dispatch
			char *vmethod_name = get_message_dispatch_method(core, cmeta_addr, vf_addr);
			if (vmethod_name) {
				RzStrBuf *comment = rz_strbuf_new(NULL);
				rz_strbuf_setf(comment, "Message dispatch to %s", vmethod_name);
				const char *str_comment = rz_strbuf_drain(comment);
				rz_core_meta_comment_add(core, str_comment, start);
				RZ_FREE(str_comment);
				add_virtual_xrefs(core->analysis, vmethod_name, op->addr);
			}
		}
		start += op->size;
		offset += op->size;
		core->offset = start;
		rz_analysis_op_fini(op);
	}
	rz_set_u_free(xref_addrs);
	rz_analysis_op_free(op);
	free(bytes);
}

static char *construct_reloc_name(RZ_NONNULL RzBinReloc *reloc, RZ_NULLABLE const char *name, bool demangle) {
	RzStrBuf *buf = rz_strbuf_new("");
	if (!buf) {
		return NULL;
	}

	// (optional) libname_
	if (reloc->import && reloc->import->libname) {
		rz_strbuf_appendf(buf, "%s_", reloc->import->libname);
	} else if (reloc->symbol && reloc->symbol->libname) {
		rz_strbuf_appendf(buf, "%s_", reloc->symbol->libname);
	}

	// actual name
	if (name) {
		rz_strbuf_append(buf, name);
	} else if (demangle && reloc->import && RZ_STR_ISNOTEMPTY(reloc->import->dname)) {
		rz_strbuf_append(buf, reloc->import->dname);
	} else if (reloc->import && RZ_STR_ISNOTEMPTY(reloc->import->name)) {
		rz_strbuf_append(buf, reloc->import->name);
	} else if (demangle && reloc->symbol && RZ_STR_ISNOTEMPTY(reloc->symbol->dname)) {
		rz_strbuf_appendf(buf, "%s", reloc->symbol->dname);
	} else if (reloc->symbol && RZ_STR_ISNOTEMPTY(reloc->symbol->name)) {
		rz_strbuf_appendf(buf, "%s", reloc->symbol->name);
	} else if (reloc->is_ifunc) {
		// addend is the function pointer for the resolving ifunc
		rz_strbuf_appendf(buf, "ifunc_%" PFMT64x, reloc->addend);
	} else {
		rz_strbuf_set(buf, "");
	}

	return rz_strbuf_drain(buf);
}

/**
 * \brief devirtualize Objective-C message dispatch methods
 *
 * \param core The RzCore instance to work with.
 */
RZ_API void rz_analysis_devirtualize_objc_methods(RZ_NULLABLE RzCore *core) {
	if (!core) {
		RZ_LOG_ERROR("devirtualization analysis failed");
		return;
	}
	RzBinFile *bf = rz_bin_cur(core->bin);
	RzBinObject *obj = rz_bin_cur_object(core->bin);

	if (!bf || !obj) {
		return;
	}

	// Check if the binary file has message dispatch methods
	// First find in symbols, then in relocs
	bool msg_dispatch = false;
	RzVector *msg_dispatch_addrs = rz_vector_new(sizeof(ut64), NULL, NULL);

	const RzPVector *symbols = rz_bin_object_get_symbols(bf->o);
	void **iter;
	rz_pvector_foreach (symbols, iter) {
		RzBinSymbol *symbol = *iter;
		if (!rz_str_cmp(symbol->name, "objc_msgSend", -1)) {
			msg_dispatch = true;
			rz_vector_push(msg_dispatch_addrs, &(symbol->vaddr));
			break;
		}
	}

	RzBinRelocStorage *relocs = rz_bin_object_patch_relocs(bf, obj);
	for (size_t i = 0; i < relocs->relocs_count; i++) {
		RzBinReloc *reloc = relocs->relocs[i];
		bool demangle = rz_config_get_b(core->config, "bin.demangle");
		char *name = construct_reloc_name(reloc, NULL, demangle);
		if (!rz_str_cmp(name, "objc_msgSend", -1)) {
			msg_dispatch = true;
			rz_vector_push(msg_dispatch_addrs, &(reloc->vaddr));
		}
		free(name);
	}

	RzSetU *msg_dispatch_xref_addr = rz_set_u_new();

	// Note all xrefs to message dispatch
	ut64 *itt;
	rz_vector_foreach (msg_dispatch_addrs, itt) {
		ut64 addr = *itt;
		RzList *xref_list = rz_analysis_xrefs_get_to(core->analysis, addr);
		RzListIter *it;
		RzAnalysisXRef *xref;
		rz_list_foreach (xref_list, it, xref) {
			rz_set_u_add(msg_dispatch_xref_addr, xref->from);
		}
		rz_list_free(xref_list);
	}
	rz_vector_free(msg_dispatch_addrs);

	if (msg_dispatch) {
		devirtualize_msg_dispatch(core, msg_dispatch_xref_addr);
	}
	rz_set_u_free(msg_dispatch_xref_addr);
}