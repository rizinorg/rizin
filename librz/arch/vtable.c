// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 maijin <maijin21@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_util.h"
#include "rz_analysis.h"

#define VTABLE_BUFF_SIZE 10

#define VTABLE_READ_ADDR_FUNC(fname, read_fname, sz) \
	static bool fname(RzAnalysis *analysis, ut64 addr, ut64 *buf) { \
		ut8 tmp[sz]; \
		if (!analysis->iob.read_at(analysis->iob.io, addr, tmp, sz)) { \
			return false; \
		} \
		*buf = read_fname(tmp); \
		return true; \
	}
VTABLE_READ_ADDR_FUNC(vtable_read_addr_le8, rz_read_le8, 1)
VTABLE_READ_ADDR_FUNC(vtable_read_addr_le16, rz_read_le16, 2)
VTABLE_READ_ADDR_FUNC(vtable_read_addr_le32, rz_read_le32, 4)
VTABLE_READ_ADDR_FUNC(vtable_read_addr_le64, rz_read_le64, 8)
VTABLE_READ_ADDR_FUNC(vtable_read_addr_be8, rz_read_be8, 1)
VTABLE_READ_ADDR_FUNC(vtable_read_addr_be16, rz_read_be16, 2)
VTABLE_READ_ADDR_FUNC(vtable_read_addr_be32, rz_read_be32, 4)
VTABLE_READ_ADDR_FUNC(vtable_read_addr_be64, rz_read_be64, 8)

RZ_API void rz_analysis_vtable_info_free(RVTableInfo *vtable) {
	if (!vtable) {
		return;
	}
	rz_vector_clear(&vtable->methods);
	free(vtable);
}

RZ_API ut64 rz_analysis_vtable_info_get_size(RVTableContext *context, RVTableInfo *vtable) {
	return (ut64)vtable->methods.len * context->word_size;
}

RZ_API bool rz_analysis_vtable_begin(RzAnalysis *analysis, RVTableContext *context) {
	context->analysis = analysis;
	context->abi = analysis->cpp_abi;
	context->word_size = (ut8)(analysis->bits / 8);
	const bool is_arm = analysis->cur->arch && rz_str_startswith(analysis->cur->arch, "arm");
	if (is_arm && context->word_size < 4) {
		context->word_size = 4;
	}
	switch (context->word_size) {
	case 1:
		context->read_addr = analysis->big_endian ? vtable_read_addr_be8 : vtable_read_addr_le8;
		break;
	case 2:
		context->read_addr = analysis->big_endian ? vtable_read_addr_be16 : vtable_read_addr_le16;
		break;
	case 4:
		context->read_addr = analysis->big_endian ? vtable_read_addr_be32 : vtable_read_addr_le32;
		break;
	case 8:
		context->read_addr = analysis->big_endian ? vtable_read_addr_be64 : vtable_read_addr_le64;
		break;
	default:
		return false;
	}
	return true;
}

static bool vtable_addr_in_text_section(RVTableContext *context, ut64 curAddress) {
	// section of the curAddress
	RzBinSection *value = context->analysis->binb.get_vsect_at(context->analysis->binb.bin, curAddress);
	// If the pointed value lies in .text section
	return value && strstr(value->name, "text") && (value->perm & 1) != 0;
}

static bool vtable_is_value_in_text_section(RVTableContext *context, ut64 curAddress, ut64 *value) {
	// value at the current address
	ut64 curAddressValue;
	if (!context->read_addr(context->analysis, curAddress, &curAddressValue)) {
		return false;
	}
	// if the value is in text section
	bool ret = vtable_addr_in_text_section(context, curAddressValue);
	if (value) {
		*value = curAddressValue;
	}
	return ret;
}

static bool vtable_section_can_contain_vtables(RzBinSection *section) {
	if (section->is_segment) {
		return false;
	}
	return !strcmp(section->name, ".rodata") ||
		!strcmp(section->name, ".rdata") ||
		!strcmp(section->name, ".data.rel.ro") ||
		!strcmp(section->name, ".data.rel.ro.local") ||
		rz_str_endswith(section->name, "__const");
}

static bool section_can_contain_rtti(RzBinSection *section) {
	if (!section) {
		return false;
	}
	if (section->is_data) {
		return true;
	}
	return !strcmp(section->name, ".data.rel.ro") ||
		!strcmp(section->name, ".data.rel.ro.local") ||
		rz_str_endswith(section->name, "__const");
}

static bool vtable_is_addr_vtable_start_itanium(RVTableContext *context, RzBinSection *section, ut64 curAddress) {
	ut64 value;
	if (!curAddress || curAddress == UT64_MAX) {
		return false;
	}
	if (curAddress && !vtable_is_value_in_text_section(context, curAddress, NULL)) { // Vtable beginning referenced from the code
		return false;
	}
	if (!context->read_addr(context->analysis, curAddress - context->word_size, &value)) { // get the RTTI pointer
		return false;
	}
	RzBinSection *rtti_section = context->analysis->binb.get_vsect_at(context->analysis->binb.bin, value);
	if (value && !section_can_contain_rtti(rtti_section)) { // RTTI ptr must point somewhere in the data section
		return false;
	}
	if (!context->read_addr(context->analysis, curAddress - 2 * context->word_size, &value)) { // Offset to top
		return false;
	}
	if ((st32)value > 0) { // Offset to top has to be negative
		return false;
	}
	return true;
}

static bool vtable_is_addr_vtable_start_msvc(RVTableContext *context, ut64 curAddress) {
	RzAnalysisXRef *xref;
	RzListIter *xrefIter;

	if (!curAddress || curAddress == UT64_MAX) {
		return false;
	}
	if (curAddress && !vtable_is_value_in_text_section(context, curAddress, NULL)) {
		return false;
	}
	// total xref's to curAddress
	RzList *xrefs = rz_analysis_xrefs_get_to(context->analysis, curAddress);
	if (rz_list_empty(xrefs)) {
		rz_list_free(xrefs);
		return false;
	}
	rz_list_foreach (xrefs, xrefIter, xref) {
		// section in which currenct xref lies
		if (vtable_addr_in_text_section(context, xref->from)) {
			ut8 buf[VTABLE_BUFF_SIZE];
			context->analysis->iob.read_at(context->analysis->iob.io, xref->from, buf, sizeof(buf));

			RzAnalysisOp aop = { 0 };
			rz_analysis_op_init(&aop);
			rz_analysis_op(context->analysis, &aop, xref->from, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_BASIC);

			if (aop.type == RZ_ANALYSIS_OP_TYPE_MOV || aop.type == RZ_ANALYSIS_OP_TYPE_LEA) {
				rz_list_free(xrefs);
				rz_analysis_op_fini(&aop);
				return true;
			}

			rz_analysis_op_fini(&aop);
		}
	}
	rz_list_free(xrefs);
	return false;
}

static bool vtable_is_addr_vtable_start(RVTableContext *context, RzBinSection *section, ut64 curAddress) {
	if (context->abi == RZ_ANALYSIS_CPP_ABI_MSVC) {
		return vtable_is_addr_vtable_start_msvc(context, curAddress);
	}
	if (context->abi == RZ_ANALYSIS_CPP_ABI_ITANIUM) {
		return vtable_is_addr_vtable_start_itanium(context, section, curAddress);
	}
	rz_return_val_if_reached(false);
}

RZ_API RVTableInfo *rz_analysis_vtable_parse_at(RVTableContext *context, ut64 addr) {
	ut64 offset_to_top;
	if (!context->read_addr(context->analysis, addr - 2 * context->word_size, &offset_to_top)) {
		return NULL;
	}

	RVTableInfo *vtable = calloc(1, sizeof(RVTableInfo));
	if (!vtable) {
		return NULL;
	}

	vtable->saddr = addr;

	rz_vector_init(&vtable->methods, sizeof(RVTableMethodInfo), NULL, NULL);

	RVTableMethodInfo meth;
	while (vtable_is_value_in_text_section(context, addr, &meth.addr)) {
		meth.vtable_offset = addr - vtable->saddr;
		if (!rz_vector_push(&vtable->methods, &meth)) {
			break;
		}

		addr += context->word_size;

		// a ref means the vtable has ended
		RzList *ll = rz_analysis_xrefs_get_to(context->analysis, addr);
		if (!rz_list_empty(ll)) {
			rz_list_free(ll);
			break;
		}
		rz_list_free(ll);
	}
	return vtable;
}

RZ_API RzList /*<RVTableInfo *>*/ *rz_analysis_vtable_search(RVTableContext *context) {
	RzAnalysis *analysis = context->analysis;
	if (!analysis) {
		return NULL;
	}

	RzList *vtables = rz_list_newf((RzListFree)rz_analysis_vtable_info_free);
	if (!vtables) {
		return NULL;
	}

	RzBinObject *obj = rz_bin_cur_object(analysis->binb.bin);
	const RzPVector *sections = obj ? analysis->binb.get_sections(obj) : NULL;
	if (!sections) {
		rz_list_free(vtables);
		return NULL;
	}

	rz_cons_break_push(NULL, NULL);

	void **iter;
	RzBinSection *section;
	rz_pvector_foreach (sections, iter) {
		section = *iter;
		if (rz_cons_is_breaked()) {
			break;
		}

		if (!vtable_section_can_contain_vtables(section)) {
			continue;
		}

		ut64 startAddress = section->vaddr;
		ut64 endAddress = startAddress + (section->vsize) - context->word_size;
		ut64 ss = endAddress - startAddress;
		if (ss > ST32_MAX) {
			break;
		}
		while (startAddress <= endAddress) {
			if (rz_cons_is_breaked()) {
				break;
			}
			if (!analysis->iob.is_valid_offset(analysis->iob.io, startAddress, 0)) {
				break;
			}

			if (vtable_is_addr_vtable_start(context, section, startAddress)) {
				RVTableInfo *vtable = rz_analysis_vtable_parse_at(context, startAddress);
				if (vtable) {
					rz_list_append(vtables, vtable);
					ut64 size = rz_analysis_vtable_info_get_size(context, vtable);
					if (size > 0) {
						startAddress += size;
						continue;
					}
				}
			}
			startAddress += context->word_size;
		}
	}

	rz_cons_break_pop();

	if (rz_list_empty(vtables)) {
		// stripped binary?
		rz_list_free(vtables);
		return NULL;
	}
	return vtables;
}

RZ_API void rz_analysis_list_vtables(RzAnalysis *analysis, RzOutputMode mode) {
	RVTableContext context;
	rz_analysis_vtable_begin(analysis, &context);

	const char *noMethodName = "No Name found";
	RVTableMethodInfo *curMethod;
	RzListIter *vtableIter;
	RVTableInfo *table;

	RzList *vtables = rz_analysis_vtable_search(&context);

	if (mode == RZ_OUTPUT_MODE_JSON) {
		PJ *pj = pj_new();
		if (!pj) {
			rz_list_free(vtables);
			return;
		}
		pj_a(pj);
		rz_list_foreach (vtables, vtableIter, table) {
			pj_o(pj);
			pj_kN(pj, "offset", table->saddr);
			pj_ka(pj, "methods");
			rz_vector_foreach (&table->methods, curMethod) {
				RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(analysis, curMethod->addr, 0);
				const char *const name = fcn ? fcn->name : NULL;
				pj_o(pj);
				pj_kN(pj, "offset", curMethod->addr);
				pj_ks(pj, "name", name ? name : noMethodName);
				pj_end(pj);
			}
			pj_end(pj);
			pj_end(pj);
		}
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	} else if (mode == RZ_OUTPUT_MODE_RIZIN) {
		rz_list_foreach (vtables, vtableIter, table) {
			rz_cons_printf("f vtable.0x%08" PFMT64x " %" PFMT64d " @ 0x%08" PFMT64x "\n",
				table->saddr,
				rz_analysis_vtable_info_get_size(&context, table),
				table->saddr);
			rz_vector_foreach (&table->methods, curMethod) {
				rz_cons_printf("Cd %d @ 0x%08" PFMT64x "\n", context.word_size, table->saddr + curMethod->vtable_offset);
				RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(analysis, curMethod->addr, 0);
				const char *const name = fcn ? fcn->name : NULL;
				if (name) {
					rz_cons_printf("f %s @ 0x%08" PFMT64x "\n", name, curMethod->addr);
				} else {
					rz_cons_printf("f method.virtual.0x%08" PFMT64x " @ 0x%08" PFMT64x "\n", curMethod->addr, curMethod->addr);
				}
			}
		}
	} else {
		rz_list_foreach (vtables, vtableIter, table) {
			ut64 vtableStartAddress = table->saddr;
			rz_cons_printf("\nVtable Found at 0x%08" PFMT64x "\n", vtableStartAddress);
			rz_vector_foreach (&table->methods, curMethod) {
				RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(analysis, curMethod->addr, 0);
				const char *const name = fcn ? fcn->name : NULL;
				rz_cons_printf("0x%08" PFMT64x " : %s\n", vtableStartAddress, name ? name : noMethodName);
				vtableStartAddress += context.word_size;
			}
			rz_cons_newline();
		}
	}
	rz_list_free(vtables);
}
