// SPDX-FileCopyrightText: 2009-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2018 maijin <maijin21@gmail.com>
// SPDX-FileCopyrightText: 2009-2018 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_analysis.h"

#define NAME_BUF_SIZE    64
#define BASE_CLASSES_MAX 32

typedef struct rtti_complete_object_locator_t {
	ut32 signature;
	ut32 vtable_offset; // offset of the vtable within class
	ut32 cd_offset; // constructor displacement offset
	ut32 type_descriptor_addr; // only a relative offset for 64bit
	ut32 class_descriptor_addr; // only a relative offset for 64bit
	ut32 object_base; // only for 64bit, see rtti_msvc_read_complete_object_locator()
} rtti_complete_object_locator;

typedef struct rtti_class_hierarchy_descriptor_t {
	ut32 signature;
	ut32 attributes; // bit 0 set = multiple inheritance, bit 1 set = virtual inheritance
	ut32 num_base_classes;
	ut32 base_class_array_addr; // only a relative offset for 64bit
} rtti_class_hierarchy_descriptor;

typedef struct rtti_base_class_descriptor_t {
	ut32 type_descriptor_addr; // only a relative offset for 64bit
	ut32 num_contained_bases;
	struct {
		st32 mdisp; // member displacement
		st32 pdisp; // vbtable displacement
		st32 vdisp; // displacement inside vbtable
	} where;
	ut32 attributes;
} rtti_base_class_descriptor;

typedef struct rtti_type_descriptor_t {
	ut64 vtable_addr;
	ut64 spare;
	char *name;
} rtti_type_descriptor;

static void rtti_type_descriptor_fini(rtti_type_descriptor *td) {
	free(td->name);
	td->name = NULL;
}

static inline ut64 rtti_msvc_addr(RVTableContext *context, ut64 col_addr, ut64 col_base, ut32 addr) {
	if (context->word_size != 8) {
		return addr;
	}
	return addr + (col_addr - col_base);
}

static bool rtti_msvc_read_complete_object_locator(RVTableContext *context, ut64 addr, rtti_complete_object_locator *col) {
	if (addr == UT64_MAX) {
		return false;
	}

	ut8 buf[6 * sizeof(ut32)];
	int colSize = 5 * sizeof(ut32);
	if (context->word_size == 8) {
		colSize += sizeof(ut32);
	}
	if (colSize > sizeof(buf)) {
		return false;
	}

	if (!context->analysis->iob.read_at(context->analysis->iob.io, addr, buf, colSize)) {
		return false;
	}

	ut32 (*read_at_32)(const void *src, size_t offset) = context->analysis->big_endian ? rz_read_at_be32 : rz_read_at_le32;
	col->signature = read_at_32(buf, 0);
	col->vtable_offset = read_at_32(buf, 4);
	col->cd_offset = read_at_32(buf, 8);

	int offsetSize = RZ_MIN(context->word_size, 4);
	col->type_descriptor_addr = (ut32)rz_read_ble(buf + 12, (bool)context->analysis->big_endian, offsetSize * 8);
	col->class_descriptor_addr = (ut32)rz_read_ble(buf + 12 + offsetSize, (bool)context->analysis->big_endian, offsetSize * 8);
	if (context->word_size == 8) {
		// 64bit is special:
		// Type Descriptor and Class Hierarchy Descriptor addresses are computed
		// by 32 bit values *(col+12) + *(col+0x14)
		// and *(col+16) + *(col+0x14) respectively
		col->object_base = read_at_32(buf, 20);
	} else {
		col->object_base = 0;
	}

	return true;
}

static bool rtti_msvc_read_class_hierarchy_descriptor(RVTableContext *context, ut64 addr, rtti_class_hierarchy_descriptor *chd) {
	if (addr == UT64_MAX) {
		return false;
	}

	ut8 buf[4 * sizeof(ut32)];
	int chdSize = 3 * sizeof(ut32) + RZ_MIN(4, context->word_size);
	if (chdSize > sizeof(buf)) {
		return false;
	}

	if (!context->analysis->iob.read_at(context->analysis->iob.io, addr, buf, chdSize)) {
		return false;
	}

	ut32 (*read_at_32)(const void *src, size_t offset) = context->analysis->big_endian ? rz_read_at_be32 : rz_read_at_le32;
	chd->signature = read_at_32(buf, 0);
	chd->attributes = read_at_32(buf, 4);
	chd->num_base_classes = read_at_32(buf, 8);
	if (context->word_size <= 4) {
		chd->base_class_array_addr = (ut32)rz_read_ble(buf + 12, (bool)context->analysis->big_endian, context->word_size * 8);
	} else {
		// 64bit is special, like in Complete Object Locator.
		// Only the offset from the base from Complete Object Locator
		// is contained in Class Hierarchy Descriptor
		chd->base_class_array_addr = read_at_32(buf, 12);
	}
	return true;
}

static ut64 rtti_msvc_base_class_descriptor_size(RVTableContext *context) {
	return context->word_size + 5 * sizeof(ut32);
}

static bool rtti_msvc_read_base_class_descriptor(RVTableContext *context, ut64 addr, rtti_base_class_descriptor *bcd) {
	if (addr == UT64_MAX) {
		return false;
	}

	ut8 buf[sizeof(ut64) + 5 * sizeof(ut32)];
	int bcdSize = (int)rtti_msvc_base_class_descriptor_size(context);
	if (bcdSize > sizeof(buf)) {
		return false;
	}

	if (!context->analysis->iob.read_at(context->analysis->iob.io, addr, buf, bcdSize)) {
		return false;
	}

	ut32 (*read_at_32)(const void *src, size_t offset) = context->analysis->big_endian ? rz_read_at_be32 : rz_read_at_le32;
	int typeDescriptorAddrSize = RZ_MIN(context->word_size, 4);
	bcd->type_descriptor_addr = (ut32)rz_read_ble(buf, (bool)context->analysis->big_endian, typeDescriptorAddrSize * 8);
	size_t offset = (size_t)typeDescriptorAddrSize;
	bcd->num_contained_bases = read_at_32(buf, offset);
	bcd->where.mdisp = read_at_32(buf, offset + sizeof(ut32));
	bcd->where.pdisp = read_at_32(buf, offset + 2 * sizeof(ut32));
	bcd->where.vdisp = read_at_32(buf, offset + 3 * sizeof(ut32));
	bcd->attributes = read_at_32(buf, offset + 4 * sizeof(ut32));
	return true;
}

static RZ_OWN RzList /*<rtti_base_class_descriptor *>*/ *rtti_msvc_read_base_class_array(RVTableContext *context, ut32 num_base_classes, ut64 base, ut32 offset) {
	if (base == UT64_MAX || offset == UT32_MAX || num_base_classes == UT32_MAX) {
		return NULL;
	}

	RzList *ret = rz_list_newf(free);
	if (!ret) {
		return NULL;
	}

	ut64 addr = base + offset;
	ut64 stride = RZ_MIN(context->word_size, 4);

	if (num_base_classes > BASE_CLASSES_MAX) {
		RZ_LOG_DEBUG("Length of base class array at 0x%08" PFMT64x " exceeds %d.\n", addr, BASE_CLASSES_MAX);
		num_base_classes = BASE_CLASSES_MAX;
	}

	rz_cons_break_push(NULL, NULL);
	while (num_base_classes > 0) {
		if (rz_cons_is_breaked()) {
			break;
		}

		ut64 bcdAddr;
		if (context->word_size <= 4) {
			if (!context->read_addr(context->analysis, addr, &bcdAddr)) {
				break;
			}
			if (bcdAddr == UT32_MAX) {
				break;
			}
		} else {
			// special offset calculation for 64bit
			ut8 tmp[4] = { 0 };
			if (!context->analysis->iob.read_at(context->analysis->iob.io, addr, tmp, 4)) {
				rz_list_free(ret);
				rz_cons_break_pop();
				return NULL;
			}
			ut32 (*read_32)(const void *src) = context->analysis->big_endian ? rz_read_be32 : rz_read_le32;
			ut32 bcdOffset = read_32(tmp);
			if (bcdOffset == UT32_MAX) {
				break;
			}
			bcdAddr = base + bcdOffset;
		}

		rtti_base_class_descriptor *bcd = malloc(sizeof(rtti_base_class_descriptor));
		if (!bcd) {
			break;
		}
		if (!rtti_msvc_read_base_class_descriptor(context, bcdAddr, bcd)) {
			free(bcd);
			break;
		}
		rz_list_append(ret, bcd);
		addr += stride;
		num_base_classes--;
	}
	rz_cons_break_pop();

	if (num_base_classes > 0) {
		// there was an error in the loop above
		rz_list_free(ret);
		return NULL;
	}

	return ret;
}

static bool rtti_msvc_read_type_descriptor(RVTableContext *context, ut64 addr, rtti_type_descriptor *td) {
	if (addr == UT64_MAX) {
		return false;
	}

	if (!context->read_addr(context->analysis, addr, &td->vtable_addr)) {
		return false;
	}
	if (!context->read_addr(context->analysis, addr + context->word_size, &td->spare)) {
		return false;
	}

	ut64 nameAddr = addr + 2 * context->word_size;
	ut8 buf[NAME_BUF_SIZE];
	ut64 bufOffset = 0;
	size_t nameLen = 0;
	bool endFound = false;
	bool endInvalid = false;
	while (1) {
		context->analysis->iob.read_at(context->analysis->iob.io, nameAddr + bufOffset, buf, sizeof(buf));
		int i;
		for (i = 0; i < sizeof(buf); i++) {
			if (buf[i] == '\0') {
				endFound = true;
				break;
			}
			if (buf[i] == 0xff) {
				endInvalid = true;
				break;
			}
			nameLen++;
		}
		if (endFound || endInvalid) {
			break;
		}
		bufOffset += sizeof(buf);
	}

	if (endInvalid) {
		return false;
	}

	td->name = malloc(nameLen + 1);
	if (!td->name) {
		return false;
	}

	if (bufOffset == 0) {
		memcpy(td->name, buf, nameLen + 1);
	} else {
		context->analysis->iob.read_at(context->analysis->iob.io, nameAddr,
			(ut8 *)td->name, (int)(nameLen + 1));
	}

	return true;
}

static void rtti_msvc_print_complete_object_locator(rtti_complete_object_locator *col, ut64 addr, const char *prefix) {
	rz_cons_printf("%sComplete Object Locator at 0x%08" PFMT64x ":\n"
		       "%s\tsignature: %#x\n"
		       "%s\tvftableOffset: %#x\n"
		       "%s\tcdOffset: %#x\n"
		       "%s\ttypeDescriptorAddr: 0x%08" PFMT32x "\n"
		       "%s\tclassDescriptorAddr: 0x%08" PFMT32x "\n",
		prefix, addr,
		prefix, col->signature,
		prefix, col->vtable_offset,
		prefix, col->cd_offset,
		prefix, col->type_descriptor_addr,
		prefix, col->class_descriptor_addr);
	rz_cons_printf("%s\tobjectBase: 0x%08" PFMT32x "\n\n",
		prefix, col->object_base);
}

static void rtti_msvc_print_complete_object_locator_json(PJ *pj, rtti_complete_object_locator *col) {
	pj_o(pj);
	pj_kn(pj, "signature", col->signature);
	pj_kn(pj, "vftable_offset", col->vtable_offset);
	pj_kn(pj, "cd_offset", col->cd_offset);
	pj_kn(pj, "type_desc_addr", col->type_descriptor_addr);
	pj_kn(pj, "class_desc_addr", col->class_descriptor_addr);
	pj_kn(pj, "object_base", col->object_base);
	pj_end(pj);
}

static void rtti_msvc_print_type_descriptor(rtti_type_descriptor *td, ut64 addr, const char *prefix) {
	rz_cons_printf("%sType Descriptor at 0x%08" PFMT64x ":\n"
		       "%s\tvtableAddr: 0x%08" PFMT64x "\n"
		       "%s\tspare: 0x%08" PFMT64x "\n"
		       "%s\tname: %s\n\n",
		prefix, addr,
		prefix, td->vtable_addr,
		prefix, td->spare,
		prefix, td->name);
}

static void rtti_msvc_print_type_descriptor_json(PJ *pj, rtti_type_descriptor *td) {
	pj_o(pj);
	pj_kn(pj, "vtable_addr", td->vtable_addr);
	pj_kn(pj, "spare", td->spare);
	pj_ks(pj, "name", td->name);
	pj_end(pj);
}

static void rtti_msvc_print_class_hierarchy_descriptor(rtti_class_hierarchy_descriptor *chd, ut64 addr, const char *prefix) {
	rz_cons_printf("%sClass Hierarchy Descriptor at 0x%08" PFMT64x ":\n"
		       "%s\tsignature: %#x\n"
		       "%s\tattributes: %#x\n"
		       "%s\tnumBaseClasses: %#x\n"
		       "%s\tbaseClassArrayAddr: 0x%08" PFMT32x "\n\n",
		prefix, addr,
		prefix, chd->signature,
		prefix, chd->attributes,
		prefix, chd->num_base_classes,
		prefix, chd->base_class_array_addr);
}

static void rtti_msvc_print_class_hierarchy_descriptor_json(PJ *pj, rtti_class_hierarchy_descriptor *chd) {
	pj_o(pj);
	pj_kn(pj, "signature", chd->signature);
	pj_kn(pj, "attributes", chd->attributes);
	pj_kn(pj, "num_base_classes", chd->num_base_classes);
	pj_kn(pj, "base_class_array_addr", chd->base_class_array_addr);
	pj_end(pj);
}

static void rtti_msvc_print_base_class_descriptor(rtti_base_class_descriptor *bcd, const char *prefix) {
	rz_cons_printf("%sBase Class Descriptor:\n"
		       "%s\ttypeDescriptorAddr: 0x%08" PFMT32x "\n"
		       "%s\tnumContainedBases: %#x\n"
		       "%s\twhere:\n"
		       "%s\t\tmdisp: %d\n"
		       "%s\t\tpdisp: %d\n"
		       "%s\t\tvdisp: %d\n"
		       "%s\tattributes: %#x\n\n",
		prefix,
		prefix, bcd->type_descriptor_addr,
		prefix, bcd->num_contained_bases,
		prefix,
		prefix, bcd->where.mdisp,
		prefix, bcd->where.pdisp,
		prefix, bcd->where.vdisp,
		prefix, bcd->attributes);
}

static void rtti_msvc_print_base_class_descriptor_json(PJ *pj, rtti_base_class_descriptor *bcd) {
	pj_o(pj);
	pj_kn(pj, "type_desc_addr", bcd->type_descriptor_addr);
	pj_kn(pj, "num_contained_bases", bcd->num_contained_bases);
	pj_ko(pj, "where");
	pj_ki(pj, "mdisp", bcd->where.mdisp);
	pj_ki(pj, "pdisp", bcd->where.pdisp);
	pj_ki(pj, "vdisp", bcd->where.vdisp);
	pj_end(pj);
	pj_kn(pj, "attributes", bcd->attributes);
	pj_end(pj);
}

/**
 * Demangle a class name as found in MSVC RTTI type descriptors.
 *
 * Examples:
 * .?AVClassA@@
 * => ClassA
 * .?AVClassInInnerNamespace@InnerNamespace@OuterNamespace@@
 * => OuterNamespace::InnerNamespace::AVClassInInnerNamespace
 */
RZ_API char *rz_analysis_rtti_msvc_demangle_class_name(RVTableContext *context, const char *name) {
	if (!name) {
		return NULL;
	}
	size_t original_len = strlen(name);
	if (original_len < 7 || (strncmp(name, ".?AV", 4) != 0 && strncmp(name, ".?AU", 4) != 0) || strncmp(name + original_len - 2, "@@", 2) != 0) {
		return NULL;
	}
	char *ret = context->analysis->binb.demangle(NULL, "msvc", name);
	if (ret && *ret) {
		char *n = strchr(ret, ' ');
		if (n && *(++n)) {
			char *tmp = strdup(n);
			free(ret);
			ret = tmp;
		} else {
			RZ_FREE(ret);
		}
	} else {
		RZ_FREE(ret);
	}
	return ret;
}

RZ_API void rz_analysis_rtti_msvc_print_complete_object_locator(RVTableContext *context, ut64 addr, int mode) {
	rtti_complete_object_locator col;
	if (!rtti_msvc_read_complete_object_locator(context, addr, &col)) {
		RZ_LOG_ERROR("Failed to parse complete object locator at 0x%08" PFMT64x "\n", addr);
		return;
	}

	if (mode == 'j') {
		PJ *pj = pj_new();
		if (!pj) {
			return;
		}
		rtti_msvc_print_complete_object_locator_json(pj, &col);
		rz_cons_print(pj_string(pj));
		pj_free(pj);
	} else {
		rtti_msvc_print_complete_object_locator(&col, addr, "");
	}
}

RZ_API void rz_analysis_rtti_msvc_print_type_descriptor(RVTableContext *context, ut64 addr, int mode) {
	rtti_type_descriptor td = { 0 };
	if (!rtti_msvc_read_type_descriptor(context, addr, &td)) {
		RZ_LOG_ERROR("Failed to parse type descriptor at 0x%08" PFMT64x "\n", addr);
		return;
	}

	if (mode == 'j') {
		PJ *pj = pj_new();
		if (!pj) {
			return;
		}
		rtti_msvc_print_type_descriptor_json(pj, &td);
		rz_cons_print(pj_string(pj));
		pj_free(pj);
	} else {
		rtti_msvc_print_type_descriptor(&td, addr, "");
	}

	rtti_type_descriptor_fini(&td);
}

RZ_API void rz_analysis_rtti_msvc_print_class_hierarchy_descriptor(RVTableContext *context, ut64 addr, int mode) {
	rtti_class_hierarchy_descriptor chd;
	if (!rtti_msvc_read_class_hierarchy_descriptor(context, addr, &chd)) {
		RZ_LOG_ERROR("Failed to parse class hierarchy descriptor at 0x%08" PFMT64x "\n", addr);
		return;
	}

	if (mode == 'j') {
		PJ *pj = pj_new();
		if (!pj) {
			return;
		}
		rtti_msvc_print_class_hierarchy_descriptor_json(pj, &chd);
		rz_cons_print(pj_string(pj));
		pj_free(pj);
	} else {
		rtti_msvc_print_class_hierarchy_descriptor(&chd, addr, "");
	}
}

RZ_API void rz_analysis_rtti_msvc_print_base_class_descriptor(RVTableContext *context, ut64 addr, int mode) {
	rtti_base_class_descriptor bcd;
	if (!rtti_msvc_read_base_class_descriptor(context, addr, &bcd)) {
		RZ_LOG_ERROR("Failed to parse base class descriptor at 0x%08" PFMT64x "\n", addr);
		return;
	}

	if (mode == 'j') {
		PJ *pj = pj_new();
		if (!pj) {
			return;
		}
		rtti_msvc_print_base_class_descriptor_json(pj, &bcd);
		rz_cons_print(pj_string(pj));
		pj_free(pj);
	} else {
		rtti_msvc_print_base_class_descriptor(&bcd, "");
	}
}

static bool rtti_msvc_print_complete_object_locator_recurse(RVTableContext *context, ut64 atAddress, RzOutputMode mode, bool strict) {
	ut64 colRefAddr = atAddress - context->word_size;
	ut64 colAddr;
	if (!context->read_addr(context->analysis, colRefAddr, &colAddr)) {
		return false;
	}

	// complete object locator
	rtti_complete_object_locator col;
	if (!rtti_msvc_read_complete_object_locator(context, colAddr, &col)) {
		if (!strict) {
			RZ_LOG_ERROR("Failed to parse complete object locator at 0x%08" PFMT64x " (referenced from 0x%08" PFMT64x ")\n", colAddr, colRefAddr);
		}
		return false;
	}

	// type descriptor
	ut64 typeDescriptorAddr = rtti_msvc_addr(context, colAddr, col.object_base, col.type_descriptor_addr);
	rtti_type_descriptor td = { 0 };
	if (!rtti_msvc_read_type_descriptor(context, typeDescriptorAddr, &td)) {
		if (!strict) {
			RZ_LOG_ERROR("Failed to parse type descriptor at 0x%08" PFMT64x "\n", typeDescriptorAddr);
		}
		return false;
	}

	// class hierarchy descriptor
	ut64 classHierarchyDescriptorAddr = rtti_msvc_addr(context, colAddr, col.object_base, col.class_descriptor_addr);
	rtti_class_hierarchy_descriptor chd;
	if (!rtti_msvc_read_class_hierarchy_descriptor(context, classHierarchyDescriptorAddr, &chd)) {
		if (!strict) {
			RZ_LOG_ERROR("Failed to parse class hierarchy descriptor at 0x%08" PFMT64x "\n", classHierarchyDescriptorAddr);
		}
		rtti_type_descriptor_fini(&td);
		return false;
	}

	ut64 base = chd.base_class_array_addr;
	ut32 baseClassArrayOffset = 0;
	if (context->word_size == 8) {
		base = colAddr - col.object_base;
		baseClassArrayOffset = chd.base_class_array_addr;
	}

	RzList *baseClassArray = rtti_msvc_read_base_class_array(context, chd.num_base_classes, base, baseClassArrayOffset);
	if (!baseClassArray) {
		if (!strict) {
			RZ_LOG_ERROR("Failed to parse base class array starting at 0x%08" PFMT64x "\n", base + baseClassArrayOffset);
		}
		rtti_type_descriptor_fini(&td);
		return false;
	}

	// print
	bool use_json = mode == RZ_OUTPUT_MODE_JSON;
	PJ *pj = NULL;
	if (use_json) {
		pj = pj_new();
		if (!pj) {
			return false;
		}
		pj_o(pj);
		pj_k(pj, "complete_object_locator");
		rtti_msvc_print_complete_object_locator_json(pj, &col);
		pj_k(pj, "type_desc");
		rtti_msvc_print_type_descriptor_json(pj, &td);
		pj_k(pj, "class_hierarchy_desc");
		rtti_msvc_print_class_hierarchy_descriptor_json(pj, &chd);
		pj_ka(pj, "base_classes");
	} else {
		rtti_msvc_print_complete_object_locator(&col, colAddr, "");
		rtti_msvc_print_type_descriptor(&td, typeDescriptorAddr, "\t");
		rtti_msvc_print_class_hierarchy_descriptor(&chd, classHierarchyDescriptorAddr, "\t");
	}

	// base classes
	RzListIter *bcdIter;
	rtti_base_class_descriptor *bcd;
	rz_list_foreach (baseClassArray, bcdIter, bcd) {
		if (use_json) {
			pj_o(pj);
			pj_k(pj, "desc");
			rtti_msvc_print_base_class_descriptor_json(pj, bcd);
		} else {
			rtti_msvc_print_base_class_descriptor(bcd, "\t\t");
		}

		ut64 baseTypeDescriptorAddr = rtti_msvc_addr(context, colAddr, col.object_base, bcd->type_descriptor_addr);
		rtti_type_descriptor btd = { 0 };
		if (rtti_msvc_read_type_descriptor(context, baseTypeDescriptorAddr, &btd)) {
			if (use_json) {
				pj_k(pj, "type_desc");
				rtti_msvc_print_type_descriptor_json(pj, &btd);
			} else {
				rtti_msvc_print_type_descriptor(&btd, baseTypeDescriptorAddr, "\t\t\t");
			}
			rtti_type_descriptor_fini(&btd);
		} else {
			if (!strict) {
				RZ_LOG_ERROR("Failed to parse type descriptor at 0x%08" PFMT64x "\n", baseTypeDescriptorAddr);
			}
		}

		if (use_json) {
			pj_end(pj);
		}
	}
	if (use_json) {
		pj_end(pj);
		pj_end(pj);
		rz_cons_print(pj_string(pj));
		pj_free(pj);
	}

	rz_list_free(baseClassArray);
	rtti_type_descriptor_fini(&td);
	return true;
}

RZ_API bool rz_analysis_rtti_msvc_print_at_vtable(RVTableContext *context, ut64 addr, RzOutputMode mode, bool strict) {
	return rtti_msvc_print_complete_object_locator_recurse(context, addr, mode, strict);
}

typedef struct recovery_type_descriptor_t RecoveryTypeDescriptor;

typedef struct recovery_base_descriptor_t {
	rtti_base_class_descriptor *bcd;
	RecoveryTypeDescriptor *td;
} RecoveryBaseDescriptor;

typedef struct recovery_complete_object_locator_t {
	ut64 addr;
	bool valid;
	RVTableInfo *vtable;
	rtti_complete_object_locator col;
	RecoveryTypeDescriptor *td;
	rtti_class_hierarchy_descriptor chd;
	RzList /*<rtti_base_class_descriptor *>*/ *bcd;
	RzVector /*<RecoveryBaseDescriptor>*/ base_td;
} RecoveryCompleteObjectLocator;

RecoveryCompleteObjectLocator *recovery_complete_object_locator_new() {
	RecoveryCompleteObjectLocator *col = RZ_NEW0(RecoveryCompleteObjectLocator);
	if (!col) {
		return NULL;
	}
	rz_vector_init(&col->base_td, sizeof(RecoveryBaseDescriptor), NULL, NULL);
	return col;
}

void recovery_complete_object_locator_free(RecoveryCompleteObjectLocator *col) {
	if (!col) {
		return;
	}
	rz_list_free(col->bcd);
	rz_vector_clear(&col->base_td);
	free(col);
}

struct recovery_type_descriptor_t {
	ut64 addr;
	bool valid;
	rtti_type_descriptor td;
	RecoveryCompleteObjectLocator *col;
};

RecoveryTypeDescriptor *recovery_type_descriptor_new() {
	RecoveryTypeDescriptor *td = RZ_NEW(RecoveryTypeDescriptor);
	if (!td) {
		return NULL;
	}

	td->addr = 0;
	td->valid = false;
	memset(&td->td, 0, sizeof(td->td));
	td->col = NULL;
	// td->vtable = NULL;
	return td;
}

void recovery_type_descriptor_free(RecoveryTypeDescriptor *td) {
	if (!td) {
		return;
	}
	rtti_type_descriptor_fini(&td->td);
	free(td);
}

typedef struct rtti_msvc_analysis_context_t {
	RVTableContext *vt_context;
	RzPVector /*<RVTableInfo *>*/ vtables;
	RzPVector /*<RecoveryCompleteObjectLocator *>*/ complete_object_locators;
	HtUP *addr_col; // <ut64, RecoveryCompleteObjectLocator *>
	RzPVector /*<RecoveryTypeDescriptor *>*/ type_descriptors;
	HtUP *addr_td; // <ut64, RecoveryTypeDescriptor *>
	HtUP *col_td_classes; // <ut64, char *> contains already recovered classes for col (or td) addresses
} RRTTIMSVCAnalContext;

RecoveryTypeDescriptor *recovery_analysis_type_descriptor(RRTTIMSVCAnalContext *context, ut64 addr, RecoveryCompleteObjectLocator *col);

RecoveryCompleteObjectLocator *recovery_analysis_complete_object_locator(RRTTIMSVCAnalContext *context, ut64 addr, RVTableInfo *vtable) {
	RecoveryCompleteObjectLocator *col = ht_up_find(context->addr_col, addr, NULL);
	if (col) {
		return col;
	}

	col = recovery_complete_object_locator_new();
	if (!col) {
		return NULL;
	}
	rz_pvector_push(&context->complete_object_locators, col);
	ht_up_insert(context->addr_col, addr, col, NULL);
	col->addr = addr;
	col->valid = rtti_msvc_read_complete_object_locator(context->vt_context, addr, &col->col);
	if (!col->valid) {
		return col;
	}
	col->vtable = vtable;

	ut64 td_addr = rtti_msvc_addr(context->vt_context, col->addr, col->col.object_base, col->col.type_descriptor_addr);
	col->td = recovery_analysis_type_descriptor(context, td_addr, col);
	if (!col->td->valid) {
		col->valid = false;
		return col;
	}
	col->td->col = col;

	ut64 chd_addr = rtti_msvc_addr(context->vt_context, col->addr, col->col.object_base, col->col.class_descriptor_addr);
	col->valid &= rtti_msvc_read_class_hierarchy_descriptor(context->vt_context, chd_addr, &col->chd);
	if (!col->valid) {
		return col;
	}

	ut64 base = col->chd.base_class_array_addr;
	ut32 baseClassArrayOffset = 0;
	if (context->vt_context->word_size == 8) {
		base = col->addr - col->col.object_base;
		baseClassArrayOffset = col->chd.base_class_array_addr;
	}

	col->bcd = rtti_msvc_read_base_class_array(context->vt_context, col->chd.num_base_classes, base, baseClassArrayOffset);
	if (!col->bcd) {
		col->valid = false;
		return col;
	}

	rz_vector_reserve(&col->base_td, (size_t)col->bcd->length);
	RzListIter *bcdIter;
	rtti_base_class_descriptor *bcd;
	rz_list_foreach (col->bcd, bcdIter, bcd) {
		ut64 base_td_addr = rtti_msvc_addr(context->vt_context, col->addr, col->col.object_base, bcd->type_descriptor_addr);
		RecoveryTypeDescriptor *td = recovery_analysis_type_descriptor(context, base_td_addr, NULL);
		if (td == col->td) {
			continue;
		}
		if (!td->valid) {
			RZ_LOG_DEBUG("Type descriptor of base is invalid.\n");
			continue;
		}
		RecoveryBaseDescriptor *base_desc = rz_vector_push(&col->base_td, NULL);
		base_desc->bcd = bcd;
		base_desc->td = td;
	}

	return col;
}

RecoveryTypeDescriptor *recovery_analysis_type_descriptor(RRTTIMSVCAnalContext *context, ut64 addr, RecoveryCompleteObjectLocator *col) {
	RecoveryTypeDescriptor *td = ht_up_find(context->addr_td, addr, NULL);
	if (td) {
		if (col != NULL) {
			td->col = col;
		}
		return td;
	}

	td = recovery_type_descriptor_new();
	if (!td) {
		return NULL;
	}
	rz_pvector_push(&context->type_descriptors, td);
	ht_up_insert(context->addr_td, addr, td, NULL);
	td->addr = addr;
	td->valid = rtti_msvc_read_type_descriptor(context->vt_context, addr, &td->td);
	if (!td->valid) {
		return td;
	}

	td->col = col;

	return td;
}

static char *unique_class_name(RzAnalysis *analysis, const char *original_name) {
	if (!rz_analysis_class_exists(analysis, original_name)) {
		return strdup(original_name);
	}

	char *name = NULL;
	RZ_LOG_DEBUG("Class name '%s' was already taken!\n", original_name);
	int i = 1;
	do {
		free(name);
		name = rz_str_newf("%s.%d", original_name, i++);
		if (!name) {
			return NULL;
		}
	} while (rz_analysis_class_exists(analysis, name));

	return name;
}

static void recovery_apply_vtable(RVTableContext *context, const char *class_name, RVTableInfo *vtable_info) {
	if (!vtable_info) {
		return;
	}

	ut64 size = rz_analysis_vtable_info_get_size(context, vtable_info);

	RzAnalysisVTable vtable;
	vtable.size = size;
	vtable.id = NULL;
	vtable.offset = 0;
	vtable.addr = vtable_info->saddr;
	rz_analysis_class_vtable_set(context->analysis, class_name, &vtable);
	rz_analysis_class_vtable_fini(&vtable);

	RVTableMethodInfo *vmeth;
	rz_vector_foreach (&vtable_info->methods, vmeth) {
		RzAnalysisMethod meth;
		if (!rz_analysis_class_method_exists_by_addr(context->analysis, class_name, vmeth->addr)) {
			meth.addr = vmeth->addr;
			meth.vtable_offset = vmeth->vtable_offset;
			RzAnalysisFunction *fcn = rz_analysis_get_function_at(context->analysis, vmeth->addr);
			meth.name = fcn ? rz_str_dup(fcn->name) : rz_str_newf("virtual_%" PFMT64d, meth.vtable_offset);
			// Temporarily set as attr name
			meth.real_name = fcn ? rz_str_dup(fcn->name) : rz_str_newf("virtual_%" PFMT64d, meth.vtable_offset);
			meth.method_type = RZ_ANALYSIS_CLASS_METHOD_VIRTUAL;
		} else {
			RzAnalysisMethod exist_meth;
			if (rz_analysis_class_method_get_by_addr(context->analysis, class_name, vmeth->addr, &exist_meth) == RZ_ANALYSIS_CLASS_ERR_SUCCESS) {
				meth.addr = vmeth->addr;
				meth.name = rz_str_dup(exist_meth.name);
				meth.real_name = rz_str_dup(exist_meth.real_name);
				meth.vtable_offset = vmeth->vtable_offset;
				meth.method_type = RZ_ANALYSIS_CLASS_METHOD_VIRTUAL;
				rz_analysis_class_method_fini(&exist_meth);
			}
		}
		rz_analysis_class_method_set(context->analysis, class_name, &meth);
		rz_analysis_class_method_fini(&meth);
	}
}

static const char *recovery_apply_complete_object_locator(RRTTIMSVCAnalContext *context, RecoveryCompleteObjectLocator *col);
static const char *recovery_apply_type_descriptor(RRTTIMSVCAnalContext *context, RecoveryTypeDescriptor *td);

static void recovery_apply_bases(RRTTIMSVCAnalContext *context, const char *class_name, RzVector /*<RecoveryBaseDescriptor>*/ *base_descs) {
	RecoveryBaseDescriptor *base_desc;
	rz_vector_foreach (base_descs, base_desc) {
		RecoveryTypeDescriptor *base_td = base_desc->td;
		if (!base_td->valid) {
			RZ_LOG_WARN("Base td is invalid!\n");
			continue;
		}

		const char *base_class_name;
		if (!base_td->col) {
			RZ_LOG_DEBUG("Base td %s has no col. Falling back to recovery from td only.\n", base_td->td.name);
			base_class_name = recovery_apply_type_descriptor(context, base_td);
		} else {
			base_class_name = recovery_apply_complete_object_locator(context, base_td->col);
		}

		if (!base_class_name) {
			RZ_LOG_DEBUG("Failed to convert !base td->col or td to a class\n");
			continue;
		}

		RzAnalysisBaseClass base;
		base.id = NULL;
		base.offset = (ut64)base_desc->bcd->where.mdisp;
		base.class_name = strdup(base_class_name);
		rz_analysis_class_base_set(context->vt_context->analysis, class_name, &base);
		rz_analysis_class_base_fini(&base);
	}
}

static const char *recovery_apply_complete_object_locator(RRTTIMSVCAnalContext *context, RecoveryCompleteObjectLocator *col) {
	if (!col->valid) {
		return NULL;
	}

	if (!col->td) {
		RZ_LOG_DEBUG("No recovery type descriptor for recovery object locator at 0x%" PFMT64x "\n", col->addr);
		return NULL;
	}

	RzAnalysis *analysis = context->vt_context->analysis;

	const char *existing = ht_up_find(context->col_td_classes, col->addr, NULL);
	if (existing != NULL) {
		return existing;
	}

	char *name = rz_analysis_rtti_msvc_demangle_class_name(context->vt_context, col->td->td.name);
	if (!name) {
		RZ_LOG_DEBUG("Failed to demangle a class name: \"%s\"\n", col->td->td.name);
		name = strdup(col->td->td.name);
		if (!name) {
			return NULL;
		}
	}

	char *tmp = name;
	name = unique_class_name(analysis, name);
	free(tmp);
	if (!name) {
		return NULL;
	}

	rz_analysis_class_create(analysis, name);
	ht_up_insert(context->col_td_classes, col->addr, name, NULL);

	recovery_apply_vtable(context->vt_context, name, col->vtable);
	recovery_apply_bases(context, name, &col->base_td);

	return name;
}

static const char *recovery_apply_type_descriptor(RRTTIMSVCAnalContext *context, RecoveryTypeDescriptor *td) {
	if (!td->valid) {
		return NULL;
	}

	RzAnalysis *analysis = context->vt_context->analysis;

	const char *existing = ht_up_find(context->col_td_classes, td->addr, NULL);
	if (existing != NULL) {
		return existing;
	}

	char *name = rz_analysis_rtti_msvc_demangle_class_name(context->vt_context, td->td.name);
	if (!name) {
		RZ_LOG_DEBUG("Failed to demangle a class name: \"%s\"\n", td->td.name);
		name = strdup(td->td.name);
		if (!name) {
			return NULL;
		}
	}

	rz_analysis_class_create(analysis, name);
	ht_up_insert(context->col_td_classes, td->addr, name, NULL);

	if (!td->col || !td->col->valid) {
		return name;
	}

	recovery_apply_vtable(context->vt_context, name, td->col->vtable);
	recovery_apply_bases(context, name, &td->col->base_td);

	return name;
}

RZ_API void rz_analysis_rtti_msvc_recover_all(RVTableContext *vt_context, RzList /*<RVTableInfo *>*/ *vtables) {
	RRTTIMSVCAnalContext context;
	context.vt_context = vt_context;
	rz_pvector_init(&context.vtables, (RzPVectorFree)rz_analysis_vtable_info_free);

	rz_pvector_init(&context.complete_object_locators, (RzPVectorFree)recovery_complete_object_locator_free);
	context.addr_col = ht_up_new(NULL, NULL);
	rz_pvector_init(&context.type_descriptors, (RzPVectorFree)recovery_type_descriptor_free);
	context.addr_td = ht_up_new(NULL, NULL);

	context.col_td_classes = ht_up_new(NULL, free);

	RzListIter *vtableIter;
	RVTableInfo *table;
	rz_list_foreach (vtables, vtableIter, table) {
		ut64 colRefAddr = table->saddr - vt_context->word_size;
		ut64 colAddr;
		if (!vt_context->read_addr(vt_context->analysis, colRefAddr, &colAddr)) {
			continue;
		}
		recovery_analysis_complete_object_locator(&context, colAddr, table);
	}

	void **it;
#if USE_TD_RECOVERY
	rz_pvector_foreach (&context.type_descriptors, it) {
		RecoveryTypeDescriptor *td = *it;
		if (!td->valid) {
			continue;
		}
		recovery_apply_type_descriptor(&context, td);
	}
#else
	rz_pvector_foreach (&context.complete_object_locators, it) {
		RecoveryCompleteObjectLocator *col = *it;
		if (!col->valid) {
			continue;
		}
		recovery_apply_complete_object_locator(&context, col);
	}
#endif

	rz_pvector_clear(&context.vtables);
	rz_pvector_clear(&context.complete_object_locators);
	ht_up_free(context.addr_col);
	rz_pvector_clear(&context.type_descriptors);
	ht_up_free(context.addr_td);
	ht_up_free(context.col_td_classes);
}
