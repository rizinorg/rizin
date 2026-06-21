// SPDX-FileCopyrightText: 2020 abcSup <zifan.tan@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_util/rz_print.h>
#include <rz_lib.h>
#include <rz_bin.h>

#include "dmp/dmp64.h"

static Sdb *dmp64_get_sdb(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);
	struct rz_bin_dmp64_obj_t *obj = (struct rz_bin_dmp64_obj_t *)bf->o->bin_obj;
	return (obj && obj->kv) ? obj->kv : NULL;
}

static void dmp64_destroy(RzBinFile *bf) {
	rz_bin_dmp64_free((struct rz_bin_dmp64_obj_t *)bf->o->bin_obj);
}

static RzStructuredData *dmp64_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->rbin && bf->o && bf->o->bin_obj, NULL);
	struct rz_bin_dmp64_obj_t *obj = (struct rz_bin_dmp64_obj_t *)bf->o->bin_obj;

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *dmp64 = rz_structured_data_map_add_map(info, "dmp64");
	if (!dmp64) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(dmp64, "MajorVersion", obj->header->MajorVersion, true);
	rz_structured_data_map_add_unsigned(dmp64, "MinorVersion", obj->header->MinorVersion, true);
	rz_structured_data_map_add_unsigned(dmp64, "DirectoryTableBase", obj->header->DirectoryTableBase, true);
	rz_structured_data_map_add_unsigned(dmp64, "PfnDataBase", obj->header->PfnDataBase, true);
	rz_structured_data_map_add_unsigned(dmp64, "PsLoadedModuleList", obj->header->PsLoadedModuleList, true);
	rz_structured_data_map_add_unsigned(dmp64, "PsActiveProcessHead", obj->header->PsActiveProcessHead, true);
	rz_structured_data_map_add_unsigned(dmp64, "MachineImageType", obj->header->MachineImageType, true);
	rz_structured_data_map_add_unsigned(dmp64, "NumberProcessors", obj->header->NumberProcessors, true);
	{
		RzStructuredData *bug_check_code = rz_structured_data_map_add_map(dmp64, "BugCheckCode");
		if (!bug_check_code) {
			rz_structured_data_free(info);
			return NULL;
		}
		rz_structured_data_map_add_unsigned(bug_check_code, "Value", obj->header->BugCheckCode, true);
		rz_structured_data_map_add_string(bug_check_code, "Meaning", rz_bin_dmp64_bugcheckcode_as_str(obj->header->BugCheckCode));
	}
	rz_structured_data_map_add_unsigned(dmp64, "BugCheckParameter1", obj->header->BugCheckParameter1, true);
	rz_structured_data_map_add_unsigned(dmp64, "BugCheckParameter2", obj->header->BugCheckParameter2, true);
	rz_structured_data_map_add_unsigned(dmp64, "BugCheckParameter3", obj->header->BugCheckParameter3, true);
	rz_structured_data_map_add_unsigned(dmp64, "BugCheckParameter4", obj->header->BugCheckParameter4, true);
	rz_structured_data_map_add_unsigned(dmp64, "KdDebuggerDataBlock", obj->header->KdDebuggerDataBlock, true);
	rz_structured_data_map_add_unsigned(dmp64, "SecondaryDataState", obj->header->SecondaryDataState, true);
	rz_structured_data_map_add_unsigned(dmp64, "ProductType", obj->header->ProductType, true);
	rz_structured_data_map_add_unsigned(dmp64, "SuiteMask", obj->header->SuiteMask, true);

	if (obj->bmp_header) {
		RzStructuredData *bitmap = rz_structured_data_map_add_map(dmp64, "Bitmap");
		if (!bitmap) {
			rz_structured_data_free(info);
			return NULL;
		}
		rz_structured_data_map_add_unsigned(bitmap, "HeaderSize", obj->bmp_header->FirstPage, true);
		rz_structured_data_map_add_unsigned(bitmap, "BitmapSize", obj->bmp_header->Pages, true);
		rz_structured_data_map_add_unsigned(bitmap, "Pages", obj->bmp_header->TotalPresentPages, true);
	}

	if (obj->triage64_header) {
		RzStructuredData *triage64 = rz_structured_data_map_add_map(dmp64, "TriageDump64");
		if (!triage64) {
			rz_structured_data_free(info);
			return NULL;
		}
		rz_structured_data_map_add_unsigned(triage64, "ServicePackBuild", obj->triage64_header->ServicePackBuild, true);
		rz_structured_data_map_add_unsigned(triage64, "SizeOfDump", obj->triage64_header->SizeOfDump, true);
		rz_structured_data_map_add_unsigned(triage64, "ValidOffset", obj->triage64_header->ValidOffset, true);
		rz_structured_data_map_add_unsigned(triage64, "ContextOffset", obj->triage64_header->ContextOffset, true);
		rz_structured_data_map_add_unsigned(triage64, "ExceptionOffset", obj->triage64_header->ExceptionOffset, true);
		rz_structured_data_map_add_unsigned(triage64, "MmOffset", obj->triage64_header->MmOffset, true);
		rz_structured_data_map_add_unsigned(triage64, "UnloadedDriversOffset", obj->triage64_header->UnloadedDriversOffset, true);
		rz_structured_data_map_add_unsigned(triage64, "PrcbOffset", obj->triage64_header->PrcbOffset, true);
		rz_structured_data_map_add_unsigned(triage64, "ProcessOffset", obj->triage64_header->ProcessOffset, true);
		rz_structured_data_map_add_unsigned(triage64, "ThreadOffset", obj->triage64_header->ThreadOffset, true);
		rz_structured_data_map_add_unsigned(triage64, "CallStackOffset", obj->triage64_header->CallStackOffset, true);
		rz_structured_data_map_add_unsigned(triage64, "SizeOfCallStack", obj->triage64_header->SizeOfCallStack, true);
		rz_structured_data_map_add_unsigned(triage64, "DriverListOffset", obj->triage64_header->DriverListOffset, true);
		rz_structured_data_map_add_unsigned(triage64, "DriverCount", obj->triage64_header->DriverCount, true);
		rz_structured_data_map_add_unsigned(triage64, "StringPoolOffset", obj->triage64_header->StringPoolOffset, true);
		rz_structured_data_map_add_unsigned(triage64, "StringPoolSize", obj->triage64_header->StringPoolSize, true);
		rz_structured_data_map_add_unsigned(triage64, "BrokenDriverOffset", obj->triage64_header->BrokenDriverOffset, true);
		rz_structured_data_map_add_unsigned(triage64, "TriageOptions", obj->triage64_header->TriageOptions, true);
		rz_structured_data_map_add_unsigned(triage64, "TopOfStack", obj->triage64_header->TopOfStack, true);
		rz_structured_data_map_add_unsigned(triage64, "BStoreOffset", rz_read_le32(&obj->triage64_header->ArchitectureSpecific.Ia64.BStoreOffset), true);
		rz_structured_data_map_add_unsigned(triage64, "SizeOfBStore", rz_read_le32(&obj->triage64_header->ArchitectureSpecific.Ia64.SizeOfBStore), true);
		rz_structured_data_map_add_unsigned(triage64, "LimitOfBStore", rz_read_le64(&obj->triage64_header->ArchitectureSpecific.Ia64.LimitOfBStore), true);
		rz_structured_data_map_add_unsigned(triage64, "DataPageAddress", obj->triage64_header->DataPageAddress, true);
		rz_structured_data_map_add_unsigned(triage64, "DataPageOffset", obj->triage64_header->DataPageOffset, true);
		rz_structured_data_map_add_unsigned(triage64, "DataPageSize", obj->triage64_header->DataPageSize, true);
		rz_structured_data_map_add_unsigned(triage64, "DebuggerDataOffset", obj->triage64_header->DebuggerDataOffset, true);
		rz_structured_data_map_add_unsigned(triage64, "DebuggerDataSize", obj->triage64_header->DebuggerDataSize, true);
		rz_structured_data_map_add_unsigned(triage64, "DataBlocksOffset", obj->triage64_header->DataBlocksOffset, true);
		rz_structured_data_map_add_unsigned(triage64, "DataBlocksCount", obj->triage64_header->DataBlocksCount, true);
	}

	return info;
}

static RzPVector /*<RzBinField *>*/ *dmp64_fields(RzBinFile *bf) {
	RzPVector *fields = rz_pvector_new((RzPVectorFree)rz_bin_field_free);
	struct rz_bin_dmp64_obj_t *obj = (struct rz_bin_dmp64_obj_t *)bf->o->bin_obj;
#define FIELD_COMMENT(header, field, comment) \
	rz_pvector_push(fields, rz_bin_field_new(rz_offsetof(header, field), rz_offsetof(header, field), sizeof(((header *)0)->field), #field, comment, sizeof(((header *)0)->field) == 4 ? "x" : "q", false));
#define FIELD(header, field) FIELD_COMMENT(header, field, NULL)

	FIELD(dmp64_header, MajorVersion);
	FIELD(dmp64_header, MinorVersion);
	FIELD(dmp64_header, DirectoryTableBase);
	FIELD(dmp64_header, PfnDataBase);
	FIELD(dmp64_header, PsLoadedModuleList);
	FIELD(dmp64_header, PsActiveProcessHead);
	FIELD(dmp64_header, MachineImageType);
	FIELD(dmp64_header, NumberProcessors);
	FIELD_COMMENT(dmp64_header, BugCheckCode, rz_bin_dmp64_bugcheckcode_as_str(obj->header->BugCheckCode));
	FIELD(dmp64_header, BugCheckParameter1);
	FIELD(dmp64_header, BugCheckParameter2);
	FIELD(dmp64_header, BugCheckParameter3);
	FIELD(dmp64_header, BugCheckParameter4);
	FIELD(dmp64_header, KdDebuggerDataBlock);
	FIELD(dmp64_header, DumpType);
	FIELD(dmp64_header, SecondaryDataState);
	FIELD(dmp64_header, ProductType);
	FIELD(dmp64_header, SuiteMask);

	if (obj->bmp_header) {
		FIELD(dmp_bmp_header, FirstPage);
		FIELD(dmp_bmp_header, Pages);
		FIELD(dmp_bmp_header, TotalPresentPages);
	} else if (obj->triage64_header) {
		FIELD(dmp64_triage, ServicePackBuild);
		FIELD(dmp64_triage, SizeOfDump);
		FIELD(dmp64_triage, ValidOffset);
		FIELD(dmp64_triage, ContextOffset);
		FIELD(dmp64_triage, ExceptionOffset);
		FIELD(dmp64_triage, MmOffset);
		FIELD(dmp64_triage, UnloadedDriversOffset);
		FIELD(dmp64_triage, PrcbOffset);
		FIELD(dmp64_triage, ProcessOffset);
		FIELD(dmp64_triage, ThreadOffset);
		FIELD(dmp64_triage, CallStackOffset);
		FIELD(dmp64_triage, SizeOfCallStack);
		FIELD(dmp64_triage, DriverListOffset);
		FIELD(dmp64_triage, DriverCount);
		FIELD(dmp64_triage, StringPoolOffset);
		FIELD(dmp64_triage, StringPoolSize);
		FIELD(dmp64_triage, BrokenDriverOffset);
		FIELD(dmp64_triage, TriageOptions);
		FIELD(dmp64_triage, TopOfStack);
		FIELD(dmp64_triage, ArchitectureSpecific.Ia64.BStoreOffset);
		FIELD(dmp64_triage, ArchitectureSpecific.Ia64.SizeOfBStore);
		FIELD(dmp64_triage, ArchitectureSpecific.Ia64.LimitOfBStore);
		FIELD(dmp64_triage, DataPageAddress);
		FIELD(dmp64_triage, DataPageOffset);
		FIELD(dmp64_triage, DataPageSize);
		FIELD(dmp64_triage, DebuggerDataOffset);
		FIELD(dmp64_triage, DebuggerDataSize);
		FIELD(dmp64_triage, DataBlocksOffset);
		FIELD(dmp64_triage, DataBlocksCount);
	}
	return fields;
}

static RzBinInfo *dmp64_info(RzBinFile *bf) {
	RzBinInfo *ret;
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	struct rz_bin_dmp64_obj_t *obj = (struct rz_bin_dmp64_obj_t *)bf->o->bin_obj;

	ret->arch = obj->header->MachineImageType == 0xaa64 ? rz_str_dup("arm") : rz_str_dup("x86");
	ret->bits = 64;
	ret->machine = obj->header->MachineImageType == 0xaa64 ? rz_str_dup("ARM64") : rz_str_dup("AMD64");
	ret->rclass = rz_str_dup("dmp64");
	ret->type = rz_str_dup("Windows Crash Dump");
	ret->has_va = true;

	switch (obj->header->ProductType) {
	case MDMP_VER_NT_WORKSTATION:
		ret->os = rz_str_newf("Windows NT Workstation %d.%d",
			obj->header->MajorVersion,
			obj->header->MinorVersion);
		break;
	case MDMP_VER_NT_DOMAIN_CONTROLLER:
		ret->os = rz_str_newf("Windows NT Server Domain Controller %d.%d",
			obj->header->MajorVersion,
			obj->header->MinorVersion);
		break;
	case MDMP_VER_NT_SERVER:
		ret->os = rz_str_newf("Windows NT Server %d.%d",
			obj->header->MajorVersion,
			obj->header->MinorVersion);
		break;
	default:
		ret->os = rz_str_dup("Unknown");
	}

	return ret;
}

static RzPVector /*<RzBinMap *>*/ *dmp64_maps(RzBinFile *bf) {
	dmp_page_desc *page;
	dmp64_triage_datablock *datablock;
	RzPVector *ret;
	RzListIter *it;
	struct rz_bin_dmp64_obj_t *obj = (struct rz_bin_dmp64_obj_t *)bf->o->bin_obj;

	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free))) {
		return NULL;
	}

	rz_list_foreach (obj->pages, it, page) {
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			return ret;
		}
		map->name = rz_str_newf("page.0x%" PFMT64x, page->start);
		map->paddr = page->file_offset;
		map->psize = page->size;
		map->vaddr = page->start;
		map->vsize = page->size;
		map->perm = RZ_PERM_R;
		rz_pvector_push(ret, map);
	}

	rz_list_foreach (obj->datablocks, it, datablock) {
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			return ret;
		}
		map->name = rz_str_newf("kernel.0x%" PFMT64x, datablock->virtualAddress);
		map->paddr = datablock->offset;
		map->psize = datablock->size;
		map->vaddr = datablock->virtualAddress;
		map->vsize = datablock->size;
		map->perm = RZ_PERM_R;
		rz_pvector_push(ret, map);
	}

	return ret;
}

static RzPVector /*<char *>*/ *dmp64_libs(RzBinFile *bf) {
	struct rz_bin_dmp64_obj_t *obj = (struct rz_bin_dmp64_obj_t *)bf->o->bin_obj;
	if (!obj->drivers) {
		return NULL;
	}
	RzPVector *ret = rz_pvector_new(free);
	RzListIter *it;
	dmp_driver_desc *driver;
	rz_list_foreach (obj->drivers, it, driver) {
		char *file = rz_str_dup(driver->file);
		if (!file) {
			break;
		}
		rz_pvector_push(ret, file);
	}
	return ret;
}

static int dmp64_file_type(RzBinFile *bf) {
	return RZ_BIN_TYPE_CORE;
}

static char *dmp64_regstate(RzBinFile *bf) {
	struct rz_bin_dmp64_obj_t *dmp64 = bf->o->bin_obj;
	return rz_hex_bin2strdup(dmp64->header->ContextRecord, sizeof(dmp64->header->ContextRecord));
}

static bool dmp64_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	rz_return_val_if_fail(buf, false);
	struct rz_bin_dmp64_obj_t *res = rz_bin_dmp64_new_buf(buf);
	if (res) {
		sdb_ns_set(sdb, "info", res->kv);
		obj->bin_obj = res;
		return true;
	}
	return false;
}

static bool dmp64_check_buffer(RzBuffer *b) {
	ut8 magic[8];
	if (rz_buf_read_at(b, 0, magic, sizeof(magic)) == 8) {
		return !memcmp(magic, DMP64_MAGIC, 8);
	}
	return false;
}

RzBinPlugin rz_bin_plugin_dmp64 = {
	.name = "dmp64",
	.desc = "Windows x64 Crash Dump",
	.license = "LGPL3",
	.author = "abcSup",
	.destroy = &dmp64_destroy,
	.get_sdb = &dmp64_get_sdb,
	.bin_structure = &dmp64_structure,
	.info = &dmp64_info,
	.load_buffer = &dmp64_load_buffer,
	.check_buffer = &dmp64_check_buffer,
	.maps = &dmp64_maps,
	.libs = &dmp64_libs,
	.regstate = &dmp64_regstate,
	.file_type = &dmp64_file_type,
	.fields = &dmp64_fields
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_dmp64,
	.version = RZ_VERSION
};
#endif
