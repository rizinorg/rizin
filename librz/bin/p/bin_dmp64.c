// SPDX-FileCopyrightText: 2020 abcSup <zifan.tan@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_util/rz_print.h>
#include <rz_lib.h>
#include <rz_bin.h>

#include "dmp/dmp64.h"

static Sdb *get_sdb(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);
	struct rz_bin_dmp64_obj_t *obj = (struct rz_bin_dmp64_obj_t *)bf->o->bin_obj;
	return (obj && obj->kv) ? obj->kv : NULL;
}

static void destroy(RzBinFile *bf) {
	rz_bin_dmp64_free((struct rz_bin_dmp64_obj_t *)bf->o->bin_obj);
}

static void header(RzBinFile *bf) {
	struct rz_bin_dmp64_obj_t *obj = (struct rz_bin_dmp64_obj_t *)bf->o->bin_obj;
	struct rz_bin_t *rbin = bf->rbin;
	rbin->cb_printf("DUMP_HEADER64:\n");
	rbin->cb_printf("  MajorVersion : 0x%08" PFMT32x "\n", obj->header->MajorVersion);
	rbin->cb_printf("  MinorVersion : 0x%08" PFMT32x "\n", obj->header->MinorVersion);
	rbin->cb_printf("  DirectoryTableBase : 0x%016" PFMT64x "\n", obj->header->DirectoryTableBase);
	rbin->cb_printf("  PfnDataBase : 0x%016" PFMT64x "\n", obj->header->PfnDataBase);
	rbin->cb_printf("  PsLoadedModuleList : 0x%016" PFMT64x "\n", obj->header->PsLoadedModuleList);
	rbin->cb_printf("  PsActiveProcessHead : 0x%016" PFMT64x "\n", obj->header->PsActiveProcessHead);
	rbin->cb_printf("  MachineImageType : 0x%08" PFMT32x "\n", obj->header->MachineImageType);
	rbin->cb_printf("  NumberProcessors : 0x%08" PFMT32x "\n", obj->header->NumberProcessors);
	rbin->cb_printf("  BugCheckCode : 0x%08" PFMT32x " (%s)\n", obj->header->BugCheckCode, rz_bin_dmp64_bugcheckcode_as_str(obj->header->BugCheckCode));
	rbin->cb_printf("  BugCheckParameter1 : 0x%016" PFMT64x "\n", obj->header->BugCheckParameter1);
	rbin->cb_printf("  BugCheckParameter2 : 0x%016" PFMT64x "\n", obj->header->BugCheckParameter2);
	rbin->cb_printf("  BugCheckParameter3 : 0x%016" PFMT64x "\n", obj->header->BugCheckParameter3);
	rbin->cb_printf("  BugCheckParameter4 : 0x%016" PFMT64x "\n", obj->header->BugCheckParameter4);
	rbin->cb_printf("  KdDebuggerDataBlock : 0x%016" PFMT64x "\n", obj->header->KdDebuggerDataBlock);
	rbin->cb_printf("  SecondaryDataState : 0x%08" PFMT32x "\n", obj->header->SecondaryDataState);
	rbin->cb_printf("  ProductType : 0x%08" PFMT32x "\n", obj->header->ProductType);
	rbin->cb_printf("  SuiteMask : 0x%08" PFMT32x "\n", obj->header->SuiteMask);

	if (obj->bmp_header) {
		rbin->cb_printf("\nBITMAP_DUMP:\n");
		rbin->cb_printf("  HeaderSize : 0x%08" PFMT64x "\n", obj->bmp_header->FirstPage);
		rbin->cb_printf("  BitmapSize : 0x%08" PFMT64x "\n", obj->bmp_header->Pages);
		rbin->cb_printf("  Pages : 0x%08" PFMT64x "\n", obj->bmp_header->TotalPresentPages);
	} else if (obj->triage64_header) {
		rbin->cb_printf("\nTRIAGE_DUMP64:\n");
		rbin->cb_printf("  ServicePackBuild : 0x%08" PFMT32x "\n", obj->triage64_header->ServicePackBuild);
		rbin->cb_printf("  SizeOfDump : 0x%08" PFMT32x "\n", obj->triage64_header->SizeOfDump);
		rbin->cb_printf("  ValidOffset : 0x%08" PFMT32x "\n", obj->triage64_header->ValidOffset);
		rbin->cb_printf("  ContextOffset : 0x%08" PFMT32x "\n", obj->triage64_header->ContextOffset);
		rbin->cb_printf("  ExceptionOffset : 0x%08" PFMT32x "\n", obj->triage64_header->ExceptionOffset);
		rbin->cb_printf("  MmOffset : 0x%08" PFMT32x "\n", obj->triage64_header->MmOffset);
		rbin->cb_printf("  UnloadedDriversOffset : 0x%08" PFMT32x "\n", obj->triage64_header->UnloadedDriversOffset);
		rbin->cb_printf("  PrcbOffset : 0x%08" PFMT32x "\n", obj->triage64_header->PrcbOffset);
		rbin->cb_printf("  ProcessOffset : 0x%08" PFMT32x "\n", obj->triage64_header->ProcessOffset);
		rbin->cb_printf("  ThreadOffset : 0x%08" PFMT32x "\n", obj->triage64_header->ThreadOffset);
		rbin->cb_printf("  CallStackOffset : 0x%08" PFMT32x "\n", obj->triage64_header->CallStackOffset);
		rbin->cb_printf("  SizeOfCallStack : 0x%08" PFMT32x "\n", obj->triage64_header->SizeOfCallStack);
		rbin->cb_printf("  DriverListOffset : 0x%08" PFMT32x "\n", obj->triage64_header->DriverListOffset);
		rbin->cb_printf("  DriverCount : 0x%08" PFMT32x "\n", obj->triage64_header->DriverCount);
		rbin->cb_printf("  StringPoolOffset : 0x%08" PFMT32x "\n", obj->triage64_header->StringPoolOffset);
		rbin->cb_printf("  StringPoolSize : 0x%08" PFMT32x "\n", obj->triage64_header->StringPoolSize);
		rbin->cb_printf("  BrokenDriverOffset : 0x%08" PFMT32x "\n", obj->triage64_header->BrokenDriverOffset);
		rbin->cb_printf("  TriageOptions : 0x%08" PFMT32x "\n", obj->triage64_header->TriageOptions);
		rbin->cb_printf("  TopOfStack : 0x%016" PFMT64x "\n", obj->triage64_header->TopOfStack);
		rbin->cb_printf("  BStoreOffset : 0x%08" PFMT32x "\n", rz_read_le32(&obj->triage64_header->ArchitectureSpecific.Ia64.BStoreOffset));
		rbin->cb_printf("  SizeOfBStore : 0x%08" PFMT32x "\n", rz_read_le32(&obj->triage64_header->ArchitectureSpecific.Ia64.SizeOfBStore));
		rbin->cb_printf("  LimitOfBStore : 0x%016" PFMT64x "\n", rz_read_le64(&obj->triage64_header->ArchitectureSpecific.Ia64.LimitOfBStore));
		rbin->cb_printf("  DataPageAddress : 0x%016" PFMT64x "\n", obj->triage64_header->DataPageAddress);
		rbin->cb_printf("  DataPageOffset : 0x%08" PFMT32x "\n", obj->triage64_header->DataPageOffset);
		rbin->cb_printf("  DataPageSize : 0x%08" PFMT32x "\n", obj->triage64_header->DataPageSize);
		rbin->cb_printf("  DebuggerDataOffset : 0x%08" PFMT32x "\n", obj->triage64_header->DebuggerDataOffset);
		rbin->cb_printf("  DebuggerDataSize : 0x%08" PFMT32x "\n", obj->triage64_header->DebuggerDataSize);
		rbin->cb_printf("  DataBlocksOffset : 0x%08" PFMT32x "\n", obj->triage64_header->DataBlocksOffset);
		rbin->cb_printf("  DataBlocksCount : 0x%08" PFMT32x "\n", obj->triage64_header->DataBlocksCount);
	}
}

static RzPVector /*<RzBinField *>*/ *fields(RzBinFile *bf) {
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

static RzBinInfo *info(RzBinFile *bf) {
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

static RzPVector /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
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

static RzPVector /*<char *>*/ *libs(RzBinFile *bf) {
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

static int file_type(RzBinFile *bf) {
	return RZ_BIN_TYPE_CORE;
}

static char *regstate(RzBinFile *bf) {
	struct rz_bin_dmp64_obj_t *dmp64 = bf->o->bin_obj;
	return rz_hex_bin2strdup(dmp64->header->ContextRecord, sizeof(dmp64->header->ContextRecord));
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	rz_return_val_if_fail(buf, false);
	struct rz_bin_dmp64_obj_t *res = rz_bin_dmp64_new_buf(buf);
	if (res) {
		sdb_ns_set(sdb, "info", res->kv);
		obj->bin_obj = res;
		return true;
	}
	return false;
}

static bool check_buffer(RzBuffer *b) {
	ut8 magic[8];
	if (rz_buf_read_at(b, 0, magic, sizeof(magic)) == 8) {
		return !memcmp(magic, DMP64_MAGIC, 8);
	}
	return false;
}

RzBinPlugin rz_bin_plugin_dmp64 = {
	.name = "dmp64",
	.desc = "Windows Crash Dump x64 rz_bin plugin",
	.license = "LGPL3",
	.destroy = &destroy,
	.get_sdb = &get_sdb,
	.header = &header,
	.info = &info,
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.maps = &maps,
	.libs = &libs,
	.regstate = &regstate,
	.file_type = &file_type,
	.fields = &fields
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_dmp64,
	.version = RZ_VERSION
};
#endif
