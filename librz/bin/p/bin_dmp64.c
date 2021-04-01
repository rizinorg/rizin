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
	rbin->cb_printf("  BugCheckCode : 0x%08" PFMT32x "\n", obj->header->BugCheckCode);
	rbin->cb_printf("  BugCheckParameter1 : 0x%016" PFMT64x "\n", obj->header->BugCheckCodeParameter[0]);
	rbin->cb_printf("  BugCheckParameter2 : 0x%016" PFMT64x "\n", obj->header->BugCheckCodeParameter[1]);
	rbin->cb_printf("  BugCheckParameter3 : 0x%016" PFMT64x "\n", obj->header->BugCheckCodeParameter[2]);
	rbin->cb_printf("  BugCheckParameter4 : 0x%016" PFMT64x "\n", obj->header->BugCheckCodeParameter[3]);
	rbin->cb_printf("  KdDebuggerDataBlock : 0x%016" PFMT64x "\n", obj->header->KdDebuggerDataBlock);
	rbin->cb_printf("  SecondaryDataState : 0x%08" PFMT32x "\n", obj->header->SecondaryDataState);
	rbin->cb_printf("  ProductType : 0x%08" PFMT32x "\n", obj->header->ProductType);
	rbin->cb_printf("  SuiteMask : 0x%08" PFMT32x "\n", obj->header->SuiteMask);

	if (obj->bmp_header) {
		rbin->cb_printf("\nBITMAP_DUMP:\n");
		rbin->cb_printf("  HeaderSize : 0x%08" PFMT64x "\n", obj->bmp_header->FirstPage);
		rbin->cb_printf("  BitmapSize : 0x%08" PFMT64x "\n", obj->bmp_header->Pages);
		rbin->cb_printf("  Pages : 0x%08" PFMT64x "\n", obj->bmp_header->TotalPresentPages);
	}
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret;
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	struct rz_bin_dmp64_obj_t *obj = (struct rz_bin_dmp64_obj_t *)bf->o->bin_obj;

	ret->arch = strdup("x86");
	ret->bits = 64;
	ret->machine = strdup("AMD64");
	ret->rclass = strdup("dmp64");
	ret->type = strdup("Windows Crash Dump");
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
		ret->os = strdup("Unknown");
	}

	return ret;
}

static RzList *sections(RzBinFile *bf) {
	dmp_page_desc *page;
	RzList *ret;
	RzListIter *it;
	RzBinSection *ptr;
	struct rz_bin_dmp64_obj_t *obj = (struct rz_bin_dmp64_obj_t *)bf->o->bin_obj;

	if (!(ret = rz_list_newf(free))) {
		return NULL;
	}

	rz_list_foreach (obj->pages, it, page) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}

		ptr->name = strdup("Memory_Section");
		ptr->paddr = page->file_offset;
		ptr->size = DMP_PAGE_SIZE;
		ptr->vaddr = page->start;
		ptr->vsize = DMP_PAGE_SIZE;
		ptr->add = true;
		ptr->perm = RZ_PERM_R;

		rz_list_append(ret, ptr);
	}
	return ret;
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	rz_return_val_if_fail(buf, false);
	struct rz_bin_dmp64_obj_t *res = rz_bin_dmp64_new_buf(buf);
	if (res) {
		sdb_ns_set(sdb, "info", res->kv);
		*bin_obj = res;
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
	.sections = &sections
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_dmp64,
	.version = RZ_VERSION
};
#endif
